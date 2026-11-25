package session

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Push is the configuration a PUSH_REPLY delivered (spec notes section 8).
type Push struct {
	Local, Remote netip.Addr // ifconfig under topology p2p
	Ping          time.Duration
	PingRestart   time.Duration
	// PingRestartSet tells a pushed ping-restart 0, which disables the
	// expiry, from none pushed, which leaves the 120 s default.
	PingRestartSet bool
	PeerID         uint32
	Cipher         string
	Flags          []string // protocol-flags
	TunMTU         int      // zero when not pushed
	// Recorded holds options burrow recognises and keeps for the caller but
	// does not act on (routes, DNS), verbatim.
	Recorded []string
	// Unrecognised holds options burrow does not know, verbatim.
	Unrecognised []string
}

var errPush = errors.New("unsupported pushed option")

const maxPush = 64 << 10

// recordedOptions are kept and reported but not acted on.
var recordedOptions = map[string]bool{
	"route": true, "route-gateway": true, "redirect-gateway": true, "dhcp-option": true,
	"ifconfig-ipv6": true, "route-ipv6": true,
}

// pushAssembler collects PUSH_REPLY messages until the push is complete.
type pushAssembler struct {
	options []string
	size    int
}

// add takes one PUSH_REPLY message and reports whether the push is complete.
func (a *pushAssembler) add(msg string) (bool, error) {
	body, ok := strings.CutPrefix(msg, "PUSH_REPLY")
	if !ok {
		return false, fmt.Errorf("%w: %q is not a PUSH_REPLY", errPush, msg)
	}
	a.size += len(body)
	if a.size > maxPush {
		return false, fmt.Errorf("%w: assembled push over %d bytes", errPush, maxPush)
	}
	opts := strings.Split(strings.TrimPrefix(body, ","), ",")
	last := strings.Fields(opts[len(opts)-1])
	if len(last) > 0 && last[0] == "push-continuation" {
		opts = opts[:len(opts)-1]
		a.options = append(a.options, opts...)
		switch {
		case len(last) == 2 && last[1] == "2":
			return false, nil
		case len(last) == 2 && last[1] == "1":
			return true, nil
		default:
			return false, fmt.Errorf("%w: %q", errPush, strings.Join(last, " "))
		}
	}
	a.options = append(a.options, opts...)
	return true, nil
}

// parsePush classifies the assembled options: honoured ones are typed,
// recorded ones kept, and anything burrow cannot honour safely is fatal.
func parsePush(options []string) (Push, error) {
	var p Push
	var sawPeerID, sawIfconfig, ekm bool
	for _, opt := range options {
		f := strings.Fields(opt)
		if len(f) == 0 {
			continue
		}
		bad := func(why string) error { return fmt.Errorf("%w: %q: %s", errPush, opt, why) }
		switch name, args := f[0], f[1:]; name {
		case "ifconfig":
			if len(args) != 2 {
				return p, bad("want two addresses")
			}
			l, err1 := netip.ParseAddr(args[0])
			r, err2 := netip.ParseAddr(args[1])
			if err1 != nil || err2 != nil || !l.Is4() || !r.Is4() {
				return p, bad("want two IPv4 addresses")
			}
			p.Local, p.Remote, sawIfconfig = l, r, true
		case "topology":
			if len(args) != 1 || args[0] != "p2p" {
				return p, bad("only topology p2p is supported")
			}
		case "ping", "ping-restart", "tun-mtu":
			if len(args) != 1 {
				return p, bad("want one number")
			}
			n, err := strconv.Atoi(args[0])
			if err != nil || n < 0 {
				return p, bad("want a non-negative number")
			}
			switch name {
			case "ping":
				p.Ping = time.Duration(n) * time.Second
			case "ping-restart":
				p.PingRestart, p.PingRestartSet = time.Duration(n)*time.Second, true
			default:
				if n < 576 {
					return p, bad("tun-mtu below 576, the IPv4 minimum")
				}
				p.TunMTU = n
			}
		case "peer-id":
			if len(args) != 1 {
				return p, bad("want one number")
			}
			n, err := strconv.ParseUint(args[0], 10, 24)
			if err != nil {
				return p, bad("want a 24-bit decimal peer ID")
			}
			p.PeerID, sawPeerID = uint32(n), true
		case "cipher":
			if len(args) != 1 || (args[0] != "AES-256-GCM" && args[0] != "AES-128-GCM") {
				return p, bad("only AES-256-GCM and AES-128-GCM are supported")
			}
			p.Cipher = args[0]
		case "protocol-flags":
			for _, fl := range args {
				switch fl {
				case "cc-exit":
				case "tls-ekm":
					ekm = true
				default:
					return p, bad("flag " + fl + " was not advertised")
				}
			}
			p.Flags = append(p.Flags, args...)
		case "key-derivation":
			if len(args) != 1 || args[0] != "tls-ekm" {
				return p, bad("only tls-ekm key derivation is supported")
			}
			ekm = true
		case "comp-lzo":
			if len(args) != 1 || args[0] != "no" {
				return p, bad("compression is not supported")
			}
		case "compress", "fragment":
			return p, bad("not supported")
		default:
			if recordedOptions[name] {
				p.Recorded = append(p.Recorded, opt)
			} else {
				p.Unrecognised = append(p.Unrecognised, opt)
			}
		}
	}
	switch {
	case p.Cipher == "":
		return p, fmt.Errorf("%w: no cipher pushed", errPush)
	case !ekm:
		return p, fmt.Errorf("%w: no tls-ekm key derivation pushed", errPush)
	case !sawPeerID:
		return p, fmt.Errorf("%w: no peer-id pushed", errPush)
	case !sawIfconfig:
		return p, fmt.Errorf("%w: no ifconfig pushed", errPush)
	}
	return p, nil
}
