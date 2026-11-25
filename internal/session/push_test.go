package session

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func assemble(t *testing.T, msgs ...string) ([]string, error) {
	t.Helper()
	var a pushAssembler
	for i, m := range msgs {
		done, err := a.add(m)
		if err != nil {
			return nil, err
		}
		if done != (i == len(msgs)-1) {
			t.Fatalf("message %d: complete=%v", i, done)
		}
	}
	return a.options, nil
}

const targetPush = "PUSH_REPLY,comp-lzo no,topology p2p,ping 10,ping-restart 60,ifconfig 10.88.0.4 10.88.0.1,peer-id 0,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm"

func TestPushHonoured(t *testing.T) {
	opts, err := assemble(t, targetPush)
	if err != nil {
		t.Fatal(err)
	}
	p, err := parsePush(opts)
	if err != nil {
		t.Fatal(err)
	}
	if p.Local != netip.MustParseAddr("10.88.0.4") || p.Remote != netip.MustParseAddr("10.88.0.1") ||
		p.Ping != 10*time.Second || p.PingRestart != 60*time.Second || p.PeerID != 0 ||
		p.Cipher != "AES-256-GCM" || strings.Join(p.Flags, " ") != "cc-exit tls-ekm" {
		t.Fatalf("parsed %+v", p)
	}
}

func TestPushFatal(t *testing.T) {
	base := strings.TrimPrefix(targetPush, "PUSH_REPLY,")
	cases := map[string]string{
		"the spike's push, no peer-id": "comp-lzo no,topology p2p,ping 10,ping-restart 60,ifconfig 10.88.0.4 10.88.0.1,cipher AES-256-GCM,key-derivation tls-ekm",
		"stock client's flags":         base + ",protocol-flags cc-exit tls-ekm dyn-tls-crypt aead-epoch",
		"another cipher":               strings.Replace(base, "AES-256-GCM", "AES-256-CBC", 1),
		"no tls-ekm":                   strings.Replace(base, ",protocol-flags cc-exit tls-ekm", ",protocol-flags cc-exit", 1),
		"comp-lzo yes":                 base + ",comp-lzo yes",
		"compress stub-v2":             base + ",compress stub-v2",
		"topology subnet":              strings.Replace(base, "topology p2p", "topology subnet", 1),
		"fragment":                     base + ",fragment 1300",
		"no ifconfig":                  strings.Replace(base, ",ifconfig 10.88.0.4 10.88.0.1", "", 1),
		"peer-id beyond 24 bits":       strings.Replace(base, "peer-id 0", "peer-id 16777216", 1),
		"tun-mtu below 576":            base + ",tun-mtu 575",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			opts, err := assemble(t, "PUSH_REPLY,"+body)
			if err == nil {
				_, err = parsePush(opts)
			}
			if !errors.Is(err, errPush) {
				t.Fatalf("got %v, want errPush", err)
			}
		})
	}
}

func TestPushRecordedAndContinuation(t *testing.T) {
	var msgs []string
	for i := range 3 {
		var routes []string
		for j := range 2 {
			routes = append(routes, fmt.Sprintf("route 10.123.%d.%d 255.255.255.255", i, j))
		}
		cont := "push-continuation 2"
		if i == 2 {
			cont = "push-continuation 1"
		}
		body := strings.Join(routes, ",")
		if i == 2 {
			body += "," + strings.TrimPrefix(targetPush, "PUSH_REPLY,") + ",dhcp-option DNS 10.88.0.1,mystery-option 1"
		}
		msgs = append(msgs, "PUSH_REPLY,"+body+","+cont)
	}
	opts, err := assemble(t, msgs...)
	if err != nil {
		t.Fatal(err)
	}
	p, err := parsePush(opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Recorded) != 7 || p.Recorded[0] != "route 10.123.0.0 255.255.255.255" || p.Recorded[6] != "dhcp-option DNS 10.88.0.1" {
		t.Fatalf("recorded %q", p.Recorded)
	}
	if len(p.Unrecognised) != 1 || p.Unrecognised[0] != "mystery-option 1" {
		t.Fatalf("unrecognised %q", p.Unrecognised)
	}
	var a pushAssembler
	if _, err := a.add(targetPush + ",push-continuation 3"); !errors.Is(err, errPush) {
		t.Errorf("push-continuation 3: %v", err)
	}
}

func TestPushTunMTUFloor(t *testing.T) {
	opts, err := assemble(t, targetPush+",tun-mtu 576")
	if err != nil {
		t.Fatal(err)
	}
	p, err := parsePush(opts)
	if err != nil || p.TunMTU != 576 {
		t.Fatalf("tun-mtu 576: %d, %v", p.TunMTU, err)
	}
}
