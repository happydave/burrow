# burrow

burrow is a Go client library for the OpenVPN® protocol that needs no privileged access. A program
using it connects to an OpenVPN server from an ordinary user process and gets a dialer for traffic
through the tunnel: no root, no TUN device, no changes to the host's routing or DNS. Traffic runs
through a userspace TCP/IP stack inside the process.

**Status: first release, not yet tagged.** It targets one server profile, described below. The API
may change before a tagged release.

## Example

```go
cfg, ignored, err := burrow.LoadConfig("client.ovpn")
if err != nil {
	log.Fatal(err)
}
for _, ig := range ignored {
	log.Printf("ignored %s (line %d): no meaning without a device", ig.Directive, ig.Line)
}
dir, err := os.UserCacheDir() // this user's own: no one else can create the file first
if err != nil {
	log.Fatal(err)
}
cfg.AdmissionStore = burrow.NewFileStore(filepath.Join(dir, "burrow-attempts.json"))

r := burrow.NewRedialer(cfg)
tn, err := r.Next(ctx)
if err != nil {
	log.Fatal(err)
}
defer tn.Close()

client := &http.Client{Transport: &http.Transport{DialContext: tn.DialContext}}
```

The full example is `ExampleLoadConfig` in [example_test.go](example_test.go). A `Config` can also
be built directly. `Connect` returns one tunnel; the `Redialer` keeps one configuration connected
with a backoff. `Tunnel` offers `DialContext`, `ListenTCP` and `ListenUDP` through its network stack.
With `Config.RawPackets` it offers `ReadPacket` and `WritePacket` instead, for a caller with its own
stack. Its `Events`, `Stats`, `Done` and `Err` report what the tunnel is doing.

## Supported in the first release

- **Transport:** UDP, to an ordered list of remotes. burrow moves to the next remote only while no
  server has answered, and tries each address of a host name in turn.
- **Control channel:** plain control packets (no `tls-auth` or `tls-crypt`), with TLS 1.3 (only)
  over Go's `crypto/tls` and a client certificate.
- **Server check:** the certificate must chain to the configured CAs and carry the server-auth
  extended key usage, as `remote-cert-tls server` asks. There is no host-name check, as in OpenVPN.
- **Keys:** key method 2, with data keys from the TLS exporter.
- **Data channel:** `P_DATA_V2` with AES-256-GCM or AES-128-GCM, a 64-packet and 15-second replay
  window, and the no-compression framing byte.
- **Session:**
  - the pushed `ifconfig` under `topology p2p`, `ping`, `ping-restart`, `peer-id` and `tun-mtu`;
  - a push split across several messages;
  - the server's AUTH_FAILED, RESTART, HALT and EXIT;
  - EXIT on close.
- **Renegotiation from either side,** at the server's interval or burrow's (`RenegInterval`,
  default an hour), and before a key reaches its packet limit. At most two key IDs are live.
- **Configuration files:** the subset of `.ovpn` the target profile uses (`LoadConfig`).
  - Host and device directives such as `dev` and `daemon` are reported as ignored.
  - Any other directive, or an honoured one with a value outside the profile, is an error naming
    it.
  - Keys must be unencrypted PEM: PKCS#1, PKCS#8 or SEC 1.
- **MTU:** the stack's MTU is the tunnel MTU lowered to fit `mssfix` (default 1492 with `mtu`
  semantics), so TCP segments fit. A UDP or ICMP packet at the full tunnel MTU can still exceed a
  1500-byte path by the encapsulation, as with OpenVPN's own clients.

## Not in the first release

- TCP transport;
- `tls-auth`, `tls-crypt`, `tls-crypt-v2` and dynamic tls-crypt;
- the CBC+HMAC data channel and the legacy TLS 1.0 PRF;
- username and password authentication, AUTH_PENDING and AUTH_FAILED,TEMP;
- epoch data keys;
- obfuscation;
- a kernel TUN binding;
- acting on pushed DNS, routes or IPv6 settings, which are recorded in `Tunnel.Pushed` but not
  applied;
- compression of any kind;
- inline key material in `.ovpn` files (`<ca>`, `<cert>`, `<key>`).

## No privilege, and how the tests show it

Nothing in burrow opens a device, needs a capability, or changes the host. The interop tests run the
client side in a rootless podman container with no `/dev/net/tun`, `--cap-drop=all` and a non-root
user. Every run first runs a probe in that same container configuration. It tries to open
`/dev/net/tun` and must fail. The probe has its own control, run in the same image with the device
given, where it must succeed, so its failure means the device is absent. The HTTP and download tests
pass in that container against OpenVPN 2.7.0 and 2.6.19 servers. The server side keeps its
privilege inside its own container; that belongs to the test harness, not the library.

## The admission guard

Some servers ban a source address after repeated refused connects. burrow counts its attempts per
ban domain (by default, all hosts of one configuration together) and refuses to start an attempt
that would go over the policy. The default allows three refused attempts an hour; an attempt that
the server answered but that did not become a tunnel counts as refused. The guard is always on: a
caller can give it a looser policy, but not remove it. The history lives in memory by default, shared by every `Connect` in the process.
`NewFileStore` shares it between processes on one host. It uses `flock`, so it works on Unix
systems only; elsewhere it refuses every attempt with an error saying so.

## Security notes

- `Config.InsecureKeyLog` writes every TLS session's secrets in the NSS key-log format, for
  debugging burrow's own sessions. Anyone with that file can decrypt captured control traffic. It is
  off unless set.
- Key material burrow holds is zeroed when a key is dropped and when the tunnel closes: the exporter
  blocks, the implicit IVs and the kept TLS connection state. The AES implementation's expanded keys
  and the secrets `crypto/tls` keeps inside its connections are outside burrow's reach, so this is
  best effort.
- Every parser of network or file input has a fuzz target.

## Platforms

Pure Go, no cgo. Tested on Linux (amd64). The gate also builds for macOS, Windows and FreeBSD, which
are untested. The file store is Unix-only (above).

## Performance

Throughput and handshake time against the test harness are in
[docs/measurements.md](docs/measurements.md). No target is set.

## Clean-room origin

burrow is written from protocol documentation and from observing our own sessions, never from the
source of other implementations, most of which are GPL. See [CLAUDE.md](CLAUDE.md) for the rule as it
applies to work in this repository.

## Licence

Dual licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Trademark

OpenVPN® is a registered trademark of OpenVPN Inc. burrow is not affiliated with or endorsed by
OpenVPN Inc.
