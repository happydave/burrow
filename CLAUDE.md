# burrow: working in this repository

burrow is an unprivileged Go client library for the OpenVPN protocol. Its design and planning
records are kept outside this repository. A `CLAUDE.local.md` beside this file, if present, holds
one site's setup and is never committed.

## Clean-room rule

burrow is a permissively licensed reimplementation of a protocol whose reference implementations
are GPL, so:

- **Never read** source code of minivpn, OpenVPN 2.x or 3, ics-openvpn, go-openvpn, TunnelKit,
  Wireshark's OpenVPN dissector, the Linux kernel `ovpn` driver, or any other GPL, LGPL or AGPL
  implementation. Do not paste, quote or summarise such code anywhere.
- **Wire facts come from the spec notes,** `docs/spec-notes.md`, which cite the openvpn-rfc draft,
  miragevpn-spec and the OpenVPN manual. Facts only; never copy their text. A fact the notes mark
  **To observe** is settled by observing our own sessions, as its register (§22) says, and the notes
  are updated with the result.
- **Allowed to read:** those documents, RFCs, permissively licensed code (record its licence when
  you use it), and packet captures or decrypted traces of our own sessions.
- **Enforcement.** `.claude/settings.json` denies `WebSearch` and a few commands, and registers
  `.claude/hooks/cleanroom-guard` (Python 3) for Bash, WebFetch, Read, Grep and Glob. The hook
  refuses any call naming a denied source. A refusal means the call is wrong, not the hook: do not
  route around it.
- **Spec notes and the similarity scan before v1.0 are written by sessions that write no burrow
  code.**
- **No identifiers of real servers or their operators** (hosts, addresses, organisation names,
  certificates) go in this repository. Fixtures use our own PKI and documentation addresses.

## Where things run

The unit tests and the gate run on any machine with Go. The interop harness needs Linux with
rootless podman. A gate that certifies a commit runs on that commit's tree (`git archive <commit>`), not the working
copy.

## Interop harness (Linux, rootless podman)

```
CGO_ENABLED=0 go test -c -tags interop -o tmp/interop.test ./internal/interop
interop/run.sh 26.04 plain tmp/interop.test -test.v -test.timeout 300s    # also 24.04; variant routes pushes 400 routes, reneg renegotiates every 20 s
interop/run.sh --probe-control 26.04 plain tmp/interop.test               # the probe's own control: the device opens
interop/capture.sh <name> --reneg-sec 20                                  # a stock client's plain headers, to interop/captures/
```

`BURROW_INTEROP_LONG=1` adds the long runs (idle past ping-restart, simultaneous renegotiation,
the soft-reset observation). `BURROW_INTEROP_MEASURE=1` adds the measurements
(`docs/measurements.md`), with `BURROW_INTEROP_RUNS` runs per arm.

`run.sh` starts the server in a rootless podman pod and runs the test binary beside it with no TUN
device, `--cap-drop=all` and a non-root user. The server also serves `hello.txt` and a 4 MiB
`large.bin` over HTTP on its tunnel address, `10.88.0.1:8080`, and `run.sh` passes the large file's
SHA-256 to the tests. The device probe runs first, alone. Interop tests carry
the `interop` build tag; without it `go test ./...` reports one skip. Nothing contacts a real VPN
server.

## Gate

Run in order from the module root; each must pass.

```
gofmt -l .                        # prints nothing
go vet ./...
go test -timeout 300s ./...       # includes the dependency-licence gate and the hook's tests
golangci-lint config verify
golangci-lint run ./...
GOOS=windows go build ./... && GOOS=darwin go build ./... && GOOS=freebsd go build ./...   # the README's platforms
```

The licence gate (`internal/modlicense`) refuses any module in the build or test graph without an
MIT, Apache-2.0, BSD or ISC licence. It needs the module cache populated (`go mod download`).
`python3` must be on PATH for the hook and its tests.
