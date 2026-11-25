# Measurements

Throughput and handshake time of burrow against its interop harness, measured for the first release.
No target is set; these are reference figures.

## Conditions

- **Date:** 2026-11-24. The code measured differs from the first published commit only in the file
  store (its platform split and pruning clock), comments and documentation, all outside the
  measured path: the measurements use the in-memory store.
- **Host:** a test machine, an AMD Ryzen 9 9950X3D (16 cores, 32 threads), Linux 7.0.0, Go 1.27.1. The tests
  were pinned to cores 0–7 with `GOMAXPROCS=8`, with nothing else scheduled on them. The 1-minute load average
  was 0.24 to 1.20 before each run, and the tests refuse to start above 2.
- **Path:** the harness's rootless podman pod on one host, so the network is loopback. The client
  runs in its device-less container through the public API (`Tunnel.DialContext`, the userspace
  stack).
- **Servers:** OpenVPN 2.7.0 (Ubuntu 26.04) and 2.6.19 (Ubuntu 24.04), configured as the target
  profile. The server's log shows data channel offload (DCO) unavailable, so the server's data path
  is single-threaded userspace.
- **Sample:** 10 runs per arm per server for throughput, each a fresh tunnel; 20 sequential
  connects per server for the handshake. Nothing was discarded.

## Throughput

64 MiB per transfer. Downloads are HTTP GETs from busybox httpd on the server's tunnel address,
checked by SHA-256. Uploads are HTTP POSTs to a CGI sink that answers with the byte count it read,
so the time covers delivery. The baseline is the same download over the pod's loopback with no
tunnel: the harness's own ceiling.

| Server | Arm | Median MiB/s | Range MiB/s | Client CPU ÷ wall (median) |
|---|---|---|---|---|
| 2.7.0 | download | 452 | 440–463 | 1.86 |
| 2.7.0 | upload | 253 | 64–282 | 1.55 |
| 2.7.0 | baseline download | 1,952 | 1,897–2,037 | 1.06 |
| 2.6.19 | download | 400 | 393–413 | 1.77 |
| 2.6.19 | upload | 165 | 103–270 | 1.40 |
| 2.6.19 | baseline download | 1,922 | 1,861–1,998 | 1.06 |

- **No drops** in any run: receive queue full, stack inject and send errors, and data
  authentication failures were all 0.
- **Attribution.** The server process's CPU time over each throughput run, against the tunnel
  transfers' wall time: 3.72 s of 5.00 s (0.74) on 2.7.0, and 3.74 s of 5.63 s (0.66) on 2.6.19.
  - **Downloads are steady** (within 4% of the median on both servers) and match an earlier batch of
    the same size on the tree before the release check's last changes: 455 and 402 MiB/s. In that
    batch the 2.7.0 server's CPU time was 0.98 of the transfer time, so the single-threaded
    userspace server is the likely limit for downloads.
  - **Uploads vary on both servers** (64–282 and 103–270 MiB/s here; 252–290 and 117–310 in the
    earlier batch). burrow's counters show no loss. But the client's CPU per MiB uploaded (7.9 and
    8.8 ms) is about twice its CPU per MiB downloaded (4.1 and 4.4 ms). Across the runs, the slower an
    upload, the more CPU per MiB it took (Pearson r −0.91 on 2.7.0, −0.95 on 2.6.19, 10 runs each):
    the slowest, 64 MiB/s, took 18.8 ms per MiB. *Hypothesis:* TCP segments resent inside the
    userspace stack after loss outside burrow's counters, at the server's socket or TUN device, say.
    The stack's TCP statistics are not exposed, so this is not checked, and the upload figures are
    the least certain here.
- **What this does not measure:** a real network path (latency, loss, a 1500-byte MTU), a DCO
  server, or several tunnels at once.

## Handshake

From the `Connect` call to an established tunnel, over loopback, through the stages' events.

| Server | Total median | p90 | Max | TLS median | Push median | Key exchange median | Hard reset median |
|---|---|---|---|---|---|---|---|
| 2.7.0 | 3.8 ms | 4.3 ms | 4.9 ms | 1.5 ms | 1.8 ms | 0.2 ms | 0.0 ms |
| 2.6.19 | 3.2 ms | 3.6 ms | 3.8 ms | 1.3 ms | 1.2 ms | 0.3 ms | 0.0 ms |

The link stage (dialling a UDP socket) took under 0.1 ms. Over a real path, each stage adds round
trips: the hard reset one, TLS 1.3 about two, key exchange one, and the push one.

## How to repeat

On a Linux host with rootless podman, with the interop test binary built as `CLAUDE.md` says:

```
BURROW_INTEROP_MEASURE=1 BURROW_INTEROP_RUNS=10 interop/run.sh 26.04 plain tmp/interop.test -test.run '^TestMeasureThroughput$' -test.v -test.timeout 590s
BURROW_INTEROP_MEASURE=1 interop/run.sh 26.04 plain tmp/interop.test -test.run '^TestMeasureHandshake$' -test.v
```

Each run logs one `measure` line per transfer, and `run.sh` logs the server's CPU ticks before and
after the client run.
