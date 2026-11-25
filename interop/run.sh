#!/bin/bash
# The interop harness: starts an OpenVPN server in a rootless podman pod and
# runs a burrow interop test binary beside it, in a container with no TUN
# device, no capabilities and a non-root user.
#
#   interop/run.sh [--probe-control] <26.04|24.04> <plain|routes|reneg> <test-binary> [test args...]
#
# The probe (TestNoTunDevice) runs first, alone, in the client's container
# configuration; a failed probe stops the run with exit 3. --probe-control
# instead runs only the probe with the device given, expecting it to open.
# Exit: the test binary's status; 2 if the server or its HTTP server never
# started; 3 if the probe failed. Scratch, PKI, logs and served files land in
# tmp/interop-<pid>/.
set -u
probe_control=0
if [ "${1:-}" = "--probe-control" ]; then probe_control=1; shift; fi
if [ $# -lt 3 ]; then sed -n '6p' "$0"; exit 64; fi
tag=$1 variant=$2 binarg=$3 bin=$(readlink -f "$3"); shift 3
[ -f "$bin" ] || { echo "run.sh: no test binary at $binarg" >&2; exit 64; }
case $tag in 26.04|24.04) ;; *) echo "run.sh: tag must be 26.04 or 24.04" >&2; exit 64 ;; esac
case $variant in plain|routes|reneg) ;; *) echo "run.sh: variant must be plain, routes or reneg" >&2; exit 64 ;; esac

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
img=localhost/burrow-interop:$tag-2 # the suffix is the Containerfile's version
pod=burrow-interop-$$
scratch=$repo/tmp/interop-$$
mkdir -p "$scratch/pki" "$scratch/log" "$scratch/www"
# Served over HTTP on the server's tunnel address: a known text and 4 MiB of
# random bytes, whose hash the client checks.
echo "burrow through the tunnel" > "$scratch/www/hello.txt"
head -c 4194304 /dev/urandom > "$scratch/www/large.bin"
large_sha=$(sha256sum "$scratch/www/large.bin" | cut -d' ' -f1)
big_sha=
if [ -n "${BURROW_INTEROP_MEASURE:-}" ]; then
  # Measurement only: 64 MiB to download, and a CGI sink that
  # answers an upload with the byte count it read.
  head -c 67108864 /dev/urandom > "$scratch/www/big.bin"
  big_sha=$(sha256sum "$scratch/www/big.bin" | cut -d' ' -f1)
  mkdir -p "$scratch/www/cgi-bin"
  cat > "$scratch/www/cgi-bin/sink" <<'SINK'
#!/bin/sh
n=$(head -c "$CONTENT_LENGTH" | wc -c)
printf 'Content-Type: text/plain\r\n\r\n%s\n' "$n"
SINK
  chmod 755 "$scratch/www/cgi-bin/sink"
fi

cleanup() { podman pod rm -f "$pod" >/dev/null 2>&1; }
trap cleanup EXIT
trap 'exit 130' INT TERM

if ! podman image exists "$img"; then
  podman build -q --build-arg BASE=docker.io/library/ubuntu:"$tag" -t "$img" "$here" >/dev/null || exit 1
fi
podman run --rm -v "$scratch/pki:/pki:Z" -v "$here/mkpki.sh:/mkpki.sh:ro,Z" "$img" /mkpki.sh /pki || exit 1

cp "$here/server.conf" "$scratch/server.conf"
if [ "$variant" = reneg ]; then
  # A server renegotiation every 20 s exactly: min = max removes the randomisation (spec notes §15.8).
  echo "reneg-sec 20 20" >> "$scratch/server.conf"
fi
if [ "$variant" = routes ]; then
  # 400 host routes push a PUSH_REPLY larger than one control message (spec notes §8.5, O5).
  for i in $(seq 0 399); do echo "push \"route 10.123.$((i / 200)).$((i % 200 + 1)) 255.255.255.255\""; done >> "$scratch/server.conf"
fi

podman pod create --name "$pod" >/dev/null || exit 1
podman run -d --pod "$pod" --name "$pod-srv" --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$scratch/pki:/pki:ro,Z" -v "$scratch/server.conf:/etc/openvpn/server.conf:ro,Z" \
  -v "$here/allow.sh:/etc/openvpn/allow.sh:ro,Z" -v "$here/allowed:/etc/openvpn/allowed:ro,Z" \
  -v "$scratch/log:/log:Z" -v "$scratch/www:/www:ro,Z" "$img" openvpn --config /etc/openvpn/server.conf >/dev/null || exit 1

ready=0
for _ in $(seq 1 60); do
  if podman logs "$pod-srv" 2>&1 | grep -q "Initialization Sequence Completed"; then ready=1; break; fi
  sleep 0.5
done
if [ $ready = 0 ]; then
  echo "run.sh: the server did not initialise within 30 s; its log ends:" >&2
  podman logs "$pod-srv" 2>&1 | tail -20 >&2
  exit 2
fi
podman exec -d "$pod-srv" busybox httpd -f -p 10.88.0.1:8080 -h /www >/dev/null || exit 1
if [ -n "${BURROW_INTEROP_MEASURE:-}" ]; then
  # The baseline: the same files on the pod's loopback, with no tunnel.
  podman exec -d "$pod-srv" busybox httpd -f -p 127.0.0.1:8081 -h /www >/dev/null || exit 1
fi
served=0
for _ in $(seq 1 20); do
  if podman exec "$pod-srv" busybox wget -q -O /dev/null http://10.88.0.1:8080/hello.txt 2>/dev/null; then served=1; break; fi
  sleep 0.25
done
[ $served = 1 ] || { echo "run.sh: busybox httpd did not start on 10.88.0.1:8080" >&2; exit 2; }

client() { # extra podman flags, then the test binary's arguments after --
  local flags=()
  while [ "$1" != "--" ]; do flags+=("$1"); shift; done; shift
  podman run --rm --pod "$pod" --name "$pod-cli" --cap-drop=all --user 65534:65534 "${flags[@]}" \
    -v "$bin:/t/interop.test:ro,Z" -v "$scratch/pki:/pki:ro,Z" \
    -e BURROW_INTEROP_SERVER=127.0.0.1:1193 -e BURROW_INTEROP_PKI=/pki -e BURROW_INTEROP_VARIANT="$variant" \
    -e BURROW_INTEROP_LONG="${BURROW_INTEROP_LONG:-}" -e BURROW_INTEROP_LARGE_SHA256="$large_sha" \
    -e BURROW_INTEROP_MEASURE="${BURROW_INTEROP_MEASURE:-}" -e BURROW_INTEROP_BIG_SHA256="$big_sha" \
    -e BURROW_INTEROP_RUNS="${BURROW_INTEROP_RUNS:-3}" \
    "$img" /t/interop.test "$@"
}

# The server's CPU time in clock ticks (user + system), so a measurement can
# be attributed to the client or the server.
server_ticks() { podman exec "$pod-srv" sh -c 'awk "{print \$14 + \$15}" /proc/$(pidof openvpn)/stat'; }

status=0
if [ $probe_control = 1 ]; then
  client --device /dev/net/tun -e BURROW_INTEROP_EXPECT_TUN=1 -- -test.run '^TestNoTunDevice$' -test.v
  status=$?
else
  client -- -test.run '^TestNoTunDevice$' -test.v || { echo "run.sh: the device probe failed" >&2; status=3; }
  if [ $status = 0 ]; then
    [ -n "${BURROW_INTEROP_MEASURE:-}" ] && echo "measure server-ticks before=$(server_ticks) clk_tck=$(getconf CLK_TCK)" >&2
    client -- "$@"; status=$?
    [ -n "${BURROW_INTEROP_MEASURE:-}" ] && echo "measure server-ticks after=$(server_ticks)" >&2
  fi
fi
podman logs "$pod-srv" > "$scratch/server.log" 2>&1
echo "run.sh: scratch, server log and allowlist log in $scratch" >&2
exit $status
