#!/bin/bash
# Captures a stock OpenVPN client's plain control headers against the harness
# server, including renegotiations, and writes the pcap and its summary to
# interop/captures/. Runs the 26.04 (openvpn 2.7.0) image.
#
#   interop/capture.sh <name> [extra stock-client options...]
set -u
if [ $# -lt 1 ]; then sed -n '6p' "$0"; exit 64; fi
name=$1; shift
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/.." && pwd)
img=localhost/burrow-interop:26.04
pod=burrow-capture-$$
scratch=$repo/tmp/capture-$$
mkdir -p "$scratch/pki" "$scratch/log" "$scratch/out"
cleanup() { podman pod rm -f "$pod" >/dev/null 2>&1; }
trap cleanup EXIT
trap 'exit 130' INT TERM

if ! podman image exists "$img"; then
  podman build -q --build-arg BASE=docker.io/library/ubuntu:26.04 -t "$img" "$here" >/dev/null || exit 1
fi
podman run --rm -v "$scratch/pki:/pki:Z" -v "$here/mkpki.sh:/mkpki.sh:ro,Z" "$img" /mkpki.sh /pki || exit 1
podman pod create --name "$pod" >/dev/null || exit 1
podman run -d --pod "$pod" --name "$pod-srv" --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$scratch/pki:/pki:ro,Z" -v "$here/server.conf:/etc/openvpn/server.conf:ro,Z" \
  -v "$here/allow.sh:/etc/openvpn/allow.sh:ro,Z" -v "$here/allowed:/etc/openvpn/allowed:ro,Z" \
  -v "$scratch/log:/log:Z" "$img" openvpn --config /etc/openvpn/server.conf >/dev/null || exit 1
# tcpdump must end on its own: on the test host a tcpdump with no traffic did not end
# on SIGINT, SIGTERM or SIGKILL, and podman then could not remove its pod. -G 50 -W 1 ends it at the first packet after 50 s, which the
# client's 10 s pings supply, so the client is stopped only after it.
podman run -d --pod "$pod" --name "$pod-cap" --cap-add NET_RAW -v "$scratch/out:/out:Z" \
  "$img" tcpdump -Z root -G 50 -W 1 -i lo -U -w /out/capture.pcap udp port 1193 >/dev/null || exit 1
sleep 2 # the server and tcpdump need a moment to bind; the client retries anyway
podman run -d --pod "$pod" --name "$pod-cli" --cap-add NET_ADMIN --device /dev/net/tun \
  -v "$scratch/pki:/pki:ro,Z" -v "$here/client.conf:/c.conf:ro,Z" "$img" \
  openvpn --config /c.conf "$@" >/dev/null || exit 1
ended=0
for _ in $(seq 1 90); do
  if [ "$(podman inspect -f '{{.State.Running}}' "$pod-cap" 2>/dev/null)" = false ]; then ended=1; break; fi
  sleep 1
done
[ $ended = 1 ] || echo "capture.sh: tcpdump did not end by itself; its pod may be left behind" >&2
podman stop -t 2 "$pod-cli" >/dev/null 2>&1
podman logs "$pod-srv" > "$scratch/server.log" 2>&1
podman logs "$pod-cli" > "$scratch/client.log" 2>&1
cp "$scratch/out/capture.pcap" "$here/captures/$name.pcap" || exit 1
python3 "$here/pcapsummary.py" "$here/captures/$name.pcap" > "$here/captures/$name.txt" || exit 1
echo "capture.sh: wrote interop/captures/$name.pcap and .txt; logs in $scratch" >&2
