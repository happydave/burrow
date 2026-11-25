#!/usr/bin/env python3
"""Summarises the OpenVPN plain control headers in a pcap of the harness.

One line per UDP packet to or from port 1193: time from the first packet,
direction, opcode and key ID, own session ID, ACK list, peer session ID,
packet ID and payload length. Data packets (opcodes 6 and 9) show only their
opcode, key ID and length. Layout: spec notes section 2.1.
"""
import struct
import sys

NAMES = {3: "SOFT_RESET_V1", 4: "CONTROL_V1", 5: "ACK_V1", 6: "DATA_V1",
         7: "HARD_RESET_CLIENT_V2", 8: "HARD_RESET_SERVER_V2", 9: "DATA_V2"}
PORT = 1193


def frames(path):
    with open(path, "rb") as f:
        head = f.read(24)
        magic = head[:4]
        if magic == b"\xd4\xc3\xb2\xa1":
            end = "<"
        elif magic == b"\xa1\xb2\xc3\xd4":
            end = ">"
        else:
            sys.exit("not a classic pcap file")
        linktype = struct.unpack(end + "I", head[20:24])[0]
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                return
            sec, usec, incl, _ = struct.unpack(end + "IIII", rec)
            yield linktype, sec + usec / 1e6, f.read(incl)


def udp_payload(linktype, frame):
    if linktype == 1:      # Ethernet
        off = 14
    elif linktype == 0:    # BSD loopback
        off = 4
    elif linktype == 113:  # Linux cooked v1
        off = 16
    elif linktype == 276:  # Linux cooked v2
        off = 20
    else:
        return None
    ip = frame[off:]
    if len(ip) < 20 or ip[0] >> 4 != 4 or ip[9] != 17:
        return None
    ihl = (ip[0] & 15) * 4
    sport, dport = struct.unpack(">HH", ip[ihl:ihl + 4])
    return sport, dport, ip[ihl + 8:]


def describe(p):
    if not p:
        return "empty"
    op, key = p[0] >> 3, p[0] & 7
    name = NAMES.get(op, f"op{op}")
    if op in (6, 9):
        return f"{name:22} key={key} len={len(p)}"
    if len(p) < 10:
        return f"{name:22} key={key} truncated len={len(p)}"
    sid = p[1:9].hex()
    n = p[9]
    acks = list(struct.unpack(f">{n}I", p[10:10 + 4 * n])) if len(p) >= 10 + 4 * n else []
    i = 10 + 4 * n
    peer = ""
    if n:
        peer = p[i:i + 8].hex()
        i += 8
    pid = ""
    if op != 5 and len(p) >= i + 4:
        pid = struct.unpack(">I", p[i:i + 4])[0]
        i += 4
    return (f"{name:22} key={key} sid={sid} acks={acks} peer={peer or '-'} "
            f"pid={pid if pid != '' else '-'} payload={len(p) - i}")


def main():
    t0 = None
    for linktype, t, frame in frames(sys.argv[1]):
        u = udp_payload(linktype, frame)
        if u is None:
            continue
        sport, dport, payload = u
        if PORT not in (sport, dport):
            continue
        t0 = t if t0 is None else t0
        way = "c>s" if dport == PORT else "s>c"
        print(f"{t - t0:9.4f} {way} {describe(payload)}")


if __name__ == "__main__":
    main()
