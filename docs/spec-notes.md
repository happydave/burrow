# burrow spec notes: the wire facts of the first release

The reference the coding sessions implement from. Every fact carries a citation and a confidence
label. Where sources disagree, both readings are given with a recommendation. Facts that no allowed
source documents are marked **To observe**, with the method and the work item that observes them.

Written by a session that writes no burrow code (item 2). No text from any source is copied beyond
short cited fragments; byte layouts are restated in our own notation.

**Items** are the first release's work plan, by number: 1 repository bootstrap, 2 these notes, 3 the
interop harness, 4 the packet codec and reliability layer, 5 TLS, key method 2 and push, 6 the data
channel, 7 the admission guard, 8 a live check, 9 the network stack and public API, 10 the
configuration loader and failover, 11 renegotiation, 12 the release check. "The design" is that
plan's design document, which is not published.

## Conventions

- **Byte order.** Every multi-byte integer on the wire is big-endian (network byte order).
  [D §6.2.1.6 Field: replay_packet_id; D §4 OpenVPN wire packet format; M "Data channel key
  exchange"] *Confirmed.*
- **Offsets** are zero-based byte offsets into the UDP payload, unless a layout says otherwise.
- **Bit numbers** in `IV_PROTO` count from the least significant bit: bit *n* has value 2^n.
- **"Packet ID"** means the control channel's reliable sequence number (miragevpn-spec calls it the
  sequence number) unless the text says "data packet ID", which is the data channel's AEAD counter.
  [M "Terminology"]
- **Confidence labels:**
  - **Confirmed**: two independent sources, or one source plus an observation of our own (the TLS
    spike, against OpenVPN 2.7.0-1ubuntu1.4 and 2.6.19 servers).
  - **Supported**: one reliable source.
  - **Hypothesis**: our own reading or inference, not stated by a source.
  - **To observe**: no allowed source states it; the method names how burrow's own sessions settle it.

### Source key

| Key | Source | Pinned as |
|---|---|---|
| D | openvpn-rfc draft, "OpenVPN Wire Protocol", draft-openvpntech-openvpn-wire-protocol-01 | commit `a58b36fbfa87e53667929149baf97dfa5d1f1c26`; section numbers as xml2rfc renders that commit's XML (no unnumbered sections) |
| M | miragevpn-spec, "The OpenVPN protocol" (Unlicense), cited by heading | file read 2026-11-24, SHA-256 `1db507d9cf3f5f332d7e6c9c1ada9e23cbc9ea37fae05aad95f8d72585c7e` |
| Man | OpenVPN 2.7 reference manual, cited by option | page read 2026-11-24 |
| S | burrow TLS spike: a throwaway Go client against our own 2.7.0 and 2.6.19 servers | 2026-11-24 |
| RFC | IETF RFCs, by number and section | — |

Draft sections cited, with titles: §4 OpenVPN wire packet format; §5.1 Unauthenticated control
channel packets; §5.3 HMAC authentication of control channel packets; §5.4.1 Control channel packet
encryption; §5.4.3.3 Implementation (tls-crypt-v2); §6.1 Overview of OPCODEs; §6.2.1 Control channel
wire packet structure (and its field subsections §6.2.1.1–§6.2.1.11); §6.2.2.3 CONTROL_SOFT_RESET_V1;
§6.2.2.4 CONTROL_V1; §6.2.2.5 ACK_V1; §6.2.2.6 CONTROL_HARD_RESET_CLIENT_V2; §6.2.2.7
CONTROL_HARD_RESET_SERVER_V2; §6.2.2.13 DATA_V2; §6.2.2.14 DATA_V1; §6.3 Message Packet IDs; §6.4
Acknowledgements; §6.5 Control message framing; §6.6 Key exchange message; §6.7 Peerinfo; §6.8
Negotiation of peer-id; §6.9 Negotiation of protocol options; §7.1 OpenVPN Key; §7.1.1 Data channel key
generation; §7.2.1 AEAD cipher usage limits; §7.2.4 Data channel key rotation; §7.3.1 Requirements
(Peer-ID); §7.3.3 Replay protection; §7.4 AEAD encrypted data channel packet; §8.1 Message format;
§8.2 PUSH_REQUEST; §8.3 PUSH_REPLY; §8.5 AUTH_PENDING; §8.6 RESTART and HALT; §8.7 AUTH_FAILED; §8.8
EXIT; §8.10 INFO_PRE and INFO; §9.2 protocol-flags; §10.1 General overview (TLV messages); §10.4.3
probe reply.

## 1. Packet header and opcodes

**1.1 The first byte.** Every packet in TLS mode starts with one byte: the opcode in the high 5 bits
and the key ID in the low 3 bits, so the byte is `opcode × 8 + key_id`. [D §6.1 Overview of OPCODEs;
D §4; M "Packet wire format"; S: opcodes 4, 5, 7, 8 worked] *Confirmed.*

**1.2 Opcodes burrow uses.**

| Opcode | Name | Channel | First byte with key ID 0 | burrow |
|---|---|---|---|---|
| 3 | CONTROL_SOFT_RESET_V1 | control | `0x18` | send and receive |
| 4 | CONTROL_V1 | control | `0x20` | send and receive |
| 5 | ACK_V1 | control | `0x28` | send and receive |
| 6 | DATA_V1 | data | `0x30` | receive only, if the Plan accepts it (11.9) |
| 7 | CONTROL_HARD_RESET_CLIENT_V2 | control | `0x38` | send |
| 8 | CONTROL_HARD_RESET_SERVER_V2 | control | `0x40` | receive |
| 9 | DATA_V2 | data | `0x48` | send and receive |

[D §6.1 table] *Confirmed* for 4, 5, 7, 8 (S); *Supported* for 3, 6, 9 (draft only until items 6 and
11 run). Opcodes 1 and 2 are obsolete; 10, 11, 13 belong to tls-crypt-v2; 12 (CONTROL_V2) and 14
(CONTROL_AUX_V1) are TLV and epoch-key features. None of these is in the first release: a packet with
any of them is dropped and counted. [D §6.2.2.1–§6.2.2.12]

**1.3 Key ID.** Range 0–7. The first TLS session uses 0 and only the first does; each renegotiation
uses the current key ID plus one, and after 7 comes 1. [D §6.2.1.3 Field: key_id; D §6.2.2.3; M
"Packet wire format"] *Confirmed* (two sources).

## 2. Control packet layout and ACKs

**2.1 Plain control packet** (no tls-auth, no tls-crypt), UDP:

```
offset  size     field
0       1        opcode<<3 | key_id
1       8        own session ID (the sender's)
9       1        n = number of ACK entries (uint8)
10      4*n      ACKed packet IDs, uint32 each
10+4n   8        peer session ID (the receiver's, as the sender knows it); present only if n >= 1
...     4        packet ID (uint32); absent in ACK_V1
...     rest     payload: TLS bytes in CONTROL_V1; ignored in resets; none in ACK_V1
```

[D §5.1 Unauthenticated control channel packets; D §6.2.1 table and §6.2.1.4–§6.2.1.11; M "Plain
header"; S: this layout worked against 2.7.0 and 2.6.19] *Confirmed.*

*Observed 2026-11-24* (item 3 capture): under key ID 0 the stock 2.7.0 client's third packet is a
CONTROL_V1 with packet ID 1, the ACK of the server's packet 0 piggybacked (4.3), and 1196 bytes of
TLS. That makes 1222 bytes of UDP payload, the 18.1 limit exactly. Both sides piggyback up to 4 ACKs
and repeat recent ones (2.4).

Fixed sizes that follow: a packet with no ACKs and a packet ID is 14 bytes plus payload. With n ACKs
it is 22 + 4n bytes plus payload. An ACK_V1 with n ACKs is 18 + 4n bytes.

**2.2 Session IDs.** Each side picks its own 8-byte session ID; the draft recommends 64 bits of
randomness and forbids the peer from assuming a format. A full reconnect must use a new session ID.
[D §5.1; D §6.2.1.4 Field: session_id; M "Plain header"] *Confirmed.* burrow uses `crypto/rand`
(design, Security).

**2.3 The draft's ACK-size inconsistency.** The draft gives two sizes for each ACK entry:

- **8 bytes per entry**: the structs in D §5.1 and D §5.3 write the list as `n*8` bytes.
- **4 bytes per entry**: the D §6.2.1 table gives 32 bits per entry, D §6.2.1.7 Field:
  acked_pktid_len says 4 bytes each, and the tls-crypt struct in D §5.4.1 writes `n*4`.
  miragevpn-spec gives 4 bytes ("Plain header"). The spike's client used 4-byte entries and the
  server accepted its ACKs: every run past TLS sent 7 control packets with no retransmissions (S).

**Settled: 4 bytes per entry**, the same width as the packet ID it acknowledges. *Confirmed* (M, three
draft passages, and S). The `n*8` in D §5.1 and §5.3 is an error in the draft.

**2.4 How many ACKs per packet.**

- An ACK_V1 usually carries up to 8 ACKs; other control packets carry up to 4. [D §6.4
  Acknowledgements] *Supported.*
- Every ACK names one packet; there are no cumulative ACKs. [D §6.4] *Supported.*
- The draft recommends repeating ACKs for the most recently received packets in every outgoing
  packet (an LRU of 4 for non-ACK packets, 8 for ACK_V1), and limiting any one packet's list to 8 for
  compatibility. [D §6.4] *Supported.*
- **burrow sends** at most 4 ACKs piggybacked on a CONTROL_V1 or SOFT_RESET, and at most 8 in an
  ACK_V1. *Recommendation.*
- **burrow accepts** any n from 0 to 255 that fits the datagram. The count is a uint8, so the bound
  is fixed at 1020 bytes; refusing n > 8 buys nothing and risks interop. *Recommendation.*
- An ACK_V1 should not be sent in response to an ACK_V1. [D §6.2.2.5 ACK_V1] *Supported.*
- An ACK names packet IDs from the sender's local cache of sent packets; an ACK for an ID never sent
  may mean manipulation. [D §6.2.1.8 Field: acked_pktid_list] *Supported.* burrow drops such an ACK
  entry and counts it.

**2.5 Peer session ID check.** When n ≥ 1 the peer session ID must be present; when n = 0 it must be
absent. [D §6.2.1.9 Field: peer_session_id; M "Plain header"] *Confirmed.* Since this profile's
control packets are unauthenticated, burrow drops any packet whose own session ID is not the
server's (once learned) or whose peer session ID, when present, is not burrow's (design, Security).

**2.6 ACK scope across key IDs.** *Hypothesis:* an ACK acknowledges packets of the key ID in its own
first byte, so each key ID's reliability state handles only ACKs carried under that key ID. No source
says so. **To observe** in item 3's capture of a stock client renegotiating (plain headers are visible
in a capture because nothing wraps them), confirmed by item 11.

## 3. Reliability rules

**3.1 Packet IDs.** Per direction, independent, starting at 0, sequential without gaps.
A retransmission carries the same packet ID as the original. ACK_V1 has no packet ID. [D §6.2.1.10
Field: packet_id; D §6.3 Message Packet IDs; M "Plain header"] *Confirmed.*

**3.2 Packet ID limit.** At 2^32 − 1 an implementation may wrap to 0 or refuse new packets; the draft
calls that number of control packets unrealistic. [D §6.3] *Supported.* Recommendation: refuse, and
end the key ID with an error, rather than wrap.

**3.3 Payload stream.** CONTROL_V1 payloads, concatenated in packet-ID order, form the TLS byte
stream for that key ID. A TLS record larger than one control packet is split across several.
[D §6.2.2.4 CONTROL_V1; D §6.5 Control message framing] *Confirmed* (S: a TLS 1.3 handshake with a
post-quantum key share and a client certificate spanned several packets and completed).

**3.4 Retransmission timer.** Default 2 s without an ACK before retransmitting, with TCP-like
exponential backoff. [Man `--tls-timeout`] *Supported.* The backoff ceiling is not documented; it is
burrow's choice, bounded by the handshake window (section 15).

**3.5 Reorder window and in-flight limit.** Not documented in any allowed source. Both are burrow's
choice. The ACK counts in 2.4 suggest the stock peer keeps a handful of packets in flight; that is a
*Hypothesis*. *Observed 2026-11-24* (item 3, `interop/captures/stock-2.7.0-reneg.txt`): during the
handshake the 2.7.0 server sent at most 3 control packets before an ACK came back (packet IDs 1–3
together), and the stock client at most 2. Informative only.

**3.6 Duplicates.** A packet whose ID was already delivered is dropped, and its ID is ACKed again
(the peer evidently missed the ACK). *Hypothesis*, consistent with D §6.4's advice to keep ACKing
recent packets.

## 4. Hard reset exchange

**4.1 Client hello of the protocol.** burrow sends CONTROL_HARD_RESET_CLIENT_V2 with key ID 0, its new
session ID, n = 0, packet ID 0 and an empty payload: 14 bytes, first byte `0x38`. The receiver must
ignore any payload. [D §6.2.2.6 CONTROL_HARD_RESET_CLIENT_V2; D §6.2.1.10] *Confirmed* (S).

**4.2 Server reply.** CONTROL_HARD_RESET_SERVER_V2 (`0x40`), carrying the server's session ID, its
own packet ID 0 and an ACK of burrow's packet 0 with burrow's session ID as the peer session ID. Its
payload must be ignored (it carries TLVs only in the tls-crypt-v2 cookie variant, out of scope).
[D §6.2.2.7 CONTROL_HARD_RESET_SERVER_V2; D §10.4.3 probe reply, which describes the server reset as
carrying an ACK; D §5.4.3.3] *Confirmed* (S). burrow learns the server's session ID from this packet.

**4.3 Third packet.** burrow's next packet acknowledges the server's packet 0 and carries the server's
session ID as peer session ID. It is either an ACK_V1 followed by a CONTROL_V1, or a CONTROL_V1 alone
with the ACK piggybacked, carrying packet ID 1 and the start of the TLS ClientHello. [D §5.4.3.3,
"Normally the first message of the client"; D §10.4.3, which names packet ID 1 acknowledging ID 0]
*Confirmed* (S, whose handshakes completed with this sequence).

**4.4 The server is stateless until the third packet.** A 2.x server uses its own session ID as a
challenge the client must echo in the third packet, keeping no state before that. [D §5.4.3.3,
"Setting up connection with cookie support"; D §10.4.3, last paragraphs] *Supported.* Consequence,
*Hypothesis*: until the server has ACKed one of burrow's packets with ID ≥ 1, every packet burrow
sends, retransmissions included, carries the ACK of server packet 0 and the server's session ID, so
whichever copy arrives first lets the server create its state.

**4.5 Failover boundary.** "Answered" means a valid CONTROL_HARD_RESET_SERVER_V2 arrived (design,
Failover). The man page's own client moves to the next remote after `--server-poll-timeout` (default
120 s; `--connect-timeout` is its alias) without a response. [Man `--server-poll-timeout`,
`--connect-timeout`] *Supported.*

## 5. TLS over the control channel, and message framing

**5.1 Roles.** The OpenVPN client is always the TLS client, including in renegotiations; the draft
calls the peers TLS client and TLS server. [D §3 The OpenVPN Wire Protocol; D §7.1 OpenVPN Key]
*Supported.*

**5.2 One message per TLS record.** After TLS completes, each control message (the key-method-2
message and every text message) is its own TLS record. A plaintext split over two records is treated
as two messages; a large message keeps one record and spans several control packets. [D §6.5 Control
message framing; D §8.1 Message format] *Supported.*

**5.3 NUL terminator.** A sender must send each text control message in its own TLS record,
terminated by a NUL byte. The current implementation may not enforce the NUL on receive, and future
ones may rely on it instead of record boundaries. [D §6.5] *Supported.* burrow therefore:

- sends each message as one TLS write ending in a single NUL;
- on receive, strips one trailing NUL if present, and treats both a NUL and a record boundary as a
  message end. Whether the 2.7.0 server's messages end with NUL is **To observe** (item 5: log the raw
  plaintext bytes of PUSH_REPLY on the harness).

**5.4 Key method 2 is binary.** The first message in each direction after the TLS handshake is the
key exchange message (section 6), not text. [D §6.6 Key exchange message; D §8.1] *Supported.*

**5.5 No host name.** None of the sources uses server names: OpenVPN verifies certificates, not host
names (design, Security). *Hypothesis:* the server ignores SNI, so burrow sends none.

## 6. Key method 2 message

**6.1 Client to server:**

```
offset  size   field
0       4      0x00 0x00 0x00 0x00
4       1      key method = 0x02
5       48     pre-master secret (random)
53      32     random1 (random)
85      32     random2 (random)
117     2+L    options string (OCC)
...     2+L    username
...     2+L    password
...     2+L    peer-info
```

[D §6.6; M "Data channel key exchange"; S: this layout, sent by the spike, was accepted and answered
by 2.7.0 and 2.6.19] *Confirmed.*

The 112 random bytes feed only the legacy TLS1-PRF; with EKM they are unused but should still be
random. [D §6.6; D §7.1.2 OpenVPN data channel PRF] *Supported.* burrow fills them from `crypto/rand`.

**6.2 String encoding.** A 2-byte big-endian length L, then L bytes. A non-empty string's L includes
its terminating NUL. [D §6.6; M "Data channel key exchange"] *Confirmed.* The two sources differ on the
empty string:

- D §6.6: an unused string is a single zero byte, so L = 1 and the byte is `0x00`.
- M: an empty string may be L = 0 (no bytes, no NUL) or L = 1 with one NUL; M also says the username
  and password lengths are 0 when password authentication is not used.

**Recommendation:** burrow *sends* empty strings as L = 1 with one NUL. That form is valid under both
sources: the draft requires it and miragevpn-spec says receivers accept it. burrow *accepts* both forms.
*Hypothesis* that the 2.7.0 server accepts L = 1 for username and password; **To observe** in item 5
(the harness server log at verb 4 reports a malformed key exchange). Fallback if it refuses: L = 0.

Strings are expected to be UTF-8. [D §6.6] *Supported.*

**6.3 What burrow puts in the strings.**

- **Options string.** A configuration summary the peer compares only to warn on mismatch. [D §6.6]
  *Supported.* Its exact content is not documented. The server log at verb 4 prints the remote options
  string it received and the one it expected. Recommendation: send the empty string (L = 1, NUL) and
  check the harness log in item 5 that the server only warns. **To observe.**
- **Username, password.** Empty: the profile is certificate-only.
- **Peer-info.** Section 7.

**6.4 Server to client.** The two sources disagree on whether the server's message has the 48-byte
pre-master field:

- D §6.6 shows one struct for both directions, with the 48 bytes always present, and says the server
  replies with its own message carrying the options string, username, password and an empty
  peer-info.
- M says the server omits the pre-master secret, so its message is 4 + 1 + 32 + 32 bytes followed by
  the strings, with username, password and peer-info empty.

**Recommendation:** parse M's layout: 4 zero bytes, method 2, random1, random2, then strings. As a
guard, if the strings do not parse exactly to the end of the record, try the D layout (48 more bytes
before random1). burrow uses none of the server's randoms under EKM, so either reading yields the same
keys; the parse only has to be strict enough to reject garbage. Also accept a message that ends after
the options string, treating the missing strings as empty (*Hypothesis*; M says only that they are
empty). **To observe** in item 5: record the server message's length on the harness. With the strings
empty, its length tells the layouts apart.

**6.5 Checks on receive.** The first 4 bytes are zero and the method byte is 2; otherwise the key
exchange fails (design error kind "key exchange failed"). [D §6.6; M] *Confirmed.* The message has a
fixed upper bound (design, Security); recommendation 4096 bytes, as peer-info and the options string
are the only variable parts and the server's are short.

## 7. Peer-info and IV_PROTO

**7.1 Format.** UTF-8 text of `NAME=VALUE` lines separated by `\n`. [D §6.7 Peerinfo; M "Peerinfo"]
*Confirmed.* Recommendation: end every line, including the last, with `\n`, then the string's NUL. A
parser splitting on newlines handles a trailing one; *Hypothesis* that the server does.

**7.2 What burrow sends** (design, Session):

| Name | Value | Source and confidence |
|---|---|---|
| `IV_VER` | burrow's name and version | D §6.7, Man `--push-peer-info`: the version of the client program. *Supported.* Whether the server accepts a non-OpenVPN version string is *Hypothesis*; **To observe** in item 5 (same PUSH_REPLY as with a stock version string). |
| `IV_PLAT` | one of `linux`, `solaris`, `openbsd`, `mac`, `netbsd`, `freebsd`, `win` | Man `--push-peer-info` lists these values. *Supported.* |
| `IV_PROTO` | `142` | 7.3 |
| `IV_CIPHERS` | `AES-256-GCM:AES-128-GCM` | colon-separated cipher list. [D §6.7; M "Negotiating cipher"; Man `--push-peer-info`] *Confirmed* (S sent this exact value and got `cipher AES-256-GCM`). |

`IV_PROTO` and `IV_CIPHERS` are mandatory for every implementation; `IV_SSO` only with AUTH_PENDING
support, which burrow lacks. [D §6.7] *Supported.* `IV_NCP` is deprecated in favour of `IV_CIPHERS`.
[D §6.7; M; Man] *Confirmed.* burrow sends no `IV_NCP`, no `IV_MTU`, no `IV_SSO`, no `IV_HWADDR`, no
`ID=` (section 11.2), and no compression variables (section 13.5).

**7.3 IV_PROTO bits.**

| Bit | Value | Meaning | burrow |
|---|---|---|---|
| 0 | 1 | reserved, must be 0 | unset |
| 1 | 2 | peer-id and DATA_V2 | **set** |
| 2 | 4 | request-push: the server may send PUSH_REPLY without waiting for PUSH_REQUEST | **set** |
| 3 | 8 | key derivation by the TLS exporter (EKM) | **set** |
| 4 | 16 | AUTH_PENDING with arguments (keywords) | unset |
| 5 | 32 | feature negotiation in P2P mode (no push) | unset |
| 6 | 64 | the pushed `dns` option (the draft marks this bit deprecated, see below) | unset |
| 7 | 128 | EXIT on the control channel, and acceptance of the pushed `protocol-flags` for EKM | **set** |
| 8 | 256 | AUTH_FAILED,TEMP | unset |
| 9 | 512 | dynamic tls-crypt | unset |
| 10 | 1024 | epoch data keys (the data format with the tag at the end and 64-bit packet IDs) | unset |
| 11 | 2048 | the pushed `dns` option (draft only) | unset |
| 12 | 4096 | PUSH_UPDATE (draft only) | unset |
| 13 | 8192 | echo request TLV in CONTROL_AUX_V1 (draft only) | unset |

Sources: D §6.7 (bits 0–13); Man `--push-peer-info` (bits 0–10); M "Peerinfo" (bits 0, 2, 3, 7); D
§7.3.1 Requirements (bit 1 as `IV_PROTO=2` meaning DATA_V2 and peer-id). Bits 0–5 and 7–10:
*Confirmed* (draft and man page agree). Bits 11–13: *Supported* (draft only).

**burrow's value: 2 + 4 + 8 + 128 = 142.** The set bits are DATA_V2/peer-id, request-push, EKM and
control-channel EXIT. The bits for AUTH_PENDING keywords (4), AUTH_FAILED,TEMP (8), dynamic tls-crypt
(9) and epoch keys (10) are unset, as are all others.

**Bit 6 disagreement.** The man page gives bit 6 as support for the pushed `--dns` option, with no
deprecation. The draft marks bit 6 deprecated and assigns the `dns` option to bit 11. The man page's
list stops at bit 10. burrow sets neither, so nothing depends on it.

**7.4 Does the EXIT bit bring `protocol-flags`? Yes.** Bit 7 means the client both sends EXIT on the
control channel and accepts `protocol-flags` in the push. With bit 7 set, the server signals EKM with
`protocol-flags … tls-ekm`; without it, with `key-derivation tls-ekm`. [Man `--push-peer-info` bit 7;
D §6.7 bit 7; M "Peerinfo" bit 7, which states the substitution outright; D §7.1.1, which names both
push forms] *Confirmed* (three sources, plus S: the spike sent `IV_PROTO=12`, without bit 7, and got
`key-derivation tls-ekm` and no `protocol-flags`, while the stock client got `protocol-flags`).

**7.5 Bit 1 brings `peer-id`.** A server that sees bit 1 should assign a peer ID and push it.
[D §7.3.1; Man bit 1] *Confirmed* (S: without bit 1 the push had no `peer-id`; the stock client's had
one).

**7.6 Expected push for IV_PROTO=142.** *Hypothesis:* the 2.7.0 harness server pushes `peer-id`,
`protocol-flags cc-exit tls-ekm` and no `dyn-tls-crypt`, since dynamic tls-crypt is offered only to a
client with bit 9. **To observe** in item 5; the design's push test fails on any unadvertised flag.

## 8. PUSH_REQUEST, PUSH_REPLY and protocol-flags

**8.1 PUSH_REQUEST.** The text `PUSH_REQUEST`, sent by the client when it is ready for its
configuration, and repeated periodically until PUSH_REPLY arrives. [D §8.2 PUSH_REQUEST] *Supported.*
How long the client keeps repeating is bounded by `--hand-window` (default 60 s). [Man `--hand-window`]
*Supported.* The repeat interval is not documented: burrow's choice (recommendation: every 2 s, the
`--tls-timeout` default). With bit 2 set the server may push without waiting [D §8.3 PUSH_REPLY], but
burrow still sends PUSH_REQUEST, since the server may not. *Recommendation.*

PUSH_REQUEST is sent only under key ID 0. A renegotiated session keeps the initial push and sends no
PUSH_REQUEST. [D §6.2.2.3 CONTROL_SOFT_RESET_V1] *Supported.*

**8.2 PUSH_REPLY.** The text `PUSH_REPLY` followed by comma-separated options. [D §8.3] *Supported.*
The spike received, after the `PUSH_REPLY,` prefix:
`comp-lzo no,topology p2p,ping 10,ping-restart 60,ifconfig 10.88.0.4 10.88.0.1,cipher AES-256-GCM,key-derivation tls-ekm`
(S). So each option is a directive name followed by space-separated arguments, and options are joined
by commas. *Confirmed* (D and S).

**8.3 Options in the target push, and their value forms.**

| Option | Form | Source |
|---|---|---|
| `ifconfig L R` | under `topology p2p`: burrow's address, then the remote end (the server's) | Man `--ifconfig`, `--topology` p2p. *Confirmed* (S). |
| `topology p2p` | keyword | Man `--topology`. *Confirmed* (S). |
| `ping N`, `ping-restart N` | decimal seconds | Man `--keepalive` (the server pushes `ping 10`, `ping-restart 60` for `keepalive 10 60`). *Confirmed* (S). |
| `cipher NAME` | the chosen data cipher | M "Negotiating cipher"; Man "Data channel cipher negotiation". *Confirmed* (S). |
| `key-derivation tls-ekm` | without bit 7 | 7.4. *Confirmed.* |
| `protocol-flags F …` | with bit 7; space-separated flags | D §9.2 protocol-flags; the target server, as reported to us: `protocol-flags cc-exit tls-ekm dyn-tls-crypt`. *Supported.* |
| `peer-id N` | *Hypothesis:* decimal integer, 24-bit range | the draft says the client must use it [D §7.3.1] but gives no value form; the `ID=` peer-info form is hex [D §6.8], a different mechanism. **To observe** in item 5. |
| `comp-lzo no` | — | section 13. *Confirmed* (S). |
| `tun-mtu N` | decimal | Man `--tun-mtu`. The spike's push had none. *Hypothesis:* the server pushes `tun-mtu` only to clients that send `IV_MTU` [Man `IV_MTU`]; burrow sends none, so expects none and uses 1500 (design, MTU). **To observe** in item 5. |

**8.4 protocol-flags values.** [D §9.2] *Supported.*

| Flag | Meaning | burrow |
|---|---|---|
| `cc-exit` | send the exit notification on the control channel | accept (bit 7 advertised) |
| `tls-ekm` | derive data keys with the TLS exporter | accept; required (no EKM is fatal, design) |
| `dyn-tls-crypt` | renegotiations use dynamic tls-crypt | fatal: not advertised (bit 9) |
| `aead-epoch` | epoch keys and their data format | fatal: not advertised (bit 10) |
| `echo` | CONTROL_AUX_V1 echo TLVs | fatal: not advertised (bit 13) |

A client that is not told `tls-ekm` (in either form) may abort. [D §7.1.1] *Supported.*

**8.5 Push-continuation framing.** *Observed 2026-11-24 (item 3, harness 2.7.0 server log).* A
push too large for one message is sent as a sequence of PUSH_REPLY messages, each a complete
`PUSH_REPLY,…` text. Every message except the last ends with the option `push-continuation 2`; the
last ends with `push-continuation 1`. A push that fits in one message carries no `push-continuation`
option. With 400 host routes the 2.7.0 server sent 16 messages of 947–969 bytes, then a last one of
276 bytes holding the remaining options. The option order otherwise matches a single push. *Supported*
(one observation of our own session). **Rule for burrow:** assemble the options of consecutive
PUSH_REPLY messages until one carries `push-continuation 1`, or none; bound the total (8.6); a
`push-continuation` value other than 1 or 2 is fatal. This replaces the interim recommendation below,
which would have refused a legitimate split push.

Earlier text (before the observation): **Push-continuation framing: not documented.** No allowed source documents how a PUSH_REPLY too
large for one message is split. The draft's PUSH_REPLY section says nothing about splitting, the
man page has no entry for it, and miragevpn-spec does not mention it. **To observe**, method: item 3
configures the harness server to push enough `route` options to exceed one control message (a few
hundred), and item 5's client logs every PUSH_REPLY plaintext it receives; the syntax of the split
marker is read from that log. This observes our own session and reads no code.

The design makes an undocumented continuation fatal, but burrow can only refuse a continuation it can
recognise. **Recommendation until observed:** treat as fatal any pushed option that is not on the
honoured or recorded lists and whose name begins with `push-`. The design itself names the mechanism
"push-continuation", so a marker of that name is caught without assuming its arguments. Also treat a
second PUSH_REPLY on the same key ID as fatal.

**8.6 Bounds.** The design requires a fixed bound on a PUSH_REPLY. The target push is about 150 bytes.
Recommendation: 64 KiB total for an assembled push, 16 KiB per message (one TLS record cannot exceed
that anyway; RFC 8446 §5.1 caps plaintext records at 2^14 bytes).

## 9. Control messages from the server

All text, one per TLS record, NUL-terminated (5.2, 5.3). [D §8.1] Formats:

| Message | Format | Meaning | Source |
|---|---|---|---|
| `AUTH_FAILED` | `AUTH_FAILED` or `AUTH_FAILED,` + reason text. Variants `AUTH_FAILED,SESSION:` + text and `AUTH_FAILED,TEMP` (+ `[keywords]`) `:` + text | authentication failed. TEMP is a retryable failure for clients with bit 8; a client without bit 8 treats it as non-recoverable | D §8.7 AUTH_FAILED; Man "Data channel cipher negotiation" shows the example `AUTH_FAILED,Data channel cipher negotiation failed (no shared cipher)`. *Confirmed.* |
| `RESTART` | `RESTART`, or `RESTART,` + text, or `RESTART,[flags]` + text, where flags are characters such as `P` (purge credentials) and `N` (reconnect to the same server) | the server ends the session; the client is expected to reconnect | D §8.6 RESTART and HALT. *Supported.* Man `--explicit-exit-notify`: a UDP server with that option sends RESTART to its clients on exit. *Supported.* |
| `HALT` | `HALT` or `HALT,` + text | the server ends the session; the client should not reconnect | D §8.6. *Supported.* |
| `EXIT` | `EXIT` | the peer has terminated | D §8.8 EXIT. *Supported.* |
| `INFO` | `INFO,` + text; also `INFO_PRE,` + text | pending-auth parameters | D §8.10 INFO_PRE and INFO. *Supported.* |
| `AUTH_PENDING` | `AUTH_PENDING` or `AUTH_PENDING,` + flags | multi-factor in progress | D §8.5 AUTH_PENDING. Not advertised; treated as unknown (design). |

Parsing rule: the message name is the text up to the first comma or the end. The remainder is opaque
text that may itself contain commas, so it is never split. *Recommendation.*

**9.1 Refusal by the client-connect hook.** *Observed 2026-11-24 (item 5):* a client advertising
`IV_PROTO=142` receives `AUTH_FAILED` at once when the hook refuses, from 2.7.0 and 2.6.19 alike.
The silence the TLS spike saw came from a client advertising `IV_PROTO=12`. Earlier text: The man page says the server sends AUTH_FAILED when the
client-connect script returns an error. [Man `--auth-retry`] The spike observed the opposite on 2.7.0:
with the hook refusing, no PUSH_REPLY and no AUTH_FAILED arrived within 10 s (S). *Inconclusive*
across the two. Recommendation: keep the design's push timeout as the primary signal, and handle
AUTH_FAILED if it arrives. **To observe** in item 5 or 7: with the rejected CN, wait past
`--hand-window` (60 s) and record whether AUTH_FAILED ever arrives.

## 10. Data channel keys: EKM and the key-material layout

**10.1 Exporter call.** RFC 5705-style keying material exporter on the control channel's TLS session,
label `EXPORTER-OpenVPN-datakeys`, length 256 bytes. [D §7.1.1 Data channel key generation; M "EKM"]
*Confirmed* (S: Go's `ExportKeyingMaterial` with this label and length returned 256 bytes on TLS 1.3
against both servers).

**10.2 Context.** Neither source names a context value. Under TLS 1.3, no context and an empty context
give the same exporter output. [RFC 8446 §7.5 Exporters] *Supported.* Under TLS 1.2 they differ [RFC
5705 §4], which matters only for a later TLS 1.2 path. Recommendation: no context. **To observe** in
item 6: the server's data packets decrypt with the keys derived this way.

**10.3 Layout of the 256 bytes.** Four 64-byte blocks, in this order: client-to-server cipher key,
client-to-server "auth" block, server-to-client cipher key, server-to-client "auth" block. Client and
server are the TLS roles. A cipher uses the first bytes it needs from a block. [D §7.1 OpenVPN Key]
*Supported* (draft). miragevpn-spec describes the same 4 × 64 structure for static keys ("OpenVPN
static keys": two directional halves, each a 64-byte cipher part then a 64-byte HMAC part, first N
bytes used), which agrees but concerns a different key.

**10.4 The AEAD implicit IV comes from the auth block.** For AEAD ciphers the implicit IV is the first
bytes of the direction's auth block: 8 bytes for AES-GCM with 32-bit packet IDs. [D §7.4 AEAD
encrypted data channel packet] *Supported* (draft only; miragevpn-spec says only that the implicit IV
comes "from the ephemeral keys"). **To observe** in item 6, by decryption.

**10.5 Offsets for burrow (TLS client):**

| Bytes | Block | AES-128-GCM | AES-256-GCM |
|---|---|---|---|
| 0–63 | client-to-server cipher key | send key = bytes 0–15 | send key = bytes 0–31 |
| 64–127 | client-to-server auth | send implicit IV = bytes 64–71 | send implicit IV = bytes 64–71 |
| 128–191 | server-to-client cipher key | receive key = bytes 128–143 | receive key = bytes 128–159 |
| 192–255 | server-to-client auth | receive implicit IV = bytes 192–199 | receive implicit IV = bytes 192–199 |

Bytes not listed are unused by AES-GCM. *Supported* (D §7.1, §7.4); confirmed when item 6 decrypts
the harness server's packets.

**10.6 Per key ID.** Each successfully established control-channel session produces its own 256-byte
block, bound to that session's key ID. [D §7.1.1] *Supported.* Renegotiation therefore derives fresh
keys from the new TLS session; the cipher stays the one first pushed (8.1). [D §6.2.2.3] *Supported.*

## 11. The AEAD data packet (DATA_V2)

**11.1 Layout:**

```
offset  size   field
0       1      0x48 | key_id            (opcode 9)
1       3      peer ID, 24-bit big-endian
4       4      data packet ID, uint32
8       16     AEAD tag
24      rest   ciphertext, same length as the plaintext
```

[D §7.4; D §6.2.2.13 DATA_V2; M "AEAD" (packet ID, then 16-byte tag, then ciphertext)] *Confirmed*
(two sources). The tag comes **before** the ciphertext. An AEAD implementation that appends the tag
(as Go's `cipher.AEAD.Seal` does) needs the tag moved to offset 8 on send and back to the end on
receive.

**11.2 Peer ID.** burrow uses the pushed `peer-id` in every DATA_V2 packet it sends. [D §7.3.1] It does
not send `ID=` in peer-info, so the asymmetric peer-ID negotiation of D §6.8 does not apply and the
server pushes `peer-id` (D §6.8 forbids pushing it only when that negotiation succeeded).
*Supported.* The client is not expected to parse the peer ID in packets it receives. [D §7.3.1]
*Supported.* It still enters the AAD exactly as received (11.4).

If no `peer-id` is pushed although bit 1 was sent: the draft says a client must still send a valid
peer ID, possibly the one meaning "disabled" [D §7.3.1], but never gives that value. Recommendation:
fatal push in the first release. Open question for the Plan.

**11.3 Nonce.** 12 bytes: the 4 bytes of the data packet ID, as on the wire, followed by the 8-byte
implicit IV (10.4). Concatenation, not XOR. [D §7.4 ("packet_id | implicit_iv"); M "AEAD" (the
packet ID prepended to the implicit IV)] *Confirmed* (two sources). The XOR construction belongs to
epoch keys only [D §7.5], which are out of scope. Consistent with RFC 5116's 12-byte AEAD nonce.

**11.4 AAD.** For DATA_V2 the authenticated data covers the opcode and key ID byte, the peer ID and
the data packet ID, followed by the payload. [D §7.4] In AEAD terms, the additional data is bytes 0–7
of the packet (8 bytes) and the payload is the AEAD plaintext. *Supported* (draft for DATA_V2). The
DATA_V1 rule in the same section (AAD = the 4-byte packet ID alone) agrees with miragevpn-spec's
"replay ID as associated data" [M "AEAD"], so the construction is *Confirmed* for V1 and *Supported*
for V2. **To observe** in item 6, by decryption.

**11.5 Tag.** 16 bytes (128 bits). [D §7.4; M "AEAD"] *Confirmed.*

**11.6 Plaintext.** Under `comp-lzo no`, the compression marker byte then the IP packet (section 13),
or the keepalive payload (section 14).

**11.7 Data packet IDs.** A per-key, per-direction counter that also feeds replay protection.
[D §7.4] *Supported.*

- **First value.** Not documented. **Recommendation:** burrow's first data packet ID under each key is
  1. A receiver that treats 0 as invalid accepts 1, and a receiver that expects 0 first also accepts
  1, because a higher ID than any seen is always accepted (12.1). **To observe** in item 6: the first
  data packet ID the server sends.
- **No reuse.** An ID is never sent twice under one key. The 32-bit counter must not wrap (design,
  Security).
- **When to renegotiate.** The draft's usage limit, at the 2^-57 safety margin TLS uses, allows about
  2^29.4 AES-GCM packets of 1500 bytes (2^29.3 at 1600) under one key, fewer than the 2^32 the counter
  holds. [D §7.2.1 AEAD cipher usage limits, table] *Supported.* Recommendation: start a renegotiation
  at 2^28 packets sent under one key, and stop sending on that key at 2^29.

**11.8 Overhead.** 4 (first byte and peer ID) + 4 (packet ID) + 16 (tag) + 1 (compression marker) =
**25 bytes** per DATA_V2 packet, before UDP and IP. *Confirmed* by arithmetic from 11.1 and 13.1.

**11.9 DATA_V1 on receive.** DATA_V1 is DATA_V2 without the peer ID: every following field shifts 3
bytes left, so the tag sits at offset 5 and the ciphertext at 21, and the AAD is the 4-byte packet ID
alone. [D §6.2.2.14 DATA_V1; D §7.4; M "AEAD"] *Confirmed.* The server should send DATA_V2 [D §7.3.1].
Whether burrow also accepts DATA_V1 is the Plan's choice; recommendation: accept, count, and send only
DATA_V2. **To observe** in item 6: the opcode the server uses (expected 9).

**11.10 Order of checks** (design, Security): replay check before decryption, window advanced only
after the tag verifies. The draft recommends the receiver count packets that fail verification.
[D §7.2.1, last paragraph] *Supported.*

## 12. Replay window

**12.1 Rules.** A packet with a higher ID than any seen is accepted. An out-of-order packet is accepted
only if (a) its ID is within n of the highest seen, (b) it arrives no later than t seconds after any
packet with a higher ID, and (c) it is not a replay. [D §7.3.3 Replay protection; Man
`--replay-window`] *Confirmed* (two sources).

**12.2 Defaults.** n = 64 packets, t = 15 s. [Man `--replay-window`] *Supported.* The window applies to
UDP; over TCP older peers enforced strict ordering. [Man `--replay-window`; D §7.3.3] *Supported.*

**12.3 State.** The receiver keeps the highest ID seen and which of the n IDs below it have arrived.
[D §7.3.3] *Supported.* For rule (b) it also needs the time each higher ID arrived; *Hypothesis* that
recording the arrival time of the highest ID is enough, since any packet with an ID above the
out-of-order one starts its t-second clock no later than that.

## 13. Compression framing

**13.1 `comp-lzo no`: one marker byte.** With compression framing on and compression off, every data
payload starts with one byte naming the method; the no-compression value is `0xFA`. [M "Data
channel": "0xFA for the null compression"] *Supported* (miragevpn-spec gives the value). The man page
says `comp-lzo` "may add 1 additional byte per packet" [Man `--comp-lzo`] and the target profile
reports the byte, which agrees on the size but not the value. **To observe** in item 6, by decrypting
the harness server's packets; the byte sits at plaintext offset 0.

- **Send:** `0xFA` followed by the IP packet.
- **Receive:** a plaintext starting with `0xFA` yields the rest as the IP packet. Any other first byte
  is a compressed or unknown frame. A 2.7 peer never compresses outgoing packets [Man `--compress`,
  Security Considerations; Man `--comp-lzo`], and the server's default `--allow-compression no`
  refuses compression [Man `--allow-compression`]. So any other byte is dropped and counted.
  *Recommendation.*
- `comp-noadapt` has no effect in current versions. [Man `--comp-noadapt`] *Supported.* burrow accepts
  it as a no-op.

**13.2 When the marker applies.** Framing is on when `comp-lzo` is configured or pushed. The target
client configuration has `comp-lzo no` and the server pushes `comp-lzo no` (S), so the marker is on for
every data packet of the profile. *Confirmed* (configuration file and S). *Hypothesis:* the keepalive
payload also carries the marker; **To observe** with 14.1.

**13.3 `compress stub`.** Compression off, framing on, with "one extra framing byte" like the other
non-v2 variants. [Man `--compress`] *Supported* for the size. The byte's value is not documented, and
the man page says `stub` is *not* compatible with `comp-lzo no`, so the framing differs from 13.1 in
some way it does not state. [Man `--compress`, Note] **Undocumented: fatal in the first release**, per
the design's rule. **To observe** later if needed: harness server with `compress stub`, decrypt.

**13.4 `compress stub-v2`.** The v2 framings add no byte to packets that are not compressed, and a
compressed frame's header reads as IP version 5 in a tun setup. So stub-v2 is essentially no
compression and no framing. [Man `--compress`] *Supported* (man page prose only). *Hypothesis* for the
wire: send the bare IP packet; on receive, deliver packets whose first nibble is 4 or 6 and drop
others. **Recommendation:** fatal in the first release. The source is prose, not a byte-level
definition, and the target pushes `comp-lzo no`. **To observe** before honouring it: harness server
with `compress stub-v2`, decrypt.

**13.5 Advertising compression support.** The stock client announces its compression framings with
`IV_LZO_STUB=1` (can talk to a `comp-lzo no` server), `IV_COMP_STUB=1` and `IV_COMP_STUBv2=1` (can talk
to a `compress` server) and `IV_LZO`/`IV_LZ4`. [Man `--push-peer-info`] *Supported.* The server's
`compress migrate` mode pushes `stub-v2` only to clients that support it. [Man `--compress` migrate]
*Supported.* burrow sends none of these (design's peer-info list), so a migrating server would fall
back to `comp-lzo no`. The spike, which sent none of them either, received `comp-lzo no` from the
target-like server (S). Whether to add `IV_LZO_STUB=1` is an open question in discover.md; the
recommendation is not to.

## 14. Keepalive

**14.1 Ping payload.** *Observed 2026-11-24 (item 6, decrypted from our own session with both harness
servers):* the plaintext is `0xFA` followed by the 16 bytes `2a 18 7b f3 64 1e b4 cb 07 ed 2d 0a 98 1f
c7 48`. *Supported* (two servers, one observation each; the servers also accept burrow's pings of these
bytes over 130 s). Earlier text: **Ping payload: not documented.** The keepalive is the OCC ping, sent on the data channel; the
draft names it as the keepalive that survived into the data-channel-offload era but gives no bytes.
[D §10.1 General overview] No allowed source gives the payload. **To observe**, method (design,
Testing): item 6's client decrypts the harness server's pings (sent every 10 s on an idle tunnel) and
records the plaintext, including whether the `0xFA` marker precedes it. The server log at high
verbosity is the second witness. Until observed, burrow cannot send a valid ping. This blocks
`ping-restart` survival on an idle tunnel, so item 6 observes it before its keepalive work.

**14.2 Where the ping travels.** The draft places the OCC ping on the data channel [D §10.1]. The man
page says the ping travels "over the TCP/UDP control channel" [Man `--ping`], which in context means
the transport link, not the control-channel opcodes. **Recommendation: data channel**, encrypted as
any data packet. *Supported* (draft); item 6's decryption confirms it, since a ping visible only after
decryption is a data packet.

**14.3 When to send.** A ping goes out when nothing has been sent for `ping` seconds. Pings are not
echoed: each side sends its own. [Man `--ping`] *Supported.*

**14.4 Timeout.** `ping-restart n` restarts after n seconds without "a ping or other packet" from the
remote. [Man `--ping-restart`] *Supported.* The client default is 120 s until the server pushes its
own. [Man `--ping-restart`] *Supported.* The server's `keepalive 10 60` pushes `ping 10` and
`ping-restart 60` and runs 120 s itself. [Man `--keepalive`] *Confirmed* (S). **Recommendation:**
only an authenticated data packet resets burrow's timer. This profile's control packets are
unauthenticated, so a forged one must not keep a dead tunnel alive. The design already counts data
packets only.

**14.5 Pings are not activity** for `--inactive`. [Man `--inactive`] *Supported.* No effect on burrow.

## 15. Soft reset, key IDs and the transition window

**15.1 Exchange.** Either side may send CONTROL_SOFT_RESET_V1 under the next key ID. The other side
must answer with its own CONTROL_SOFT_RESET_V1, and the side that receives the last one sends an
ACK_V1. TLS then runs in CONTROL_V1 packets under the new key ID. [D §6.2.2.3 CONTROL_SOFT_RESET_V1]
*Supported.* M "Operations" adds only that the soft reset is the first packet under a fresh key ID.
burrow is the TLS client in every renegotiation, whichever side started it (5.1).

**15.2 Packet layout.** A control packet as in 2.1 with opcode 3 and an empty payload. [D §6.1 table
gives no payload for SOFT_RESET] *Supported.*

**15.3 Reliability state per key ID.** *Hypothesis*, from the draft's "negotiated the same as the
initial session" [D §6.2.2.3]: each key ID has its own reliable sequence. The SOFT_RESET is packet ID
0 in each direction, as the hard reset is under key ID 0, and the TLS ClientHello starts at packet ID
1. Both session IDs stay those of the original session, since a new session ID marks a full reconnect
[D §6.2.1.4]. **To observe** in item 3's capture of a stock client renegotiating (short `reneg-sec`):
the key ID, packet IDs, session IDs and ACKs of each soft-reset packet. Item 11 confirms.

**Observed** (item 11, O13, server side): the 2.7.0 and 2.6.19 servers' soft reset is opcode 3 under
key 1, packet ID 0, with no ACKs and an empty payload. It carries the server's session ID from the
hard reset, and is resent 2 s, then 4 s later until answered. A per-key reliability state with the
original session IDs and a soft reset as packet 0 completed every renegotiation, from either side, on
both servers. *Confirmed.*

**15.4 After TLS.** Key method 2 is exchanged again under the new key ID, then data keys are derived
from the new TLS session (10.6). No PUSH_REQUEST. [D §6.2.2.3] *Supported* for no push. **Observed**
(item 11, O14): both servers send their key-method-2 message on every renegotiation, after burrow's.
*Confirmed.*

**15.5 Key ID sequence.** Current + 1, and 7 is followed by 1. A failed renegotiation that is retried
reuses the failed attempt's key ID. [D §6.2.2.3; D §6.2.1.3] *Confirmed* (with M "Packet wire
format").

**15.6 Who renegotiates when.**

- `reneg-sec max [min]`: default max 3600 s. The effective value is uniformly randomised between min
  and max per session. min defaults to 90% of max on a server (3240–3600 s) and equals max on a client
  (exactly 3600 s). Whichever side has the lower value triggers. `0` disables it on that side. [Man
  `--reneg-sec`] *Supported.*
- `reneg-bytes` and `reneg-pkts` are off by default, except `reneg-bytes` 64 MB for ciphers with
  blocks under 128 bits, which excludes AES-GCM. [Man `--reneg-bytes`, `--reneg-pkts`] *Supported.*
- The renegotiation must complete within `--hand-window` (default 60 s) of its start. On failure the
  stock peer resets and tries again, and keeps the expiring key for up to `--tran-window`. [Man
  `--hand-window`] *Supported.* The design instead ends the tunnel on an incomplete renegotiation; that
  is a burrow choice, not a protocol requirement.

**15.7 Pending, active and retiring keys.** [D §7.2.4 Data channel key rotation] *Supported*, with a
caveat: the section sits under the draft's epoch-key chapter, but its text describes key rotation in
general.

- When a renegotiation finishes, the new key is **pending**: it decrypts packets with its key ID but is
  not yet used to encrypt.
- After a delay the pending key is promoted to **active** and the old active key becomes **retired**
  (the "lame duck"), used only to decrypt. The default delay is min(`hand-window`, `reneg-sec` / 2) =
  min(60, 1800) = **60 s**. The delay prevents desynchronisation: by the time either side encrypts with
  the new key, the other has had time to install it. [D §7.2.4] The man page gives the same defaults
  (60 and 3600). *Confirmed* for the default values.
- A retired key lives until `--tran-window` (default 3600 s) after the renegotiation began. [Man
  `--tran-window`] *Supported.*
- If a renegotiation completes while a pending key still waits, the waiting key replaces the active
  one and the new key becomes pending. An implementation may keep only two key slots, then dropping
  the active key without retiring it. [D §7.2.4, last paragraph] *Supported.* This is the design's "at
  most two live, drop the retiring one first".

**Recommendation for burrow's send switch:** decrypt with a new key as soon as it is installed. Start
encrypting with it at the earlier of (a) the 60 s promotion timer and (b) the first data packet from
the server that authenticates under the new key, because a peer that sends with a key has installed
it. (b) is our inference (*Hypothesis*), safe by construction, and shortens the window in which both
keys carry traffic.

**15.8 Both sides start a soft reset at once.** No source addresses the race. Reading D §6.2.2.3's
exchange (initiator's SOFT_RESET, responder's SOFT_RESET, ACK), each side's packet serves as the
other's answer when the two cross. **Rule (Hypothesis):**

1. Both sides compute the same next key ID from the same current one, so the two soft resets name the
   same key ID.
2. A SOFT_RESET for key ID k received while burrow's own SOFT_RESET for k is unacknowledged is the
   peer's answer, not a new negotiation. burrow ACKs it (piggybacked or in an ACK_V1), keeps its own
   outstanding packet for retransmission until ACKed, and does not send a second SOFT_RESET.
3. The TLS roles are fixed, so there is no conflict over who starts TLS: burrow sends the ClientHello
   as packet ID 1 under key k.
4. A SOFT_RESET for a key ID other than current + 1 while a renegotiation is in progress is dropped
   and counted. Exception: a SOFT_RESET for the key ID burrow itself is negotiating is rule 2.

**To observe** in item 11: run the harness server with `reneg-sec 60 60` (min = max removes the
randomisation [Man `--reneg-sec`]) and burrow at 60 s, so both fire within the same second.
Capture the plain headers and check that the session reaches the new key. A scripted peer in burrow's
unit tests covers the exact crossing order, which the harness cannot force.

**Observed** (item 11, O15): with the server at `reneg-sec 20 20` and burrow at 20 s, four
renegotiations in 90 s all completed, with no soft reset dropped. burrow's soft reset went first in
three, the server's in one. Whether the two packets crossed on the wire is not visible from the
client. The rule above is checked by the session's decision tables.

**15.9 Server re-running client-connect on a soft reset.** Not documented. **Observed** (item 11,
O16): the harness allowlist log shows one `client-connect` call per session through two server
renegotiations, four simultaneous ones and a client-initiated one, on 2.7.0 and 2.6.19. The hook does
not re-run on a soft reset, so a renegotiation cannot be refused by it.

## 16. Close and EXIT

**16.1 Sending EXIT.** The client sends the text `EXIT` (NUL-terminated, own TLS record) on the
control channel when both sides support it: bit 7 advertised and `cc-exit` pushed. With EXIT, the
server closes the client instance at once instead of timing it out. [Man `--explicit-exit-notify`; D
§9.2 (`cc-exit`); D §8.8] *Supported.* The stock client sends no exit notification unless configured
to [Man `--explicit-exit-notify`]; burrow always sends one (design). *Hypothesis:* EXIT goes under the
active key ID's TLS session. **Observed** (item 11): EXIT sent on the active key after renegotiations
(keys 2 and 4) is logged by both servers as received, as in O12. *Confirmed.* **To observe** in item 5: the server log shows the session freed on
EXIT.

**16.2 Without `cc-exit`.** The alternative is a data-channel exit message (OCC), which is not
documented. [Man `--explicit-exit-notify`] Recommendation: send nothing and tear down; the server
times the session out.

## 17. Defaults

| Setting | Default | Source | Confidence |
|---|---|---|---|
| control packet size limit (the design's "tls-mtu"; the 2.7 option is `--max-packet-size`) | 1250 bytes **including IP and UDP headers**; settable 154–2048 | Man `--max-packet-size`; D §6.5 ("1250 or smaller") | *Confirmed* (value); *Supported* (that it includes IP and UDP) |
| `mssfix` | `1492 mtu`: the whole outer IP packet ≤ 1492 bytes | Man `--mssfix` | *Supported*; see 18.2 for the man page's internal disagreement |
| `tun-mtu` | 1500 | Man `--tun-mtu` | *Supported* |
| `tun-mtu-max` (server buffers) | 1600 | Man `--tun-mtu-max` | *Supported* |
| `replay-window` | 64 packets, 15 s | Man `--replay-window` | *Supported* |
| `reneg-sec` | 3600 s; server min 90% (3240) | Man `--reneg-sec` | *Supported* |
| `tran-window` | 3600 s | Man `--tran-window` | *Supported* |
| `hand-window` | 60 s | Man `--hand-window`; D §7.2.4 | *Confirmed* |
| key promotion delay | min(hand-window, reneg-sec / 2) = 60 s | D §7.2.4 | *Supported* |
| `ping` | none (off) until pushed | Man `--ping` (no default stated) | *Supported* |
| `ping-restart` | 120 s on a client until pushed | Man `--ping-restart` | *Supported* |
| pushed by `keepalive 10 60` | `ping 10`, `ping-restart 60` | Man `--keepalive`; S | *Confirmed* |
| `tls-timeout` | 2 s, exponential backoff | Man `--tls-timeout` | *Supported* |
| `server-poll-timeout` / `connect-timeout` | 120 s | Man `--server-poll-timeout` | *Supported* |
| `connect-retry` | 1 s; doubles after 5 retries per remote; cap 300 s | Man `--connect-retry`; M "Configuration parameters" | *Confirmed* |
| `data-ciphers` (server) | AES-256-GCM:AES-128-GCM, plus CHACHA20-POLY1305 where available | Man `--data-ciphers` | *Supported* |
| `allow-compression` | no | Man `--allow-compression` | *Supported* |
| `explicit-exit-notify` | off; `n` default 1 when given | Man `--explicit-exit-notify` | *Supported* |
| default port | 1194 | Man `--port`; M | *Confirmed* |

## 18. Sizes

**18.1 Control packets.** The 1250-byte default bounds the whole IP datagram. [Man
`--max-packet-size`] So the OpenVPN control packet (UDP payload) is at most 1250 − 28 = **1222 bytes**
over IPv4 and 1250 − 48 = **1202 bytes** over IPv6. At 14 + 4n + 8 bytes of header (2.1), a CONTROL_V1
carrying 4 ACKs leaves 1222 − 38 = 1184 bytes of TLS data per packet over IPv4. *Confirmed* by
arithmetic from cited values. The draft says only that the implementation "expects" control packets of
1250 or less [D §6.5]; staying under the man page's stricter reading satisfies both.

On receive, a peer may be configured up to 2048 [Man `--max-packet-size`], so burrow accepts control
packets up to 2048 bytes of UDP payload. *Recommendation.*

**18.2 `mssfix` semantics.** [Man `--mssfix`] *Supported.*

- With the `mtu` keyword (the default `1492 mtu`), the limit is the outer packet including the IP and
  UDP headers.
- Without it (the target configuration's optional `mssfix 1410`), the limit is the UDP payload, the OpenVPN packet,
  excluding the UDP header. The outer IP packet is then up to 28 (IPv4) or 48 (IPv6) bytes larger.
- `0` disables it; `fixed` limits the inner IP packets to the given size directly (IPv4 MSS = value −
  40, IPv6 = value − 60).

The man page contradicts itself here: one sentence gives the default as "1492 mtu", a later one speaks
of a "default value of 1450". **Recommendation: 1492 with `mtu` semantics.** It is the sentence that
states the default, and the 1450 sentence reads as a leftover example of the non-`mtu` form.

**18.3 MSS arithmetic for burrow** (*Confirmed* arithmetic from 11.8 and 18.2; whether OpenVPN's own
clamp produces exactly these numbers is *Hypothesis*):

| Case | Bound | Outer overhead | Largest inner IP packet | TCP MSS (IPv4 inner) | TCP MSS (IPv6 inner) |
|---|---|---|---|---|---|
| default `1492 mtu`, IPv4 outer | 1492 | 25 + 8 + 20 = 53 | 1439 | 1399 | 1379 |
| default `1492 mtu`, IPv6 outer | 1492 | 25 + 8 + 40 = 73 | 1419 | 1379 | 1359 |
| `mssfix 1410` (no `mtu`) | 1410 (UDP payload) | 25 | 1385 | 1345 | 1325 |

**To observe** (optional, item 9): the MSS the stock client clamps a SYN to through the harness tunnel,
captured on the server's tun device, to compare with this table.

**18.4 Receive buffer.** Largest expected data datagram: `tun-mtu` + 25. A server's buffers allow
pushed MTUs up to 1600 [Man `--tun-mtu-max`], and the draft says the stock implementation may send up
to its 1600-byte internal buffer [D §7.2.1]. Control packets reach 2048 (18.1). **Recommendation:** a
receive buffer of at least 2048 bytes, dropping and counting anything larger.

## 19. remote-cert-tls server

**19.1 What the option means.** `remote-cert-tls server` is equivalent to `remote-cert-ku` with no
arguments plus `remote-cert-eku "TLS Web Server Authentication"`. [Man `--remote-cert-tls`]
*Supported.* It applies to the peer's (leaf) certificate.

**19.2 Extended key usage.** The leaf must carry the EKU extension and it must list serverAuth,
OID 1.3.6.1.5.5.7.3.1 ("TLS Web Server Authentication" is its OpenSSL display name). The man page
says the EKU must be explicit. [Man `--remote-cert-eku`; RFC 5280 §4.2.1.12] *Supported.* A leaf
with no EKU extension fails (Go would accept it; the design rejects it in burrow's own check).
**Recommendation:** also reject a leaf whose EKU lists only anyExtendedKeyUsage (2.5.29.37.0), since
"explicit" rules it out. *Hypothesis* about OpenVPN's own treatment.

**19.3 Key usage: yes, it is checked.** `remote-cert-ku` without arguments requires the keyUsage
extension (OID 2.5.29.15) to be present, and leaves its value to the TLS library's own validation.
[Man `--remote-cert-ku`] *Supported.* For a TLS 1.3 server certificate, the key must allow signing: the
digitalSignature bit must be set if keyUsage is present. [RFC 8446 §4.4.2.2 Server Certificate
Selection] *Supported.* Go's `crypto/tls` does not enforce key usage (the design review), so burrow
checks:

- the leaf has a keyUsage extension; reject if absent;
- that extension has digitalSignature set; reject if not.

*Hypothesis* that OpenSSL under OpenVPN enforces the digitalSignature rule in TLS 1.3; burrow enforces
it regardless, as RFC 8446 requires it. Evidence that the target server's certificate passes: the target's own
clients use `remote-cert-tls server` and connect, so the certificate has the keyUsage extension
(*Supported*, from the target profile's client configuration). That the bit is set is confirmed only
by the live check. **Two tests to add** beside the design's four: a leaf from the right CA with
serverAuth but no keyUsage extension is rejected; one with keyUsage lacking digitalSignature is
rejected. Each has a negative control.

**19.4 Chain.** The peer certificate must chain to a CA in `--ca`; the file may hold several
concatenated PEM certificates. [Man `--ca`] *Supported.*

**19.5 Repeated per session.** Every TLS session, renegotiations included, presents and verifies
certificates (design). The man page describes every connection presenting and checking certificates
[Man "TLS Mode Options"]; *Hypothesis* that the server re-sends its certificate on renegotiation, which
TLS 1.3 requires of a full handshake anyway.

## 20. TCP framing (later release)

**20.1** Over TCP, every OpenVPN packet is preceded by a 16-bit big-endian length counting the bytes
that follow, excluding the length itself. The packet inside is identical to the UDP form, so the
opcode is the third byte of the stream frame. [D §4; D §6.2.1.1 Field: pkt_len; D §6.1; M
"Transport"] *Confirmed.*

**20.2** Over TCP the replay window's reordering allowance does not apply (the man page calls the
option UDP-only), and older peers reject any reordering. [Man `--replay-window`; D §7.3.3] *Supported.*
*Hypothesis:* data packet IDs must then arrive strictly increasing.

**20.3** The man page's TCP client retries the connect after 5 s by default, adjustable with
`--connect-retry`. [Man `--proto`] *Supported.*

## 21. Register of source disagreements

| # | Topic | Readings | Settled as |
|---|---|---|---|
| R1 | ACK entry size | D §5.1, §5.3: 8 bytes; D §5.4.1, §6.2.1, §6.2.1.7, M: 4 bytes | 4 bytes, *Confirmed* by S (2.3) |
| R2 | Server key-method-2 pre-master | D §6.6: present; M: omitted | parse M, fall back to D; to observe (6.4) |
| R3 | Empty string in key method 2 | D: L = 1 with NUL; M: L = 0 or L = 1 | send L = 1, accept both; to observe (6.2) |
| R4 | IV_PROTO bit 6 | Man: `--dns` support; D: deprecated, `dns` moved to bit 11 | moot, neither set (7.3) |
| R5 | Where the ping travels | D §10.1: data channel; Man `--ping`: "control channel" | data channel; to observe (14.2) |
| R6 | `mssfix` default | Man: "1492 mtu" and a later "1450" | 1492 `mtu` (18.2) |
| R7 | Client-connect refusal | Man `--auth-retry`: AUTH_FAILED; S: silence within 10 s | handle both; to observe with a longer wait (9.1) |
| R8 | Section placement of key rotation | D §7.2.4 sits in the epoch chapter but reads as general | used as general (15.7) |
| R9 | Transition window owner | D §6.2.2.3: "decided by the server"; Man: `--tran-window` is a local option | burrow applies its own `tran-window` default (15.7) |

## 22. Register of "To observe" items

| # | Fact | Method | Item |
|---|---|---|---|
| O1 | Ping payload bytes, and whether `0xFA` precedes them | **settled 2026-11-24** (item 6): `0xFA` then 16 bytes `2a 18 7b f3 64 1e b4 cb 07 ed 2d 0a 98 1f c7 48`, the same from 2.7.0 and 2.6.19; both servers kept a 130 s idle tunnel alive on burrow's pings of the same bytes | 6 |
| O2 | `0xFA` marker value and position | **settled 2026-11-24** (item 6): `0xFA` at plaintext offset 0 on the server's IP packets and pings | 6 |
| O3 | Implicit IV from the auth blocks, key offsets, AAD, nonce | **settled 2026-11-24** (item 6): every server data packet authenticated with 10.5, 11.3 and 11.4 as written, and the server answered burrow's ICMP echoes | 6 |
| O4 | First data packet ID; opcode the server uses (9 expected) | **settled 2026-11-24** (item 6): first ID 1, opcode 9 (DATA_V2), no DATA_V1 | 6 |
| O5 | Push-continuation marker syntax | **settled 2026-11-24** (8.5): `push-continuation 2` on all but the last message, `1` on the last; observed in the 2.7.0 harness server's log with 400 routes | 3 |
| O6 | Server key-method-2 layout (R2) | **settled 2026-11-24** (item 5): 2.7.0 and 2.6.19 send 187 bytes in miragevpn-spec's layout, with no pre-master field | 5 |
| O7 | Empty-string encoding and empty options string accepted (R3, 6.3) | **settled 2026-11-24** (item 5): L = 1 with NUL for all three, and the server log shows no warning | 5 |
| O8 | NUL after server text messages | **settled 2026-11-24** (item 5): burrow's reader ends messages only at a NUL, and every push and AUTH_FAILED arrived complete | 5 |
| O9 | Push for IV_PROTO=142: `peer-id` value form, `protocol-flags cc-exit tls-ekm`, no `dyn-tls-crypt`, no `tun-mtu` | **settled 2026-11-24** (item 5): `…,ifconfig 10.88.0.4 10.88.0.1,peer-id 0,cipher AES-256-GCM,protocol-flags cc-exit tls-ekm`, with no `tun-mtu` and no `dyn-tls-crypt`, on both servers | 5 |
| O10 | Non-OpenVPN `IV_VER` accepted | **settled 2026-11-24** (item 5): `IV_VER=burrow-interop` logged and the same push sent | 5 |
| O11 | AUTH_FAILED ever sent on hook refusal (R7) | **settled 2026-11-24** (item 5): with `IV_PROTO=142` the 2.7.0 and 2.6.19 servers send `AUTH_FAILED` at once on a client-connect refusal. the TLS spike's client (`IV_PROTO=12`) got nothing within 10 s; bit 7 is the likely difference (Hypothesis) | 5 |
| O12 | EXIT frees the server session | **settled 2026-11-24** (item 5): the server logs "CC-EEN exit message received by peer" and "Delayed exit in 5 seconds"; the same after a Close on renegotiated keys 2 and 4 (item 11, 16.1) | 5 |
| O13 | Soft-reset packets: packet IDs, session IDs, ACK key ID, three-packet exchange (2.6, 15.3) | **settled 2026-11-24** (item 11, 15.3): the server's soft reset is packet 0 under the new key with the original session IDs and no ACKs, resent at 2 s then 4 s. A stock client's are wrapped by dynamic tls-crypt (item 3), so burrow's own sessions were observed | 11 |
| O14 | Key method 2 repeated on renegotiation (15.4) | **settled 2026-11-24** (item 11): yes, on both servers | 11 |
| O15 | Simultaneous soft resets (15.8) | **observed 2026-11-24** (item 11): four renegotiations at equal 20 s intervals all completed; the crossing order is not visible, so the decision tables check rule 2 | 11 |
| O16 | Client-connect re-run on soft reset | **settled 2026-11-24** (item 11, 15.9): no, on both servers | 11 |
| O17 | Server's in-flight control packets (informative) | **settled 2026-11-24** (3.5): at most 3 unacknowledged in the handshake | 3 |
| O18 | Stock client's MSS clamp (optional) | SYN captured on the harness server's tun | 9 |

## 23. Client configuration directives

Added by item 10 for the `.ovpn` loader. Facts from the OpenVPN 2.6.19 manual page (Ubuntu noble),
read 2026-11-24 and paraphrased. A fact marked *Supported* was read in the page text; one marked
*Hypothesis* came only from a summary of a section not read in full.

**23.1 File syntax.** [Man, "Options" and `--config`] *Supported.*

- A `#` or `;` in the first column starts a comment. The page names no comment that follows a
  directive on the same line; burrow treats a later `#` as an ordinary character.
- Single or double quotes enclose one parameter that holds whitespace. Outside single quotes, a
  doubled backslash gives one backslash, a backslash before a double quote gives the quote, and a
  backslash before a space or tab gives that character.
- In a file, an option's leading `--` is left off. Whether the dashes are also accepted there is not
  stated; burrow refuses them.

**23.2 Remotes.** [Man `--remote`, `--proto`, `--port`] *Supported.*

- Several `remote` lines are tried in the order given, moving to the next on failure, with one server
  connected at a time.
- A host name with several addresses is tried address by address, in resolver order.
- The default protocol is UDP, and the default port 1194.

**23.3 `<connection>` blocks.** [Man, "Connection Profiles"] *Hypothesis:* a block may hold `remote`
and some link options, and options before the blocks act as their defaults. burrow accepts only
`remote` and `nobind` inside a block, and refuses `remote` both inside and outside blocks.

**23.4 Timing.** [Man `--server-poll-timeout`, `--connect-timeout`, `--connect-retry`,
`--connect-retry-max`, `--resolv-retry`] *Supported.*

- `--server-poll-timeout` (alias `--connect-timeout`) is the wait for a server's response before the
  next server. Its default is 120 s (17).
- `--connect-retry n [max]`: n is the wait between attempts (default 1 s). After 5 retries per
  remote, the wait doubles after each failed attempt, up to max (default 300 s).
- `--connect-retry-max n`: how many times each remote is tried (default unlimited). A successful
  connection resets the count.
- `--resolv-retry n|infinite`: a failed name lookup is retried for n seconds. The default is
  infinite, and 0 disables retrying. The page does not say how it combines with several remotes;
  burrow bounds each remote's retrying by its connect timeout, so later remotes are still tried.

**23.5 Values.** [Man `--mssfix`, `--comp-lzo`, `--remote-cert-tls`, `--nobind`] *Supported.*

- `--mssfix max [mtu|fixed]` agrees with 18.2.
- `--comp-lzo` takes `yes`, `no` or `adaptive`. A bare `comp-lzo` is not stated; burrow refuses it.
- `--remote-cert-tls server` requires the server's certificate to carry the server-authentication
  extended key usage (19).
- `--nobind` leaves the local port to the system, which is all burrow ever does.
