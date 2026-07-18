# Minimal Multicast QUIC (hackathon PoC)

A minimal, **unreliable** extension that lets a QUIC server send DATAGRAM data
to an IP multicast group, which multicast-capable clients receive as part of
their existing unicast QUIC connection.

The design goal is **the smallest possible delta** to an existing QUIC stack,
and **interoperability** across independent implementations (quic-go, quiche,
aioquic). Everything that is not strictly required to "put QUIC packets on a
multicast address and have a client decode them" is deliberately left out.

This hackathon builds upon **Flexicast QUIC**, distilling it into a minimal
proof of concept. For the full design, see the Flexicast QUIC IETF draft
([draft-navarre-quic-flexicast](https://datatracker.ietf.org/doc/draft-navarre-quic-flexicast/))
and the SIGCOMM CCR paper
(https://dl.acm.org/doi/pdf/10.1145/3750832.3750834). See Section 13 for the
full list of references.

## 1. Scope and non-goals

As a first step, this document focuses on a **single multicast flow** per
connection. Supporting multiple concurrent flows (e.g. the same content at
different bit-rates) is a straightforward extension but is intentionally left
out to keep the initial PoC minimal.

In scope:

- A server sends ordinary QUIC 1-RTT packets to an IP multicast (S,G) group.
- Those packets carry DATAGRAM frames (RFC 9221) only.
- A client, over its normal unicast QUIC connection, is told the group address,
  UDP port, a Flow ID, a cipher suite, and a secret; it joins the group and
  decodes the packets as if they had arrived over unicast.

Explicitly **out of scope** for this PoC:

- **No reliability**: no acknowledgements, no retransmission, no loss recovery
  for multicast data.
- **No Multipath QUIC.** The cleanest approach would be to rely on Multipath QUIC, as it solves numerous problems (e.g., unicast fallback and retransmission), but requires support of the extension in the underlying implementation. As such, this PoC does not use Multipath QUIC to increase the potential coverage of implementations. The multicast traffic is *not* an MP-QUIC path. It is
  an alternate packet input demultiplexed into the existing connection by DCID.
- **No flow control or congestion control** for the multicast traffic. The
  server sends at an application-chosen rate.
- **No integrity / source authentication** beyond AEAD with a shared key
  (see Section 11).
- **No key update / key rotation.** One secret per flow for its lifetime.
- **No join/leave/state signalling from the client.** The server does not track
  per-receiver flow membership.
- **No STREAM frames** on multicast (would pull in offset tracking and flow
  control).

## 2. Overview

```
   unicast QUIC connection (control + normal data)
   <------------------------------------------------>
Server                                            Client R1
  |  1. QUIC handshake (multicast_support TP)         |
  |  2. MC_FLOW (S,G, port, FlowID, suite,            |
  |             secret, first PN)  ---------------->  |  join (S,G):port
  |                                                   |  install flow keys
  |                                                   |
  |  3. 1-RTT packets, DCID = FlowID,                 |
  |     encrypted with flow keys, sent to (S,G) ===============>  (all Rn)
  |                                                   |  decode DATAGRAMs,
  |                                                   |  deliver to app
```

Key idea: the packets on the multicast wire are **normal QUIC 1-RTT short-header
packets**. The only differences from a unicast packet are (a) the Destination
Connection ID is a **Flow ID**, and (b) they are protected with a
**flow-specific key**. This lets the client reuse its existing
receive -> remove-header-protection -> decrypt -> parse-frames -> deliver pipeline
essentially unchanged.

The same Flow ID and secret are sent to **every** multicast-capable client,
so a single encrypted packet is decodable by all of them.

## 3. Transport parameter

A single transport parameter negotiates support:

- `multicast_support` (hackathon value `0xff4d40`): **zero-length**. Presence in
  a client's transport parameters indicates the client can receive multicast
  flows and process the `MC_FLOW` frame.

A server MUST NOT send `MC_FLOW` frames to a client that did not send
`multicast_support`. A client that did not send `multicast_support` MUST treat
receipt of an `MC_FLOW` frame as a connection error of type
`PROTOCOL_VIOLATION`.

*Note*: For the PoC, implementations may decide to skip the aforementioned treatment of protocol violation.

*Note*: For the PoC, only the client -> server direction matters, since the server is the
only sender of multicast data.

## 4. The MC_FLOW frame

`MC_FLOW` is sent **server -> client**, on the unicast connection, in a 1-RTT
packet. It combines "here is a flow" and "here is its key" into one frame,
which is possible because there is no reliability and no key rotation to
sequence. This is a difference with existing drafts.

```
MC_FLOW Frame {
  Type (i) = 0xff4d43,
  Flow ID Length (8),
  Flow ID (8..160),
  IP Version (8),
  Source IP (32 or 128),
  Group IP (32 or 128),
  UDP Port (16),
  Cipher Suite (16),
  First Packet Number (i),
  Secret Length (i),
  Secret (..),
}
```

Fields:

- **Flow ID Length**: length in bytes of the Flow ID. MUST be between 1
  and 20. A value of 0 or > 20 MUST be treated as `FRAME_ENCODING_ERROR`.
- **Flow ID**: the connection ID that appears as the DCID of packets on this
  flow. MUST NOT be zero-length. The client MUST NOT use this value as a
  connection ID for its unicast connection; if it is already in use, the client
  retires it first.

  *Note*: For this PoC, implementations may assume that the Flow ID always lies within the [1, 20] length, and that it is not already used by the client (low probability).
- **IP Version**: 4 or 6. Any other value is `FRAME_ENCODING_ERROR`. Selects the
  width of the two address fields (32 bits for IPv4, 128 bits for IPv6).
- **Source IP**: the multicast source address S (network byte order).
- **Group IP**: the multicast group address G (network byte order). MUST be a
  valid SSM destination address (RFC 4607).
- **UDP Port**: destination UDP port for the flow (network byte order).
- **Cipher Suite**: a TLS cipher suite code point (see Section 9). Determines the
  AEAD, the header-protection algorithm, and the hash used for key derivation.
- **First Packet Number**: the packet number the client should use as the
  initial "next expected" value for packet-number reconstruction, before it has
  decrypted any packet on the flow. This value is necessary to decrypt incoming packets if the client joins the flow later.
- **Secret / Secret Length**: the flow traffic secret from which packet
  protection keys are derived (Section 5). Its length is the hash length of the
  cipher suite.

`MC_FLOW` is ack-eliciting on the unicast connection and retransmitted using
normal QUIC loss recovery until acknowledged.

*Optional withdraw (not required for the PoC):* a server MAY signal flow
teardown by sending an `MC_FLOW` with `Secret Length = 0` for the same
Flow ID; on receipt the client leaves the group and drops flow state. If
omitted, the client simply leaves the group when the unicast connection closes.

## 5. Flow key derivation

The Secret plays exactly the role of a QUIC 1-RTT application traffic secret.
Keys are derived with the **unmodified** RFC 9001 procedure, using the hash and
AEAD of the cipher suite:

```
flow_key = HKDF-Expand-Label(Secret, "quic key", "", key_len)
flow_iv  = HKDF-Expand-Label(Secret, "quic iv",  "", iv_len)
flow_hp  = HKDF-Expand-Label(Secret, "quic hp",  "", hp_len)
```

Because this is identical to normal 1-RTT key derivation, an implementation can
call its **existing** "install 1-RTT keys from this secret" function, tagging the
result as the flow's key context. The server generates the Secret randomly
(hash-length bytes) once per flow.

## 6. Multicast packet format

Packets on the flow are standard 1-RTT short-header packets (RFC 9000
Section 17.3.1):

- Header Form = 0 (short header), Fixed Bit = 1.
- **Spin Bit = 0**; clients ignore it.
- **Key Phase = 0**, fixed (there is no key update).
- **Packet Number Length = 0b11 (4 bytes), fixed.** A one-to-many sender cannot
  choose a per-receiver packet-number length, so the length is always four bytes.

  *Note*: This choice is subject to discussion, if the `First Packet Number` field of the `MC_FLOW` is sufficient to recover the true packet number, as done in the implementations of Flexicast QUIC.

- Destination Connection ID = the **Flow ID**.
- Packet payload contains only `DATAGRAM` frames, optionally with `PADDING` /
  `PING`. No other frame types are sent on the flow; a client MUST ignore any
  other frame type received on the flow.

Packet protection (AEAD nonce = left-padded packet number XOR `flow_iv`) and
header protection use the flow key context and are otherwise unchanged from
RFC 9001. Since the flow has its own key and its own packet-number space,
nonce uniqueness holds without any Path ID or multipath construct.

**Packet number reconstruction:** the flow has its own packet-number space.
The client reconstructs full packet numbers (RFC 9000 Section 17.1) using the
largest packet number it has successfully decrypted on the flow as the basis;
before the first successful decrypt it uses `First Packet Number` from
`MC_FLOW`. The server sends flow packet numbers continuously starting from
`First Packet Number`.

## 7. Client processing

On receiving `MC_FLOW`:

1. Derive the flow key context (Section 5).
2. Open a UDP socket bound to the flow UDP port and **join the (S,G)**
   using the platform source-specific-multicast join
   (e.g. `MCAST_JOIN_SOURCE_GROUP` / `IP_ADD_SOURCE_MEMBERSHIP`).
3. Register the Flow ID so that incoming short-header packets whose DCID
   equals it are routed to this connection's flow key context and flow
   packet-number space.

On receiving a packet on the multicast socket: feed it into the normal QUIC
receive routine. Because its DCID is the Flow ID, it is decrypted with the
flow keys, its packet number is reconstructed in the flow space, and its
`DATAGRAM` frames are delivered to the application exactly like unicast
datagrams.

Two behaviours differ from a normal received packet:

- The client MUST NOT acknowledge flow packets (there is no return path and
  no reliability). The receive path for flow packets skips all
  ack-eliciting / ACK-generation bookkeeping.
- Flow packets MUST NOT reset the unicast connection's idle timer. Liveness
  is determined solely by the unicast connection.

When the unicast connection closes, the client leaves the (S,G) and discards
flow state.

## 8. Server processing

1. When a multicast-capable client's connection is established, send an
   `MC_FLOW` frame on its unicast connection describing the flow (the
   **same** Flow ID and Secret for all clients sharing the flow).
2. Maintain one flow context: the derived keys, `flow_iv`, and a single
   monotonic packet-number counter starting at `First Packet Number`.
3. To transmit application data, build a 1-RTT short-header packet with
   DCID = Flow ID and PN = counter++, place the data in `DATAGRAM` frame(s),
   protect it with the flow keys, and `sendto` the (S,G):port. One packet
   reaches all receivers.

The server keeps no per-receiver state for the flow and processes no feedback
for it.

## 9. Interop profile

To eliminate interop friction between quic-go, quiche, and aioquic, all
endpoints in the hackathon MUST use these exact choices:

- Transport parameter `multicast_support` = `0xff4d40` (zero-length).
- Frame type `MC_FLOW` = `0xff4d43`.
- Cipher suite = `TLS_AES_128_GCM_SHA256` (`0x1301`): 16-byte key, 12-byte IV,
  16-byte header-protection key, 32-byte secret. (The Cipher Suite field remains
  in the frame for generality, but only this value is exercised.)
- Fixed 4-byte packet number, Key Phase 0, on all flow packets.
- Payload is `DATAGRAM` frames only.
- IPv4 first; IPv6 optional if time allows.

These codepoints are arbitrary experimental values; their only requirement is
that every implementation uses the same ones.

## 10. What you reuse vs. what you add

Reused unchanged (no new code):

- TLS handshake and the whole unicast connection.
- Key derivation from a secret (fed the flow Secret).
- AEAD packet protection + header protection.
- Short-header packet parsing.
- `DATAGRAM` frame parsing and delivery to the application.

New code (the entire delta), per side:

Client:

1. Advertise / parse the `multicast_support` transport parameter.
2. Parse the `MC_FLOW` frame.
3. Open + source-join the multicast UDP socket.
4. Register Flow ID -> flow key context + flow PN space; derive keys via
   the existing routine.
5. Route packets with DCID = Flow ID to the flow context and suppress
   ACK/idle-timer bookkeeping for them.

Server:

1. Emit / parse the transport parameter.
2. Generate the flow secret, derive keys (existing routine), open the
   multicast socket.
3. Emit `MC_FLOW` on each capable client's unicast connection.
4. Send path: build, protect, and `sendto` flow packets with the flow
   DCID, keys, and PN counter.

## 11. Security considerations

This PoC intentionally provides no source authentication and no integrity
beyond AEAD with a shared key. Every receiver holds the same flow key, so
any receiver (or anyone given the key) can forge packets to the group that other
receivers will accept. There is no protection against a malicious group member
injecting data.

This is acceptable only for a controlled/lab hackathon environment. A real
deployment needs packet-level authentication independent of the shared key
(e.g. the `MC_INTEGRITY` mechanism of draft-jholland-quic-multicast and the
analysis in draft-krose-multicast-security). That machinery is deliberately
excluded here to keep the change minimal.

## 12. Interoperability testing

TODO: we will provide a way for participants to test their implementation, and to perform interoperability testing.

## 13. References

This PoC distills ideas from ongoing work on multicast QUIC. For background and
reference implementations:

- **Flexicast QUIC IETF draft** (draft-navarre-quic-flexicast):
  https://datatracker.ietf.org/doc/draft-navarre-quic-flexicast/
- **Flexicast QUIC implementation** (quiche fork):
  https://github.com/IPNetworkingLab/flexicast-quic
- **Flexicast QUIC paper** (ACM SIGCOMM CCR):
  https://dl.acm.org/doi/pdf/10.1145/3750832.3750834
- **Multicast QUIC IETF draft** (draft-jholland-quic-multicast):
  https://datatracker.ietf.org/doc/draft-jholland-quic-multicast/
