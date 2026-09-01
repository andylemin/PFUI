# PFUI wire protocol

Normative description of what a PFUI client sends to a PFUI server. Any client
(`client-unbound/`, or a future client for another resolver) and any server
(`server-python/`, `server-c/`) must agree with this document, and both are
tested against the shared vectors in `vectors/`.

Version: 2 (`qname` moved from each record to the message). There is no version
field on the wire; see
[Compatibility](#compatibility).

## Transport

| Transport | Use |
|-----------|-----|
| TCP | The supported transport between hosts. |
| Unix domain stream socket | A client and server on the same host. |
| UDP | Lab use only, and disabled unless the server sets `ALLOW_INSECURE_UDP`, because a datagram source address is not verified and the protocol has no authentication. |

A server MAY serve more than one transport at once, and `server-python` does: a
firewall can accept messages from a resolver on the same host over a local socket
while accepting them from a remote resolver over TCP. Nothing in the message or
the framing distinguishes them.

The unix socket is a `SOCK_STREAM` socket carrying **exactly the framing and the
replies TCP does**, so an implementation that speaks TCP needs no message-level
change to speak it. It is the better choice on one host: there is no handshake,
no `TIME_WAIT` entry per message, and no ephemeral-port ceiling, all of which
matter because a client opens one connection per DNS answer (see DECISIONS.md).

No transport is authenticated or encrypted. An IP must reach a PF table
microseconds before the client connects to it, and a handshake would spend that
budget. Access control is therefore delegated:

- TCP and UDP: the packet filter's job. Restrict the server's listening port to
  the known resolvers.
- Unix socket: the filesystem's job. There is no packet to filter, so the socket's
  ownership and mode are the whole control. A server MUST NOT create it
  world-writable, and `server-python` binds it `0660` to a configured group, under
  a directory only that group may traverse. A client that cannot connect with
  `EACCES` is not in that group.

Because the two are enforced in different places, a server that serves both is
only as restricted as the weaker of them.

## Framing

A TCP message is exactly one frame:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        length (uint32, BE)                    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        payload (length bytes)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- `length` is the payload byte count, big-endian (network byte order), not
  including the 4 header bytes.
- A receiver MUST read exactly 4 bytes, then exactly `length` bytes.
- A receiver MUST reject `length == 0` and `length > MAX_MESSAGE`
  (1048576, 1 MiB) **before** buffering any payload, and MUST close the
  connection.
- A receiver MUST NOT scan the payload for a terminator. The payload is
  arbitrary binary and may contain any byte sequence, including the `EOT` that
  earlier releases used as a footer.
- Nothing follows the payload. One connection carries one frame.
- If the peer closes before a complete 4-byte header arrives, there is no
  message. That is not a protocol error: the receiver closes the connection and
  carries on. A payload that stops short of `length`, by contrast, IS an error,
  because the sender declared bytes it did not send.

UDP datagrams are self-delimiting and carry the payload **alone**, with no
length prefix.

UDP therefore has a message-size ceiling that TCP does not. A datagram above the
link MTU fragments and PF commonly drops fragments, so a server MUST NOT be
expected to receive a large message over UDP however big its receive buffer is.
`server-python` caps datagrams at 1400 bytes and logs a rejection above that
rather than handing truncated bytes to the decoder. Note that the ceiling applies
to the *encoded message*, not the DNS answer it came from: `qname` appears once
per message but the JSON overhead is real, so an uncompressed message reaches
1400 bytes at roughly 20 address records. Use TCP for anything but a lab.

## Payload

The payload is UTF-8 JSON, optionally compressed with lz4 frame format. Whether
compression is in use is configuration on both sides (`COMPRESS`), not signalled
on the wire: a mismatch is a misconfiguration and shows up as a decode failure.

A receiver MUST bound decompression to `MAX_MESSAGE` and abort while expanding,
not after: a small frame can otherwise expand to gigabytes before any size check
runs.

### Message object

```json
{
  "kind": "rr",
  "qname": "example.com.",
  "AF4": [{"ip": "8.8.8.8", "ttl": 3600}],
  "AF6": [{"ip": "2001:4860:4860::8888", "ttl": 3600}]
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `kind` | `"rr"` or `"cache"` | How to read every `ttl` in this message. Required. |
| `qname` | string | The query name every record in this message answers. Optional; `""` if unknown. |
| `AF4` | array | IPv4 records. May be empty or absent. |
| `AF6` | array | IPv6 records. May be empty or absent. |
| `AF*[].ip` | string | Address in presentation form. |
| `AF*[].ttl` | integer | See `kind`. `0` is valid and means do-not-cache. |

`qname` is a property of the message, not of each address: one message carries
one reply, and every address in it answers the same query.

**One message per reply, sent immediately.** A client MUST send the message as
soon as it has the reply's records, and MUST NOT wait for further replies, batch
messages, or hold records back for any reason. The whole design depends on the
addresses reaching the PF table in the microseconds before the client connects
to them, so any buffering trades away the property PFUI exists to provide. A
client MUST NOT put records for more than one query name in one message, which
is what makes a single message-level `qname` correct rather than merely
convenient.

Several addresses in one message therefore means one DNS reply that carried
several records, never an accumulation across replies. Repeating it per
record cost roughly half the uncompressed payload for a 24-address answer (2021
bytes against 940). Compression hid almost all of that on the wire — 262 bytes
against 261 — so the saving is mostly in what an uncompressed deployment sends
and in not implying the fields can differ.

`kind` is what removes the guesswork that used to come from TTL magnitude:

- `"rr"` — `ttl` is a **relative** DNS TTL in seconds, read from a fresh
  resolution. The server expires the entry at
  `received_at + ttl * TTL_MULTIPLIER`.
- `"cache"` — `ttl` is an **absolute** unix timestamp, because the resolver
  reported a cache entry's expiry rather than a countdown. The server expires
  the entry when that timestamp passes.

A server MUST reject a message with a missing or unrecognised `kind` rather than
infer one. A server MUST accept a message whose `AF4`/`AF6` are both empty only
by rejecting it as having nothing to act on.

### Server obligations for records

A server MUST NOT install a non-global address. Sentinels (`0.0.0.0`, `::` and
every other spelling of them), private, loopback, link-local, CGNAT, ULA,
IPv4-mapped and multicast addresses MUST be dropped: a DNS answer pointing
inside the network must not authorise egress. A server SHOULD canonicalise
addresses before use, so its own state and `pfctl -T show` cannot disagree about
IPv6 spelling.

## Replies

| Reply | Meaning |
|-------|---------|
| `ACKDATA` | UDP only. The datagram decoded to a valid message. Sent **after** validation, never on receipt. |
| (silence) | UDP only. A refused datagram gets no reply at all, since its source address is unverified and a reply would make the server a reflector. |
| `ACKUPDATE` | The PF tables have been updated. The client may release the DNS answer. |
| any other | Refusal, with a short human-readable reason (`Missing kind`, `Bad frame`, `Bad length`, `Truncated`, `Failed to decode`, `Invalid datatype`, `No records`, `Empty payload`, `Socket timeout`). |

`Bad length` and `Truncated` are separate reasons because they are separate
faults: the first is a prefix a receiver refuses before buffering anything, the
second is a sender that declared bytes it did not send. `Invalid datatype` is a
payload that decoded to something other than a message object; `No records` is a
well-formed message with no routable address left after validation.

A client SHOULD treat anything other than `ACKUPDATE` as a failed update and log
the reason, which is what a version skew looks like from the client side.

## Compatibility

There is no version negotiation. The framing change from the `EOT` footer, and
the addition of `kind`, are both breaking: a mismatched pair fails closed in
either direction, so client and server must be deployed from the same release.

If a future change needs negotiation, add a field to the JSON payload rather
than the frame header; the framing layer is deliberately dumb.

## Conformance vectors

`vectors/framing.tsv` is language-neutral and covers the framing layer only, so
an implementation that has no JSON parser yet can still be checked. Columns:

| Column | Meaning |
|--------|---------|
| `name` | Identifier for the case |
| `frame_hex` | Bytes on the wire, hex |
| `expect` | `ok`, `short`, or a rejection reason (`length`, `truncated`) |
| `payload_hex` | Expected payload for `ok`, else `-` |

Fields are tab-separated and never empty: `-` stands for empty or not
applicable, so a reader that collapses runs of whitespace cannot silently shift
columns.

`vectors/messages.json` covers the payload layer: each entry has the decoded
message and, where the encoding is byte-stable, the exact frame. Compressed
frames are round-trip only, because lz4 output is not guaranteed identical
across library versions.
