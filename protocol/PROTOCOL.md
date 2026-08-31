# PFUI wire protocol

Normative description of what a PFUI client sends to a PFUI server. Any client
(`client-unbound/`, or a future client for another resolver) and any server
(`server-python/`, `server-c/`) must agree with this document, and both are
tested against the shared vectors in `vectors/`.

Version: 1. There is no version field on the wire; see
[Compatibility](#compatibility).

## Transport

TCP is the supported transport. UDP exists for lab use and is disabled unless
the server sets `ALLOW_INSECURE_UDP`, because a datagram source address is not
verified and the protocol has no authentication.

Neither transport is authenticated or encrypted. An IP must reach a PF table
microseconds before the client connects to it, and a handshake would spend that
budget. Access control is therefore the packet filter's job: restrict the
server's listening port to the known resolvers.

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
  "AF4": [{"ip": "8.8.8.8",             "ttl": 3600, "qname": "example.com."}],
  "AF6": [{"ip": "2001:4860:4860::8888", "ttl": 3600, "qname": "example.com."}]
}
```

| Field | Type | Meaning |
|-------|------|---------|
| `kind` | `"rr"` or `"cache"` | How to read every `ttl` in this message. Required. |
| `AF4` | array | IPv4 records. May be empty or absent. |
| `AF6` | array | IPv6 records. May be empty or absent. |
| `AF*[].ip` | string | Address in presentation form. |
| `AF*[].ttl` | integer | See `kind`. `0` is valid and means do-not-cache. |
| `AF*[].qname` | string | Query name, for logging. Optional. |

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
| any other | Refusal, with a short human-readable reason (`Missing kind`, `Bad frame`, `Bad length`, `Truncated`, `Failed to decode`, `Invalid datatype`, `Empty payload`, `Socket timeout`). |

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
