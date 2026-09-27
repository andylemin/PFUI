# PFUI protocol

What every PFUI client and server must agree on.

- [PROTOCOL.md](PROTOCOL.md) — the normative specification
- `vectors/framing.tsv` — framing conformance vectors, language-neutral
- `vectors/messages.json` — payload conformance vectors
- `python/pfui_wire.py` — reference implementation, used by both
  `client-unbound/` and `server-python/`

Only code that both a client and a server need lives here. Server-only logic
(expiry, address validation, PF ioctl) belongs to the server.

Both implementations run `vectors/framing.tsv`:

```
python -m pytest protocol/python/tests
cargo test --manifest-path server-rust/Cargo.toml
```

A change to the framing or the message object means changing PROTOCOL.md, the
vectors, and every implementation together.
