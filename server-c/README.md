# PFUI_Firewall (C)

A C implementation of the PFUI server, intended to replace the Python daemon on
the firewall itself. The Python version wraps the PF ioctl structures through
ctypes, so the kernel interface is the part that most wants to be C.

## Status

Framing only. `src/pfui_wire.c` implements the length-prefixed frame described in
[../protocol/PROTOCOL.md](../protocol/PROTOCOL.md), and nothing else exists yet:
no listener, no JSON parsing, no Redis, no PF ioctl.

It is here now so the protocol spec has a second implementation checking it. The
framing vectors in `../protocol/vectors/framing.tsv` are run by both this suite
and the Python one, so the two cannot drift apart unnoticed.

## Build and test

```
make test
```

Requires only a C99 compiler. The test binary takes the vector file as its first
argument, defaulting to the shared copy.

## Still to write

Roughly in dependency order:

- JSON payload parsing, and lz4 decompression bounded to `PFUI_MAX_MESSAGE`
- address validation (globally routable unicast only, canonicalised)
- PF table ioctl: `DIOCRADDADDRS`, `DIOCRDELADDRS`, and `DIOCRGETADDRS`, which
  the Python server never implemented and currently shells out to `pfctl` for
- expiry state, whether in Redis or in-process
- persist-file writer with the same locking discipline as the Python version
- listener with bounded concurrency, privilege drop, and an rc.d script

`../server-python/` remains the reference for all of the above, and
`../protocol/PROTOCOL.md` is normative where the two disagree.
