# PFUI_Firewall (Rust)

A Rust implementation of the PFUI server, intended as a drop-in replacement
for the Python daemon on the firewall itself: same `/etc/pfui_firewall.yml`,
same Redis schema, same reply strings, same rc.d service name, binary at
`/usr/local/sbin/pfui_firewall`.

## Status

Complete and validated on OpenBSD 7.9: TCP, UNIX and UDP listeners, bounded
worker pool, the full receiver decision tree with the frozen reply
vocabulary, PF tables via ioctl or pfctl, Redis, persist files, the
scan/sync expiry loop, the rc.d script, unveil, and the installer
(`../install-server-rust.sh`).

The validation covered the parts no container can reach: the struct layouts
and all three ioctl numbers match `net/pfvar.h` exactly, the table ioctls
were exercised against a live kernel, the rc.d lifecycle behaves (including
`reload` refusing), and a real resolver's answers reached the PF tables,
Redis and the persist files on a firewall carrying live traffic.

pledge(2) is not enabled yet; it comes only after that pass has been repeated
with it on (see DECISIONS.md).

- `src/wire.rs` — the length-prefixed frame and bounded lz4/JSON decode from
  [../protocol/PROTOCOL.md](../protocol/PROTOCOL.md)
- `src/validate.rs` — globally-routable-unicast whitelist, canonicalised
- `src/store.rs` — Redis expiry store, schema-compatible with server-python
- `src/persist.rs` — persist files under the same flock discipline
- `src/pf/` — pfr_table/pfioc_table/pfr_addr layouts, `DIOCRADDADDRS`/
  `DIOCRDELADDRS`/`DIOCRGETADDRS` (the last is new; server-python shells out
  to `pfctl -T show` instead), and the pfctl fallback
- `src/config.rs` — same yml, same keys, coercive like the Python loader
- `src/listener.rs` — accept loops, shed-beyond-2×MAX_WORKERS pool, the
  fail-closed unix bind path
- `src/receiver.rs` — PF → ACKUPDATE → Redis → persist ordering
- `src/sync.rs` — per-AF expiry loop, PF-before-Redis read order
- `src/main.rs` — foreground daemon (`-f config`, `-n` check, `-d` stderr)

Both shared vector suites run here — `../protocol/vectors/framing.tsv` (also
run by `server-c` and `protocol/python`) and `../protocol/vectors/messages.json`
(also run by `protocol/python`) — plus a checked-in python-lz4-produced frame,
so the implementations cannot drift apart unnoticed.

## Build and test

Rust 1.94 (the rustc in OpenBSD-stable ports; `rust-version` in Cargo.toml).

```
cargo test
cargo build --release --locked
```

The PF ioctl code, once it exists, is `#[cfg(target_os = "openbsd")]`;
everything else builds and tests on any platform.

## End-to-end test

```
./tests/e2e/run.sh
```

Builds the client container (Unbound from source with the Python module),
this daemon, and runs the real resolver against the real daemon over both
transports at once — live lz4 between python-lz4 and lz4_flex, real Redis,
a stateful pfctl stub for the tables. Verifies the rr and cache paths, the
merged-hash relabelling, multi-record and AAAA answers, sync-loop stability
and clean shutdown.

## Still to do

- pledge(2), enabled only after the OpenBSD pass above is repeated with it on
  (see DECISIONS.md for the sequencing rationale)

## Release builds

OpenBSD amd64 is a Rust tier-3 target with no rustup std, so release
binaries are built natively on an OpenBSD host with the ports rustc:

```
pkg_add rust
cargo build --release --locked
```

`--locked` enforces the committed Cargo.lock; `rust-version` in Cargo.toml
is the ports rustc of the current -stable release, so the ports toolchain is
never too old by construction. A firewall that should not carry a toolchain
installs the artifact instead of building:

```
PFUI_BINARY=/path/to/pfui_firewall doas ../install-server-rust.sh
```

`../server-python/` remains the reference for all of the above, and
`../protocol/PROTOCOL.md` is normative where the two disagree.
