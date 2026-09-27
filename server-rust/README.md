# PFUI_Firewall (Rust)

A Rust implementation of the PFUI server, intended as a drop-in replacement
for the Python daemon on the firewall itself: same `/etc/pfui_firewall.yml`,
same Redis schema, same reply strings, same rc.d service name, binary at
`/usr/local/sbin/pfui_firewall`.

## Status

In production on OpenBSD 7.9: TCP, UNIX and UDP listeners, bounded worker
pool, the full receiver decision tree with the frozen reply vocabulary, PF
tables via ioctl or pfctl, Redis, persist files, the scan/sync expiry loop,
the rc.d script, unveil and pledge, and the installer
(`../install-server-rust.sh`).

`CTL` chooses one control path and the daemon never falls back to the other.
`IOCTL` drives `/dev/pf` directly and forks nothing; `PFCTL` runs `pfctl(8)`.
At startup the daemon reads both tables through the chosen path and refuses
to serve if it cannot, naming the cause and the remedy, so a broken path is a
failed `rcctl start` rather than a daemon quietly running slow (DECISIONS.md,
"CTL: IOCTL is the ioctl and nothing else").

The sandbox follows `CTL`. The `pf` pledge promise does not permit the
table-address ioctls, so under `IOCTL` they run in a PF child forked before
the parent pledges: the child alone holds `/dev/pf` and answers one ioctl per
request over a socketpair, and the parent's pledge is `stdio rpath wpath cpath
flock fattr inet`, plus `unix` with a local socket. Under `PFCTL` there is no
child; the pledge gains `proc exec` and `/dev/pf` and the pfctl paths are
unveiled. `PLEDGE: False` is an emergency switch and is logged on every start
(DECISIONS.md, "The sandbox follows CTL").

Exit codes: 2 config, 3 Redis client, 4 sync thread, 5 UDP gate, 6 bind or
sandbox, 7 PF control path unusable or PF child not started.

- `src/wire.rs` — the length-prefixed frame and bounded lz4/JSON decode from
  [../protocol/PROTOCOL.md](../protocol/PROTOCOL.md)
- `src/validate.rs` — globally-routable-unicast whitelist, canonicalised
- `src/store.rs` — Redis expiry store, schema-compatible with server-python
- `src/persist.rs` — persist files under the same flock discipline
- `src/pf/` — pfr_table/pfioc_table/pfr_addr layouts, `DIOCRADDADDRS`/
  `DIOCRDELADDRS`/`DIOCRGETADDRS` (the last is new; server-python shells out
  to `pfctl -T show` instead), the PF child that issues them, the pfctl path,
  and the startup probe
- `src/platform.rs` — the unveil plan and the pledge promises as data,
  tested everywhere; the two system calls behind them on OpenBSD
- `src/config.rs` — same yml, same keys, coercive like the Python loader
- `src/listener.rs` — accept loops, shed-beyond-2×MAX_WORKERS pool, the
  fail-closed unix bind path
- `src/receiver.rs` — PF → ACKUPDATE → Redis → persist ordering
- `src/sync.rs` — per-AF expiry loop, PF-before-Redis read order
- `src/main.rs` — foreground daemon (`-f config`, `-n` check, `-d` stderr)

Both shared vector suites run here — `../protocol/vectors/framing.tsv` (also
run by `protocol/python`) and `../protocol/vectors/messages.json`
(also run by `protocol/python`) — plus a checked-in python-lz4-produced frame,
so the implementations cannot drift apart unnoticed.

## Build and test

Rust 1.94 (the rustc OpenBSD-stable packages; `rust-version` in Cargo.toml).

```
cargo test
cargo build --release --locked
```

The PF ioctl, unveil and pledge calls are `#[cfg(target_os = "openbsd")]`;
everything else, including the unveil plan and promise set, builds and tests
on any platform. The OpenBSD job below is what compiles and runs the rest.

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

## OpenBSD in CI

`.github/workflows/openbsd.yml` runs `../tests/openbsd/run.sh` inside a real
OpenBSD VM on every relevant change. It runs both installers
unattended, loads a tables-only pf.conf, runs this crate's tests on the
target (including the live ioctl suite against the real tables), then sends
live answers from the resolver it installed to the daemon it installed over
TCP, the unix socket and both at once, under `IOCTL` and `PFCTL`, and checks
each answer in the PF table, Redis and the persist file. Further passes prove
expiry, that a `pfctl -f` reload repopulates the table from the persist file,
that stop leaves no socket behind, and that a table missing from the ruleset
is refused loudly at start. The same script runs by hand as root on a scratch
OpenBSD machine; it rewrites `/etc/pf.conf` and both PFUI configurations.

## Still to do

- Per-transport `COMPRESS`, so a local socket can run uncompressed while a
  remote resolver over TCP compresses
- Authentication of the TCP transport, which today relies on pf.conf alone

## Release builds

OpenBSD amd64 is a Rust tier-3 target with no rustup std, so release
binaries are built natively on an OpenBSD host with the packaged rustc:

```
pkg_add rust
cargo build --release --locked
```

`--locked` enforces the committed Cargo.lock; `rust-version` in Cargo.toml
is the rustc the current -stable release packages, so the packaged toolchain
is never too old by construction. A firewall that should not carry a toolchain
installs the artifact instead of building:

```
PFUI_BINARY=/path/to/pfui_firewall doas ../install-server-rust.sh
```

`../server-python/` remains the reference for all of the above, and
`../protocol/PROTOCOL.md` is normative where the two disagree.
