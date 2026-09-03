# PFUI Design Decisions

Decisions that are not obvious from the code, and the deferrals that were taken
knowingly rather than missed.

## Privilege model

`_pfui_firewall` holds a dedicated group with read/write on `/dev/pf`, rather
than `wheel`. This narrows *account* privilege — `wheel` also grants `su` — but
not PF capability: group write on `/dev/pf` still exposes the whole PF ioctl
surface, so a compromised daemon can rewrite rules. The stronger alternative,
keeping root for the ioctl and dropping privileges after bind, was rejected for
now as a larger change to the daemon's startup path.

`/dev/pf`'s group and mode are re-applied by `rc_pre` on every service start.
On OpenBSD `/dev` is a static on-disk directory, so the mode persists across
reboots; what resets it is `MAKEDEV` during a release upgrade.

## RR TTLs are stored exactly as sent

`db_push` records the TTL the client reported, with no floor. An earlier
`max(ttl, 3600)` contradicted the expiry rule in `PROTOCOL.md`, and with the
shipped `TTL_MULTIPLIER: 4` it turned a 60 second answer into four hours of
authorised egress. It also raised the `ttl` of 0 that means do-not-cache, which
`validate.extract` deliberately preserves.

`TTL_MULTIPLIER` is the only knob for holding entries longer than the record
says, which is the right place for it: the operator sets it knowing why (browsers
caching past the TTL), rather than inheriting a hidden minimum. The Redis
`EXPIRE` written alongside each key stays a backstop for the scan loop and is
floored at one second, because Redis reads `EXPIRE 0` as "delete now".

## Unbound is built from a release tag, resolved at install time

`install-client-unbound.sh` asks NLnet Labs for its newest `release-*` tag rather
than carrying a version. Three things follow from that choice:

Tags, not branches. The `branch-<version>` heads are pruned upstream (nothing
before 1.23 survives), so a version named in the script goes stale and then
vanishes. Release tags are permanent.

`git ls-remote`, not the GitHub releases API. It needs no token, has no rate
limit, and uses the git the installer already requires. The API would also depend
on a release being marked "latest" by hand.

Git, not the signed release tarball. The tarball is PGP-signed, which the clone
is not, and that is a real gap. It stays a clone because the OpenBSD build needs
`Makefile.bsd-wrapper` dropped into a source tree, and because `configure` is
committed upstream so no autoreconf is needed. Verifying the source is worth
doing and is not done here.

## The Unbound build is tested in a Linux container

`client-unbound/tests/container/` builds Unbound with `--with-pythonmodule` and
runs PFUI_Unbound inside it, on Debian. It cannot prove the OpenBSD build, and it
is not trying to: what it protects is the pythonmod interface. No distribution
ships Unbound with the Python module, so PFUI is the only consumer of that build,
and an upstream API change used to surface as an operator's install failing.

Two things it caught immediately, both of which the OpenBSD installer gets from
base and would not have revealed: building from the git tree needs flex and
bison, and `configure --with-pythonmodule` looks for `python`, not `python3`.

It also settles what the TTL labelling in `read_rr` rests on: against 1.26.0 and
against `master`, the reply path reports a relative TTL and the cache path an
absolute unix timestamp, so `kind` means what `PROTOCOL.md` says it means. That
was previously an assumption.

Unbound really runs as `_unbound` in the container, and the local socket really is
`0660 :_pfui` under a `0750` directory, so the container also exercises the group
model that permits a same-host deployment rather than just the code paths.

Known and benign: on shutdown the resolver logs `pythonmod: Exception occurred in
function deinit` / `TypeError: 'NoneType' object cannot be interpreted as an
integer`. It is not PFUI's — it persists with `deinit`'s body reduced to
`return True`, so nothing PFUI executes can be setting it, and it happens after
`service stopped`. The container prints any resolver `error:` line even when every
check passes, which is how this was noticed; it is recorded here so it is not
re-investigated.

## UDP has a message-size ceiling

`UDP_DGRAM_CEILING` (1400 bytes) bounds a PFUI message over UDP. This is not a
buffer that wants raising: a datagram above the link MTU fragments and PF
commonly drops fragments, so UDP cannot carry the large answers TCP handles. A
message above the ceiling is logged and dropped rather than truncated silently.
Accepted because UDP is lab-only and gated behind `ALLOW_INSECURE_UDP`; the fix
for a real deployment is TCP.

## A local socket for a same-host deployment

When PFUI_Unbound runs on the firewall itself, `SOCKET_UNIX` on the server and a
`SOCKET:` entry on the client replace loopback TCP. That is not a micro-
optimisation: the client opens one connection per DNS answer (see below), so
loopback TCP costs a handshake, a `TIME_WAIT` entry on the firewall and a slice of
the ephemeral port range for every reply. A unix socket has none of those.

Both listeners can run at once, and a CARP node with its own resolver wants
exactly that: the firewall on this box over the socket, the peer over TCP. That is
also why the transport is chosen **per `FIREWALLS` entry** on the client rather
than by one global `SOCKET_PROTO` — one resolver genuinely needs both at the same
time. `SOCKET_PROTO` now describes only the network entries.

The server binds one accept loop per listener, in a thread each, rather than
polling them together. Each loop already blocks only for `SOCKET_TIMEOUT` before
re-checking for `SIGTERM`, and the worker pool, the slot semaphore and the shed
path are shared and thread-safe, so this leaves each accept path as it was.

### The filesystem is the access control

There is no packet on this transport, so the `pf.conf` source restriction does not
apply and cannot. The socket's own ownership and mode are the whole control on who
may inject PF whitelist entries, which is a meaningfully different security model
from the network listener's, in a different place, enforced by a different
subsystem. A server serving both is only as restricted as the weaker one.

`_pfui` is a dedicated group holding `_pfui_firewall` and `_unbound`, rather than
reusing either account's own group. Membership means "may authorise egress", and
that should not be implied by merely running as the resolver, or be acquired by
anything later added to `_unbound`'s group for an unrelated reason.

The bind path fails closed throughout, because every one of these leaves the
socket reachable by more than intended:

- `bind()` creates the node with the process umask, so the umask is narrowed
  around it rather than the mode being fixed by a `chmod` afterwards. Otherwise
  the socket is connectable by everyone for the moment in between.
- A missing `SOCKET_UNIX_GROUP`, or a `chown`/`chmod` that does not take, exits
  the daemon and unlinks the socket instead of serving on it.
- A world-writable parent directory is refused unless it is sticky: anyone could
  otherwise replace the socket and be handed the resolver's messages, whatever
  mode the socket itself has. The parent is `0750 _pfui_firewall:_pfui`, so it is
  a second gate in front of the socket.
- A socket file left by an unclean stop is removed, but only after a probe
  connect shows nothing is listening. Unlinking a live daemon's socket would
  leave it running and unreachable.

`SOCKET_UNIX` is length-checked at config load because `sockaddr_un.sun_path` is
104 bytes on OpenBSD; without it the failure is an `AF_UNIX path too long` from
`bind()` rather than a named configuration error.

### EPIPE is visible here where TCP hid it

A cache report is sent with `blocking=False`, so the client has closed by the time
the server writes `ACKUPDATE`. Loopback TCP absorbs that write into a buffer
nobody reads; a unix socket reports `EPIPE` at once. The tolerance in
`disconnect()` was already there and is now load-bearing on this transport, and
there is a test for it. Nothing is lost: the addresses are installed before the
acknowledgement is attempted.

## Unauthenticated transport

Neither the TCP nor the UDP transport authenticates or encrypts. IPs must reach
a PF table microseconds before the client connects, and a handshake would spend
that budget. The only control on who may inject whitelist entries is therefore
the PF source restriction in `pf.conf` (`from <PFUI_Unbound> to self port
{ SOCKET_PORT }`). UDP additionally refuses to start unless
`ALLOW_INSECURE_UDP` is set, because a datagram source address is trivially
spoofed.

## `pfctl -T show` per scan

`sync_pf_table` shells out to `pfctl` once per `SCAN_PERIOD` to read the current
table. It is not on the per-query hot path, so the subprocess cost is accepted.
Replacing it needs a `DIOCRGETADDRS` implementation, which belongs with the
other ioctl structs; deferred, not forgotten. The Rust daemon closes this
deferral: under `CTL: IOCTL` it reads the table with `DIOCRGETADDRS`, and the
subprocess survives only as the `CTL: PFCTL` path and the ioctl-error fallback.

## No live configuration reload

`rcctl reload pfui_firewall` refuses and returns non-zero. It previously mapped
to a full stop/start, which is not a reload, and simply deleting the override
would be worse: rc.subr's default sends `SIGHUP`, the daemon installs no
handler, and Python's default disposition would terminate it.

A real reload would re-read only the safely re-readable keys (`LOGGING`,
`LOG_LEVEL`, `SCAN_PERIOD`, `TTL_MULTIPLIER`) and reject socket, Redis and table
changes as restart-only. Deferred: a restart costs a few seconds of fail-closed
control plane, so the concurrency cost of swapping config under running threads
is not yet justified.

## One TCP connection per DNS answer

The client connects, sends, reads the acknowledgement and closes, for every
answer. This is the dominant latency cost: the handshake means roughly 2 RTT to
deliver a message and get a reply, where a held-open connection would need 1. It
also puts a TIME_WAIT socket on the *firewall* for each query, since the server
replies and closes first, and it caps throughput on ephemeral port reuse.

It stays this way because an Unbound pythonmod plugin cannot hold a connection:
it is called per query inside the resolver, with no process of its own to own a
socket across queries. Fixing it properly means a separate client daemon holding
a persistent connection to each firewall, with the plugin handing messages to it
over local IPC. That is a new component, not a change to this one, and it is not
scheduled.

What was done instead is to remove the costs that are avoidable without it:
TCP_NODELAY on both ends, no pointless SO_SNDBUF clamping, and an accept queue
deep enough that a burst does not turn into a SYN retransmit.

Parallelising the sends to multiple firewalls is still open, and marked with a
TODO in transmit_all. With BLOCKING, a healthy CARP pair doubles the block time.
Whether a thread per firewall per query is cheaper than the serial round trips
needs measuring rather than assuming.

## Nothing is buffered on the send path

A reply is encoded and transmitted as soon as the resolver hands it over: one
reply, one message, no batching, no queue, no coalescing of records across
queries. `read_rr` reads the rrsets Unbound has already produced and
`transmit_all` runs on the next line. Several addresses in one message means one
reply carried several records.

This is a constraint rather than an implementation detail, so PROTOCOL.md states
it normatively. An optimisation that batched messages would look like a
bandwidth win and would break the guarantee the whole design rests on: the
address must be in the PF table before the client connects.

The one place work can wait is the server's receiver pool, which is bounded at
twice MAX_WORKERS and sheds beyond that rather than queueing without limit. It
delays a message that has already arrived; it never delays sending one.

## Persist files are append-only on the hot path

`file_push` appends without reading the file, because it runs per DNS answer
with every receiver thread serialised on one lock. Duplicate lines are harmless
— PF loads a table as a set — and `sync_pf_file`'s set-based rewrite collapses
them once per `SCAN_PERIOD`.

## Wire format compatibility

The wire format carries a 4-byte big-endian length prefix and an explicit
message `kind`. It is deliberately not backward compatible with releases that
used the `EOT` footer: both daemons must be deployed from the same commit. A
mismatched pair fails closed in either direction.

## Unbound runs unchrooted

`chroot: ""` in the shipped resolver config. `client-unbound/pfui_unbound.py` imports `lz4` and
`yaml` at module load, and those would have to exist inside the chroot. Revisit
only alongside a plan for the module's dependencies.

## The second full server is Rust, not C

`server-rust/` is a drop-in replacement for the Python daemon: same config
file, same Redis schema, same reply strings, same rc.d service name, same
binary path. C's only real edge was zero-package builds from base clang;
Rust buys memory safety on the one component that parses unauthenticated
network input and writes PF tables, serde for the config and payloads, a
test framework that carried the whole Python suite across, and cheap
`unveil(2)`/`pledge(2)`. `server-c/` stays as the framing cross-check; its
retirement is a separate decision, taken only after the Rust daemon passes
the same vectors in production use.

The daemon is plain threads, no async runtime: the Python design (an accept
thread per listener plus a bounded worker pool shedding beyond twice
MAX_WORKERS) maps onto std threads exactly, and an async runtime on a Rust
tier-3 target buys risk for nothing this daemon does.

## The Rust daemon keeps Redis

An in-process expiry store would drop the Redis dependency but change
crash-recovery semantics: today a restarted daemon inherits the whitelist
Redis kept, and the persist files only cover PF reloads, not expiry state.
Parity first; an in-process store is its own decision if ever taken.

## The Rust daemon runs foreground under rc_bg

No fork, no pidfile: rc.d backgrounds it (`rc_bg=YES`) and rc.subr's
pexp/pgrep model owns check/stop. This replaces the Python setup's
pidfile/verb model (its rc.d routes start/stop/check through the daemon's
own verbs) and deletes the third-party daemonisation dependency rather than
porting it. `rcctl reload` still refuses: the daemon ignores SIGHUP, so a
reload would silently do nothing.

## Routability is an explicit prefix table

The Rust validator rejects by a fixed RFC 6890-derived prefix list rather
than a stdlib `is_global()`: Rust's is nightly-only, and CPython's own
answer has shifted across versions (CVE-2024-4032). Parity with the Python
daemon is one-directional — everything Python rejects is rejected, and a few
rows reject more (the registry carve-outs inside 192.0.0/24 and 2001::/23,
plus 192.88.99/24, 64:ff9b::/96, fec0::/10 and ::/96), which only refuses
extra egress. Accepting anything Python rejected is a bug, and the test
suite pins a reject/accept pair on every table row.

## Addresses are canonicalised everywhere

Redis keys, PF pushes and table reads must agree on IPv6 spelling: before
canonicalisation existed, `sync_pf_table` deleted and re-added the same
IPv6 address forever, because the stored key and `pfctl -T show` spelled it
differently. Both daemons canonicalise on ingress (Python via
`str(ip_address(...))`, Rust via RFC 5952 display), and the Rust
`DIOCRGETADDRS` reader converts kernel entries back through the same
formatter for the same reason.

## serde_yaml stays pinned despite its archive status

The config loader uses serde_yaml 0.9, archived upstream but frozen-stable
with a large install base. If it ever breaks, `serde_yaml_ng` is the
recorded swap; the loader's coercive behaviour (numeric strings parse,
unknown keys ignored) is what the tests pin, not the parser.

## pledge comes last, after an unpledged baseline

`unveil(2)` is unconditional in the Rust daemon. `pledge(2)` is sequenced
after everything else works: the full OpenBSD validation runs and passes on
an unpledged daemon first, then pledge is enabled and the identical pass is
repeated. A pledge violation kills the process with SIGABRT, so any promise
gap during bring-up would be indistinguishable from a daemon bug; sequencing
it last makes every kill in the pledged pass attributable to the pledge.
Whether the `pf` promise covers the table-address ioctls decides the final
shape: covered means a pledged daemon, not covered means unveil-only with a
privsep follow-up (a pledged network parent feeding a small PF-writer child
over a socketpair).
