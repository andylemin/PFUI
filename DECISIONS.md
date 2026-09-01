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
floored at one second, because Redis treats `EXPIRE 0` (or negative) as "delete
now".

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

## UDP has a message-size ceiling

`UDP_DGRAM_CEILING` (1400 bytes) bounds a PFUI message over UDP. This is not a
buffer that wants raising: a datagram above the link MTU fragments and PF
commonly drops fragments, so UDP cannot carry the large answers TCP handles. A
message above the ceiling is logged and dropped rather than truncated silently.
Accepted because UDP is lab-only and gated behind `ALLOW_INSECURE_UDP`; the fix
for a real deployment is TCP.

## UDP has a message-size ceiling

`UDP_DGRAM_CEILING` (1400 bytes) bounds a PFUI message over UDP. This is not a
buffer that wants raising: a datagram above the link MTU fragments and PF
commonly drops fragments, so UDP cannot carry the large answers TCP handles. A
message above the ceiling is logged and dropped rather than truncated silently.
Accepted because UDP is lab-only and gated behind `ALLOW_INSECURE_UDP`; the fix
for a real deployment is TCP.

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
other ioctl structs; deferred, not forgotten.

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
