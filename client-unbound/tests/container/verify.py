#!/usr/bin/env python3
"""Runs PFUI_Unbound inside the Unbound this container built.

The checks the Dockerfile cannot make on its own:

  * the resolver loads the module at all (a pythonmod API change shows up here,
    as a resolver that refuses to start)
  * a real resolved answer reaches the wire as a valid PFUI message
  * `kind` matches the shape of the TTL it labels: relative seconds on the
    reply path, an absolute timestamp on the cache path
  * both transports carry it: a local unix socket and TCP, configured per
    firewall in one config, which is the same-host and CARP-node arrangement
  * the resolver keeps answering after the exchange

Everything runs inside the container: nsd is authoritative for pfui-test.,
Unbound forwards to it, and the two stubs below stand in for a PFUI_Firewall on
this host and one across the network.
"""

import grp
import os
import socket
import stat
import subprocess
import sys
import threading
import time

# Where the installer puts the shared protocol module, and where pfui_unbound.py
# looks for it
sys.path.insert(0, "/var/unbound/etc")
from pfui_wire import read_frame  # noqa: E402

UNBOUND = "/usr/local/sbin/unbound"
RESOLVER = ("127.0.0.1", 5353)
AUTHORITATIVE = ("127.0.0.1", 5354)
STUB = ("127.0.0.1", 10001)
# Must match the SOCKET entry in pfui_unbound.yml, and the mode the real server
# binds it with, so the resolver's connect() is exercised against the same
# permissions a deployment would have
STUB_SOCKET = "/var/run/pfui/pfui_firewall.sock"
STUB_SOCKET_MODE = 0o660
# The group install-server-python.sh creates and puts _unbound in. Unbound drops
# to _unbound before any query, so this membership is what the resolver's
# connect() actually depends on
STUB_SOCKET_GROUP = "_pfui"
COMPRESS = True  # Must match COMPRESS in pfui_unbound.yml

# A relative DNS TTL cannot plausibly be a unix timestamp, and vice versa. The
# gap between them is what makes the two kinds distinguishable at all.
TIMESTAMP_FLOOR = 1_000_000_000


class StubFirewall(threading.Thread):
    """Accepts PFUI messages and acknowledges them, recording what arrived.

    With no arguments it listens on TCP, standing in for a firewall across the
    network; given a path it listens on a unix socket, standing in for one on this
    host. The framing and the reply are identical either way, which is the point.
    """

    daemon = True

    def __init__(self, path=None):
        super().__init__()
        self.path = path
        if path:
            gid = grp.getgrnam(STUB_SOCKET_GROUP).gr_gid
            parent = os.path.dirname(path)
            os.makedirs(parent, exist_ok=True)
            # As rc.d/pfui_firewall sets it up: only the group may traverse to the
            # socket, which is a second gate in front of the socket's own mode
            os.chown(parent, -1, gid)
            os.chmod(parent, 0o750)
            if os.path.exists(path):
                os.unlink(path)
            self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            previous_umask = os.umask(0o177)  # Never briefly wider, as the daemon does
            try:
                self.listener.bind(path)
            finally:
                os.umask(previous_umask)
            os.chown(path, -1, gid)
            os.chmod(path, STUB_SOCKET_MODE)
        else:
            self.listener = socket.socket()
            self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.listener.bind(STUB)
        self.listener.listen(64)
        self.listener.settimeout(0.5)
        self.messages = []
        self.errors = []
        self.unacked = 0  # Peers gone before the ACK; see the EPIPE note below
        self.stop = threading.Event()

    def run(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            conn.settimeout(3)
            try:
                def recv_exactly(n):
                    buf = bytearray()
                    while len(buf) < n:
                        chunk = conn.recv(n - len(buf))
                        if not chunk:
                            return None
                        buf += chunk
                    return bytes(buf)

                message = read_frame(recv_exactly, compress=COMPRESS)
                if message is not None:
                    self.messages.append(message)
                    try:
                        conn.sendall(b"ACKUPDATE")
                    except BrokenPipeError:
                        # Expected, and only on the local socket: a cache report is
                        # sent with blocking=False, so the resolver has already
                        # closed by now. Loopback TCP absorbs the write into a
                        # buffer nobody reads; a unix socket reports EPIPE at once.
                        # PFUI_Firewall's disconnect() ignores it for exactly this
                        # reason, so this is not a fault to record as one
                        self.unacked += 1
            except Exception as exc:  # Recorded, never raised into accept()
                self.errors.append(repr(exc))
            finally:
                conn.close()

    def close(self):
        self.stop.set()
        self.listener.close()
        if self.path and os.path.exists(self.path):
            os.unlink(self.path)

    def for_qname(self, qname):
        return [m for m in self.messages if m.get("qname") == qname]


def wait_for_dns(server, name, seconds=30):
    """True once `server` answers for `name`."""
    host, port = server
    deadline = time.time() + seconds
    while time.time() < deadline:
        probe = subprocess.run(
            ["dig", f"@{host}", "-p", str(port), name, "A", "+time=1", "+tries=1"],
            capture_output=True,
        )
        if probe.returncode == 0 and b"status: NOERROR" in probe.stdout:
            return True
        time.sleep(0.5)
    return False


def dig(name, rrtype):
    """Answer addresses for one query, as text."""
    host, port = RESOLVER
    result = subprocess.run(
        ["dig", f"@{host}", "-p", str(port), name, rrtype, "+short", "+time=3"],
        capture_output=True,
    )
    return [
        line for line in result.stdout.decode().split("\n") if line.strip()
    ]


class Checks:
    def __init__(self):
        self.failures = []

    def that(self, condition, description):
        print(f"{'PASS' if condition else 'FAIL'}  {description}", flush=True)
        if not condition:
            self.failures.append(description)


def main():
    with open("/src/unbound-ref") as f:
        built = f.read().strip()
    version = subprocess.run([UNBOUND, "-V"], capture_output=True)
    print(f"Unbound ref built: {built}")
    print(version.stdout.decode().strip(), flush=True)

    checks = Checks()
    checks.that(
        b"with-pythonmodule" in version.stdout or b"pythonmodule" in version.stdout,
        "the built resolver reports the Python module in its configure line",
    )

    checkconf = subprocess.run(
        ["/usr/local/sbin/unbound-checkconf", "/var/unbound/etc/pfui_unbound.conf"],
        capture_output=True,
    )
    checks.that(
        checkconf.returncode == 0,
        f"unbound-checkconf accepts the PFUI config {checkconf.stderr.decode().strip()}",
    )
    if checkconf.returncode != 0:
        return 1

    # Two firewalls, one per transport, as pfui_unbound.yml's FIREWALLS names them
    stub = StubFirewall()
    stub.start()
    local = StubFirewall(path=STUB_SOCKET)
    local.start()

    nsd = subprocess.Popen(["nsd", "-d", "-c", "/etc/nsd/nsd.conf"],
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    resolver = None
    try:
        if not wait_for_dns(AUTHORITATIVE, "www.pfui-test.", seconds=20):
            print("FAIL  nsd never answered for the test zone")
            print((nsd.stdout.read() or b"").decode())
            return 1
        print("PASS  the authoritative server answers for the test zone", flush=True)

        resolver = subprocess.Popen([UNBOUND, "-d"], stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT)
        if not wait_for_dns(RESOLVER, "www.pfui-test.", seconds=30):
            print("FAIL  the resolver never answered; the module did not load")
            resolver.terminate()
            print((resolver.stdout.read() or b"").decode()[-8000:])
            return 1
        print("PASS  the resolver loaded pfui_unbound.py and answers queries",
              flush=True)

        # A name not yet in the cache: the iterator resolves it, MODDONE fires,
        # and the module reports a relative RR TTL
        answers = dig("dual.pfui-test.", "A")
        checks.that(answers == ["1.1.1.1"], f"the answer resolves ({answers})")

        time.sleep(2)  # The message is sent during the query; allow for the ACK
        fresh = stub.for_qname("dual.pfui-test.")
        checks.that(bool(fresh), "a PFUI message arrived for the resolved name")
        if fresh:
            message = fresh[0]
            print(f"      reply-path message: {message}", flush=True)
            checks.that(message["kind"] == "rr",
                        "a freshly resolved answer is labelled kind 'rr'")
            checks.that(
                [r["ip"] for r in message["AF4"]] == ["1.1.1.1"],
                "the resolved address is the one on the wire",
            )
            checks.that(
                all(0 <= r["ttl"] < TIMESTAMP_FLOOR for r in message["AF4"]),
                "an 'rr' TTL is a relative TTL, not a timestamp",
            )
            checks.that(
                all("qname" not in r for r in message["AF4"]),
                "qname is carried once per message, not once per record",
            )

        # The same name again is answered from the cache, which is a different
        # call point (inplace_cache_callback) reporting a different kind of TTL
        before = len(stub.for_qname("dual.pfui-test."))
        dig("dual.pfui-test.", "A")
        time.sleep(2)
        cached = [
            m for m in stub.for_qname("dual.pfui-test.")[before:]
        ]
        checks.that(bool(cached), "a cache hit also reports to the firewall")
        if cached:
            message = cached[0]
            print(f"      cache-path message: {message}", flush=True)
            checks.that(message["kind"] == "cache",
                        "a cache hit is labelled kind 'cache'")
            checks.that(
                all(r["ttl"] >= TIMESTAMP_FLOOR for r in message["AF4"]),
                f"a 'cache' TTL is an absolute expiry timestamp "
                f"({[r['ttl'] for r in message['AF4']]})",
            )

        # Several addresses in one reply must arrive as one message, per the
        # protocol's one-message-per-reply rule
        dig("many.pfui-test.", "A")
        time.sleep(2)
        multi = stub.for_qname("many.pfui-test.")
        checks.that(len(multi) >= 1, "a multi-address answer reported")
        if multi:
            addresses = sorted(r["ip"] for r in multi[0]["AF4"])
            checks.that(
                addresses == ["149.112.112.112", "9.9.9.9"],
                f"both addresses from one reply arrive in one message ({addresses})",
            )

        # AAAA records travel in AF6
        dig("www.pfui-test.", "AAAA")
        time.sleep(2)
        v6 = [m for m in stub.for_qname("www.pfui-test.") if m.get("AF6")]
        checks.that(bool(v6), "an AAAA answer reported")
        if v6:
            checks.that(
                [r["ip"] for r in v6[0]["AF6"]] == ["2001:4860:4860::8888"],
                f"the IPv6 address is reported in AF6 ({v6[0]['AF6']})",
            )

        # The local socket carries the same messages as TCP, from the same
        # resolver and the same config, chosen per FIREWALLS entry
        checks.that(
            bool(local.messages),
            f"the firewall on this host was told over {STUB_SOCKET}",
        )
        if local.messages and stub.messages:
            checks.that(
                sorted(m["qname"] for m in local.messages)
                == sorted(m["qname"] for m in stub.messages),
                "both transports carried the same set of replies",
            )
            local_fresh = local.for_qname("dual.pfui-test.")
            checks.that(
                bool(local_fresh) and bool(fresh) and local_fresh[0] == fresh[0],
                "the message over the socket is identical to the one over TCP",
            )
        checks.that(
            stat.S_IMODE(os.stat(STUB_SOCKET).st_mode) == STUB_SOCKET_MODE,
            f"the socket the resolver connected to is {oct(STUB_SOCKET_MODE)}, "
            f"not world-writable",
        )
        checks.that(
            local.errors == [], f"no malformed messages over the socket {local.errors}"
        )
        # Informational, not a pass/fail: it depends on how many cache reports the
        # run happened to make, and the resolver is right not to wait for those
        print(
            f"      non-blocking reports whose ACK found the peer gone: "
            f"socket={local.unacked} tcp={stub.unacked}",
            flush=True,
        )

        checks.that(stub.errors == [], f"no malformed messages arrived {stub.errors}")
        checks.that(
            dig("www.pfui-test.", "A") == ["8.8.8.8"],
            "the resolver still answers after the whole exchange",
        )
        checks.that(resolver.poll() is None, "the resolver is still running")
    finally:
        for process in (resolver, nsd):
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
        stub.close()
        local.close()

    resolver_log = (resolver.stdout.read() or b"").decode() if resolver else ""
    for line in resolver_log.splitlines():
        # Surfaced unconditionally: the resolver logging an error while every
        # check passes is exactly the case that would otherwise go unnoticed
        if "error:" in line:
            print(f"      resolver error: {line}", flush=True)

    if checks.failures:
        print(f"\nResolver output:\n{resolver_log[-8000:]}")
        print(f"\n{len(checks.failures)} check(s) failed:")
        for failure in checks.failures:
            print(f"  - {failure}")
        return 1

    print(f"\nAll checks passed against Unbound {built}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
