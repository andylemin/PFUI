#!/usr/bin/env python3
"""The real PFUI_Unbound against the real Rust PFUI_Firewall.

The client container's verify.py proves the resolver side against stub
firewalls; this proves the daemon side against the real resolver: a resolved
answer travels the live protocol (lz4-compressed, both transports at once)
and lands in the PF table, the persist file and Redis, the cache path
relabels the Redis key, and the daemon survives the whole exchange and shuts
down clean.

Everything runs inside the container: nsd is authoritative for pfui-test.,
Unbound forwards to it, Redis and the daemon are the real thing, and pfctl
is a stateful stub because Linux has no PF.
"""

import grp
import os
import signal
import socket
import subprocess
import sys
import time

UNBOUND = "/usr/local/sbin/unbound"
DAEMON = "/usr/local/sbin/pfui_firewall"
RESOLVER = ("127.0.0.1", 5353)
AUTHORITATIVE = ("127.0.0.1", 5354)
DAEMON_TCP = ("127.0.0.1", 10001)
SOCKET_DIR = "/var/run/pfui"
SOCKET_PATH = f"{SOCKET_DIR}/pfui_firewall.sock"
AF4_TABLE = "pfui_ipv4_domains"
AF6_TABLE = "pfui_ipv6_domains"
AF4_FILE = "/tmp/pfui_ipv4_domains"
AF6_FILE = "/tmp/pfui_ipv6_domains"


class Checks:
    def __init__(self):
        self.failures = []

    def that(self, condition, description):
        print(f"{'PASS' if condition else 'FAIL'}  {description}", flush=True)
        if not condition:
            self.failures.append(description)


def wait_for(condition, seconds, step=0.25):
    deadline = time.time() + seconds
    while time.time() < deadline:
        if condition():
            return True
        time.sleep(step)
    return condition()


def wait_for_dns(server, name, seconds=30):
    host, port = server
    def answered():
        probe = subprocess.run(
            ["dig", f"@{host}", "-p", str(port), name, "A", "+time=1", "+tries=1"],
            capture_output=True,
        )
        return probe.returncode == 0 and b"status: NOERROR" in probe.stdout
    return wait_for(answered, seconds, step=0.5)


def dig(name, rrtype):
    host, port = RESOLVER
    result = subprocess.run(
        ["dig", f"@{host}", "-p", str(port), name, rrtype, "+short", "+time=3"],
        capture_output=True,
    )
    return [line for line in result.stdout.decode().split("\n") if line.strip()]


def table(name):
    try:
        with open(f"/tmp/tbl.{name}") as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def persist(path):
    try:
        with open(path) as f:
            return {line.strip() for line in f if line.strip()}
    except FileNotFoundError:
        return set()


def redis_hget(key, field):
    result = subprocess.run(
        ["redis-cli", "hget", key, field], capture_output=True
    )
    return result.stdout.decode().strip()


def tcp_answers(addr):
    try:
        with socket.create_connection(addr, timeout=1):
            return True
    except OSError:
        return False


def main():
    checks = Checks()

    # The socket directory as rc.d/install lay it out: group-traverse only,
    # so the resolver (running as _unbound, member of _pfui) can reach the
    # socket and nobody else can
    gid = grp.getgrnam("_pfui").gr_gid
    os.makedirs(SOCKET_DIR, exist_ok=True)
    os.chown(SOCKET_DIR, 0, gid)
    os.chmod(SOCKET_DIR, 0o750)
    for path in (AF4_FILE, AF6_FILE):
        open(path, "a").close()

    subprocess.run(
        ["redis-server", "--daemonize", "yes", "--save", "", "--bind", "127.0.0.1"],
        check=True,
    )
    checks.that(
        wait_for(
            lambda: subprocess.run(
                ["redis-cli", "ping"], capture_output=True
            ).stdout.strip() == b"PONG",
            10,
        ),
        "redis answers PING",
    )

    daemon = subprocess.Popen(
        [DAEMON, "-f", "/etc/pfui_firewall.yml", "-d"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    checks.that(
        wait_for(lambda: tcp_answers(DAEMON_TCP), 10),
        "the daemon listens on TCP",
    )
    checks.that(
        wait_for(lambda: os.path.exists(SOCKET_PATH), 10),
        "the daemon bound its local socket",
    )

    nsd = subprocess.Popen(
        ["nsd", "-d", "-c", "/etc/nsd/nsd.conf"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    resolver = None
    try:
        if not wait_for_dns(AUTHORITATIVE, "www.pfui-test.", seconds=20):
            print("FAIL  nsd never answered for the test zone")
            return 1
        print("PASS  the authoritative server answers for the test zone", flush=True)

        resolver = subprocess.Popen(
            [UNBOUND, "-d"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        if not wait_for_dns(RESOLVER, "www.pfui-test.", seconds=30):
            print("FAIL  the resolver never answered; the module did not load")
            resolver.terminate()
            print((resolver.stdout.read() or b"").decode()[-8000:])
            return 1
        print("PASS  the resolver loaded pfui_unbound.py and answers queries",
              flush=True)

        # A fresh resolution: the reply path reports kind rr over both
        # transports (both FIREWALLS entries point at this daemon), and the
        # address must land in the PF table before the resolver's blocking
        # send returns
        answers = dig("dual.pfui-test.", "A")
        checks.that(answers == ["1.1.1.1"], f"the answer resolves ({answers})")
        checks.that(
            wait_for(lambda: "1.1.1.1" in table(AF4_TABLE), 10),
            "the resolved address reached the PF table",
        )
        checks.that(
            wait_for(lambda: "1.1.1.1" in persist(AF4_FILE), 10),
            "the resolved address reached the persist file",
        )
        checks.that(
            wait_for(
                lambda: redis_hget(f"{AF4_TABLE}^1.1.1.1", "kind") == "rr", 10
            ),
            "the Redis key is labelled kind rr",
        )
        checks.that(
            redis_hget(f"{AF4_TABLE}^1.1.1.1", "qname") == "dual.pfui-test.",
            "the Redis key records the query name",
        )

        # The same name from the cache: a different resolver call point, an
        # absolute expiry, and the merged Redis hash must flip to kind cache
        # with the ttl field deleted
        dig("dual.pfui-test.", "A")
        checks.that(
            wait_for(
                lambda: redis_hget(f"{AF4_TABLE}^1.1.1.1", "kind") == "cache", 10
            ),
            "a cache hit relabels the Redis key to kind cache",
        )
        if redis_hget(f"{AF4_TABLE}^1.1.1.1", "kind") == "cache":
            expires = redis_hget(f"{AF4_TABLE}^1.1.1.1", "expires")
            checks.that(
                expires.isdigit() and int(expires) >= 1_000_000_000,
                f"the cache expiry is an absolute timestamp ({expires})",
            )
            checks.that(
                redis_hget(f"{AF4_TABLE}^1.1.1.1", "ttl") == "",
                "the losing ttl field was deleted from the merged hash",
            )

        # Several addresses in one reply arrive as one message and all land
        dig("many.pfui-test.", "A")
        checks.that(
            wait_for(
                lambda: {"9.9.9.9", "149.112.112.112"} <= table(AF4_TABLE), 10
            ),
            f"both addresses of a multi-record answer landed ({table(AF4_TABLE)})",
        )

        # AAAA records land in the v6 table and file
        dig("www.pfui-test.", "AAAA")
        checks.that(
            wait_for(lambda: "2001:4860:4860::8888" in table(AF6_TABLE), 10),
            f"the IPv6 address reached the v6 PF table ({table(AF6_TABLE)})",
        )
        checks.that(
            wait_for(
                lambda: "2001:4860:4860::8888" in persist(AF6_FILE), 10
            ),
            "the IPv6 address reached the v6 persist file",
        )

        # One sync period later nothing has churned: the loop's reads agree
        # with its writes (canonical spelling end to end)
        before4 = table(AF4_TABLE)
        time.sleep(7)
        checks.that(
            table(AF4_TABLE) == before4,
            f"a sync cycle leaves a consistent table unchanged ({table(AF4_TABLE)})",
        )

        checks.that(
            dig("www.pfui-test.", "A") == ["8.8.8.8"],
            "the resolver still answers after the whole exchange",
        )
        checks.that(resolver.poll() is None, "the resolver is still running")
        checks.that(daemon.poll() is None, "the daemon is still running")
    finally:
        for process in (resolver, nsd):
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()

    # Clean shutdown: SIGTERM, exit 0, socket unlinked
    daemon.send_signal(signal.SIGTERM)
    try:
        code = daemon.wait(timeout=15)
    except subprocess.TimeoutExpired:
        daemon.kill()
        code = "killed"
    checks.that(code == 0, f"SIGTERM stops the daemon cleanly (exit {code})")
    checks.that(
        not os.path.exists(SOCKET_PATH), "shutdown removed the local socket"
    )

    daemon_log = (daemon.stdout.read() or b"").decode()
    for line in daemon_log.splitlines():
        print(f"      daemon: {line}", flush=True)

    if checks.failures:
        print(f"\n{len(checks.failures)} check(s) failed:")
        for failure in checks.failures:
            print(f"  - {failure}")
        return 1

    print("\nAll checks passed: PFUI_Unbound <-> pfui_firewall (Rust), live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
