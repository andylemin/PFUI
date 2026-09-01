#!/usr/local/bin/python3
# Intentionally uses explicit OpenBSD python3 path due to boot autostart issues

"""
    The pfui_firewall.py server daemon receives from pfui_unbound.py, successfully resolved domains,
      and adds the IPs into local "PF Tables" (v4 & v6), for traffic filtering with PF.
      `pfctl -t pfui_ipv4_domains -T [add|show|delete]` https://www.openbsd.org/faq/pf/tables.html

    DNS Resource Record (A & AAAA) age (last query timestamp) and max-age (TTL) are tracked using Redis, and IPs are
      expired from PF Tables when the last query is older than "EPOCH - (TTL * TTL_MULTIPLIER)".

    The most common PFUI use case blocks all egress traffic by default, allowing egress traffic only for the
      corporate/internal Unbound DNS servers. Therefore, any direct outbound connections without a prior cororate lookup fail.
      This blocks DoH/DoT (DNS over HTTPS/TLS), forcing clients to use the internal Unbound DNS servers (running pfui_unbound).
      Enforces device compliance with corporate DNS-BlockLists for all hosts on the network (including private BYODs).

    This approach blocks most Botnets, Malware, and Ransomware by blocking Command & Control and Infection Spreading.
    pfctl -t pfui_ipv4_domains -T [add|show|delete]

    The PF Table interface supports expiring old entries (pfctl -t pfui_ipv4_domains -T expire 3600), however
    subsequent queries/updates do _not_ refresh the cleared timestamp. Therefore, Redis used to track entries.
    ioctl (pfctl) calls implemented DIOCRADDADDRS, DIOCRDELADDRS (OpenBSD).
    https://man.openbsd.org/ioctl.2 https://docs.python.org/2/library/fcntl.html
"""

import grp
import logging
import os
import stat
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from fcntl import LOCK_EX, LOCK_UN, flock
from logging.handlers import SysLogHandler
from concurrent.futures import ThreadPoolExecutor
from threading import BoundedSemaphore, Event, Thread
from time import sleep, time

from redis import StrictRedis
from service import Service, find_syslog
from yaml import safe_load

from socket import AF_INET, AF_INET6, AF_UNIX, SOCK_DGRAM, SO_REUSEADDR, SOL_SOCKET
from socket import SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY, AddressFamily
from socket import error as socket_error, timeout as socket_timeout
from socket import socket

from pfui.pf_ioctl import table_pop, table_push
from pfui.store import expired_keys
from pfui.validate import extract
from pfui_wire import BadLength, MAX_MESSAGE, Truncated, WireError, decode, read_frame

CONFIG_LOCATION = "/etc/pfui_firewall.yml"

# UDP mode only; see the receive loop in run(). TCP is bounded by MAX_MESSAGE.
UDP_DGRAM_CEILING = 1400

# Mode the local socket ends up with, and the umask that gets it there without
# ever being briefly wider. Not configurable: the socket is the whole access
# control for a local resolver, and the only reason to widen it is a mistake.
UNIX_SOCKET_MODE = 0o660
UNIX_SOCKET_UMASK = 0o177

# Longest usable SOCKET_UNIX path. OpenBSD's sockaddr_un.sun_path is 104 bytes
# including the terminator; Linux allows 108. The smaller limit is checked so the
# failure is a named configuration error at load rather than an "AF_UNIX path too
# long" OSError out of bind() on the platform PFUI targets.
UNIX_PATH_MAX = 103

# Every key the daemon reads, with the value assumed when the yml omits it
CONFIG_DEFAULTS = {
    "LOGGING": True,
    "LOG_LEVEL": "DEBUG",
    "SOCKET_PROTO": "TCP",
    "SOCKET_PORT": 10001,
    # Local stream socket for a resolver on this same host. Empty disables it.
    "SOCKET_UNIX": "",
    # Group allowed to connect; the resolver's account must be a member
    "SOCKET_UNIX_GROUP": "_pfui",
    "SOCKET_TIMEOUT": 3,
    "SOCKET_BUFFER": 1024,
    "SOCKET_BACKLOG": 128,
    "COMPRESS": True,
    "MAX_WORKERS": 32,
    "ALLOW_INSECURE_UDP": False,
    "REDIS_HOST": "127.0.0.1",
    "REDIS_PORT": 6379,
    "REDIS_DB": 0,  # Valid range is 0-15
    "SCAN_PERIOD": 60,
    "TTL_MULTIPLIER": 2,
    "CTL": "IOCTL",
    "DEVPF": "/dev/pf",
}

# Keys with no safe default. SOCKET_LISTEN is deliberately not among them and
# not defaulted either: see the network-listener rule in load_config.
CONFIG_REQUIRED = {
    "AF4_TABLE": "IPv4 PF Table",
    "AF4_FILE": "IPv4 PF Persist file",
    "AF6_TABLE": "IPv6 PF Table",
    "AF6_FILE": "IPv6 PF Persist file",
}


def load_config(location: str = CONFIG_LOCATION) -> dict:
    """Read the yml, apply the defaults, and reject a config that cannot work.

    Raises ValueError rather than exiting, so the daemon owns the exit status and
    the rules stay testable off an OpenBSD host.
    """
    cfg = safe_load(open(location)) or {}
    for key, value in CONFIG_DEFAULTS.items():
        cfg.setdefault(key, value)

    missing = [f"{k} ({v})" for k, v in CONFIG_REQUIRED.items() if k not in cfg]
    if missing:
        raise ValueError(
            "not found in the YAML Config File, please configure: "
            + ", ".join(missing)
        )

    # Normalised and validated here because run() selects its network listener by
    # exact match. Anything else matched neither branch, fell through to the
    # shutdown path and exited 0 as though it had served, and a lowercase 'udp'
    # also slipped past the ALLOW_INSECURE_UDP gate
    cfg["SOCKET_PROTO"] = str(cfg["SOCKET_PROTO"]).strip().upper()
    if cfg["SOCKET_PROTO"] not in ("TCP", "UDP"):
        raise ValueError(
            f"SOCKET_PROTO must be TCP or UDP, not '{cfg['SOCKET_PROTO']}'"
        )

    cfg["SOCKET_UNIX"] = str(cfg["SOCKET_UNIX"] or "").strip()
    if cfg["SOCKET_UNIX"] and not cfg["SOCKET_UNIX"].startswith("/"):
        # A relative path would be resolved against whatever directory rc.subr
        # happened to start the daemon in
        raise ValueError(
            f"SOCKET_UNIX must be an absolute path, not '{cfg['SOCKET_UNIX']}'"
        )
    if len(cfg["SOCKET_UNIX"].encode("utf-8")) > UNIX_PATH_MAX:
        raise ValueError(
            f"SOCKET_UNIX is {len(cfg['SOCKET_UNIX'])} bytes, over the "
            f"{UNIX_PATH_MAX} byte limit on a socket path: '{cfg['SOCKET_UNIX']}'"
        )

    # A listener has to be asked for explicitly, one way or the other. Both may
    # be set: a firewall can serve its own resolver over the local socket and a
    # remote one - a CARP peer's - over the network at the same time.
    #
    # SOCKET_LISTEN is neither required nor defaulted to 0.0.0.0. The port it
    # binds injects entries into the PF whitelist and is unauthenticated, so
    # publishing it on every interface is never the right guess; leaving it out
    # is how a same-host deployment says "local socket only".
    if not cfg.get("SOCKET_LISTEN") and not cfg["SOCKET_UNIX"]:
        raise ValueError(
            "no listener configured: set SOCKET_LISTEN (the inside interface IP, "
            "never 0.0.0.0) for remote resolvers, or SOCKET_UNIX for a resolver "
            "on this host, or both"
        )
    return cfg


def _key_lifetime(window: int, cfg: dict) -> int:
    """Seconds to keep a Redis key alive, as a backstop only.

    scan_redis_db owns expiry; this just stops a key outliving the daemon that
    would have swept it. One SCAN_PERIOD of slack keeps the key present for the
    scan that should retire it, and the result is floored at 1 because Redis
    treats EXPIRE 0 (or negative) as "delete now", which for a ttl of 0 would
    discard the record before its own scan ever saw it.
    """
    return max(int(window) + int(cfg["SCAN_PERIOD"]), 1)


def db_push(logger, log: bool, db, table: str, data: list, kind: str, qname: str,
            cfg: dict = None):
    """Store IP(s) and metadata to Redis database table.

    'kind' comes from the sender, which knows whether it read a relative RR TTL
    ("rr") or an absolute Unbound cache-expiry timestamp ("cache"). The losing
    field is deleted because hmset merges, and a key holding both would be
    ambiguous to the expiry scan.

    The TTL is stored exactly as the sender reported it. There is no floor: the
    protocol says a ttl of 0 means do-not-cache, so raising it here would have
    authorised egress the answer explicitly asked not to keep, and any floor
    contradicts the documented expiry rule. TTL_MULTIPLIER is the knob for
    holding entries longer than the record says.
    """

    if log:
        logger.info(f"PFUIFW: Storing '{data}' ({kind}) to Redis")

    try:
        pipe = db.pipeline()
        now = int(time())
        for ip, rr_ttl in data:
            key = f"{table}^{ip}"
            rr_ttl = int(rr_ttl)
            if kind == "cache":
                pipe.hmset(
                    key,
                    {"epoch": now, "kind": "cache", "expires": rr_ttl, "qname": qname},
                )
                pipe.hdel(key, "ttl")
                if cfg:
                    pipe.expire(key, _key_lifetime(max(rr_ttl - now, 0), cfg))
            else:
                pipe.hmset(
                    key,
                    {
                        "epoch": now,
                        "kind": "rr",
                        "ttl": rr_ttl,
                        "qname": qname,
                    },
                )
                pipe.hdel(key, "expires")
                if cfg:
                    pipe.expire(
                        key, _key_lifetime(rr_ttl * int(cfg["TTL_MULTIPLIER"]), cfg)
                    )
        pipe.execute()
        return True
    except Exception:
        logger.exception(f"PFUIFW: Failed to store {data} to Redis")
        return False


def db_pop(logger, log: bool, db, table: str, ip_list: list):
    """Remove IP(s) from Redis database table."""

    if log:
        logger.info(f"PFUIFW: Clearing '{ip_list}' from Redis DB")

    try:
        pipe = db.pipeline()
        for ip in ip_list:
            pipe.delete(f"{table}^{ip}")
        pipe.execute()
        return True
    except Exception:
        logger.exception(f"PFUIFW: Failed to delete {ip_list} from Redis")
        return False


@contextmanager
def _locked(path: str):
    """Exclusive cross-process lock via a sidecar .lock file, which is never
    truncated or renamed, so the lock cannot be lost with the file it guards.
    """
    fd = os.open(path + ".lock", os.O_CREAT | os.O_RDWR, 0o640)
    try:
        flock(fd, LOCK_EX)  # Blocking; the kernel queues waiters
        yield
    finally:
        flock(fd, LOCK_UN)
        os.close(fd)


def file_push(logger, log: bool, file: str, ip_list: list):
    """Append IP(s) to PF Table's File.

    Called per DNS answer, with every receiver thread serialised on one lock, so
    it must not read the file. Duplicate lines are harmless (PF loads a table as
    a set) and file_pop's rewrite collapses them on the next scan.
    """
    if log:
        logger.info(f"PFUIFW: Adding '{ip_list}' to PF Table File {file}")

    try:
        with _locked(file):
            with open(file, "a") as f:
                f.write("".join(f"{ip}\n" for ip in ip_list))
        return True
    except Exception:
        logger.exception(f"PFUIFW: Failed to append {ip_list} to {file}.")
        return False


def file_pop(logger, log: bool, file: str, ip_list: list):
    """Remove IP(s) from PF Table's File, and dedupe what remains."""

    if log:
        logger.info(f"PFUIFW: Clearing '{ip_list}' from PF Table File {file}")

    remove = set(ip_list)
    try:
        with _locked(file):
            with open(file, "r") as f:
                # Read from the handle we are about to replace, so a tightened
                # mode is carried over rather than reverted to a hardcoded one
                mode = stat.S_IMODE(os.fstat(f.fileno()).st_mode)
                # sorted() keeps content stable, so an unchanged whitelist
                # produces an unchanged file. PF ignores line order.
                keep = sorted(
                    {
                        line.strip()
                        for line in f
                        if line.strip() and line.strip() not in remove
                    }
                )
            fd, tmp = tempfile.mkstemp(
                dir=os.path.dirname(file) or ".", prefix=".pfui_", suffix=".tmp"
            )
            with os.fdopen(fd, "w") as t:
                t.write("".join(f"{ip}\n" for ip in keep))
            os.chmod(tmp, mode)  # mkstemp creates 0600, whatever the file was
            os.replace(tmp, file)  # Atomic within one filesystem
        return True
    except Exception:
        logger.exception(f"PFUIFW: Failed to delete IP(s) {ip_list} from {file}")
        return False


class ScanSync(Thread):
    """scan_redis_db: Expires IPs with last update epoch/timestamp older than (TTL * TTL_MULTIPLIER).
    sync_pf_table: Removes orphaned IPs (no DB entry) from the PF Table, and adds missing IPs to the PF Table.
    sync_pf_file: Removes orphaned IPs (no DB entry) from the PF File, and adds missing IPs to the PF File.
    """

    def __init__(self, logger, cfg, db, af, table, file):
        Thread.__init__(self)
        self.daemon = True
        self.stop_event = Event()
        self.logger = logger
        self.cfg = cfg
        self.db = db
        self.af = af
        self.table = table
        self.file = file
        self.logger.info(f"PFUIFW: [+] Sync thread started for {self.table}")

    def join(self, timeout=30):  # Overload join from Thread super
        self.stop_event.set()
        super().join(timeout)

    def run(self):
        """Start Scanner loop"""

        class Break(Exception):
            pass

        try:
            while not self.stop_event.is_set():
                try:
                    self.scan_redis_db()
                    # Each sync reads its own Redis snapshot, after reading the
                    # store it may delete from; see sync_pf_table
                    self.sync_pf_table()
                    self.sync_pf_file()
                except Exception:
                    # A transient fault must not end expiry for this table
                    self.logger.exception(
                        f"PFUIFW: Sync cycle failed for {self.table}, retrying next scan"
                    )
                for _ in range(int(self.cfg["SCAN_PERIOD"])):
                    if self.stop_event.is_set():
                        raise Break
                    sleep(1)
        except Break:
            self.logger.info(f"PFUIFW: [-] Sync thread closing for {self.table}")
        except Exception as e:
            self.logger.exception(f"PFUIFW: Sync thread died for {self.table}! {e}")

    def scan_redis_db(self):
        """Expire IPs whose metadata says they are past their TTL or cache expiry."""

        if self.cfg["LOGGING"]:
            self.logger.info(
                f"PFUIFW: Scan DB({self.cfg['REDIS_DB']}) for expiring {self.table} IPs."
            )

        try:
            expired_ips = expired_keys(
                db=self.db,
                table=self.table,
                now=int(time()),
                multiplier=self.cfg["TTL_MULTIPLIER"],
            )
        except Exception:
            # Survive a transient Redis fault; the next SCAN_PERIOD retries
            self.logger.exception(
                f"PFUIFW: Failed to scan Redis for {self.table}, retrying next scan"
            )
            return

        if expired_ips and self.cfg["LOGGING"]:
            self.logger.info(f"PFUIFW: TTL Expired for IPs {expired_ips}")

        # Purge if expired
        if expired_ips:
            db_pop(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                db=self.db,
                table=self.table,
                ip_list=expired_ips,
            )

    def sync_pf_table(self):
        """
        Sync the Redis table with the PF Table. Reads the table with pfctl; DIOCRGETADDRS
        is not implemented (see DECISIONS.md)
        """
        if self.cfg["LOGGING"]:
            self.logger.info(
                f"PFUIFW: Sync PF Table {self.table} with DB({self.cfg['REDIS_DB']})"
            )

        db_ips, t_ips = [], []
        try:
            # Order matters: read the PF table BEFORE Redis. Deletions below are
            # driven by "in the table but not in Redis", so if Redis were read
            # first, an IP whitelisted between the two reads would look orphaned
            # and be deleted despite a live key. Reading Redis last can only
            # retain an expired entry for one more cycle, which is harmless.
            # pfctl costs a subprocess, but this runs once per SCAN_PERIOD, not
            # per query (see DECISIONS.md)
            #
            # The exit status is checked because a failing pfctl produces no
            # output, which is indistinguishable from an empty table: the diff
            # below would then find nothing to delete and try to re-add every
            # live IP, so real table entries would never be expired and nothing
            # would say why. Raising here lands in the handler below, which
            # logs and skips the cycle.
            shown = subprocess.run(
                ["pfctl", "-t", self.table, "-T", "show"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            if shown.returncode != 0:
                raise RuntimeError(
                    f"pfctl -t {self.table} -T show exited {shown.returncode}: "
                    f"{shown.stderr.decode('utf-8', 'replace').strip()}"
                )
            t_ips = [
                l.strip()
                for l in shown.stdout.decode("utf-8", "replace").splitlines()
                if l.strip()
            ]

            keys = list(self.db.scan_iter(match=f"{self.table}^*", count=500))
            db_ips = [k.decode("utf-8").split("^")[1] for k in keys]
        except Exception:
            self.logger.exception(
                f"PFUIFW: Failed to read stores for {self.table}, skipping this sync"
            )
            return  # Never diff against a partial read

        # Remove expired IPs from pf_table (Redis record purged)
        db_set, t_set = set(db_ips), set(t_ips)
        t_ips_del = list(t_set - db_set)
        if t_ips_del:
            table_pop(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                cfg=self.cfg,
                af=self.af,
                table=self.table,
                ip_list=t_ips_del,
            )

        # Add any missing IPs into pf_table (Active Redis record)
        t_ips_add = list(db_set - t_set)
        if t_ips_add:
            table_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                cfg=self.cfg,
                af=self.af,
                table=self.table,
                ip_list=t_ips_add,
            )

    def sync_pf_file(self):
        """
        Sync the Redis DB with the PF File.
        """
        if self.cfg["LOGGING"]:
            self.logger.info(
                f"PFUIFW: Sync PF File {self.table} with DB({self.cfg['REDIS_DB']})"
            )

        db_ips, f_ips = [], []
        try:
            # Read the file before Redis, for the reason given in sync_pf_table
            with open(self.file) as f:
                content = f.readlines()
            f_ips = [x.strip() for x in content if x.strip()]

            keys = list(self.db.scan_iter(match=f"{self.table}^*", count=500))
            db_ips = [k.decode("utf-8").split("^")[1] for k in keys]
        except Exception:
            self.logger.exception(
                f"PFUIFW: Failed to read stores for {self.file}, skipping this sync"
            )
            return  # Never diff against a partial read

        # Remove expired IPs from PF Table File (Redis record purged).
        # Set-based, so duplicate lines from file_push's appends collapse here.
        db_set, f_set = set(db_ips), set(f_ips)
        f_ips_del = list(f_set - db_set)
        if f_ips_del:
            file_pop(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                file=self.file,
                ip_list=f_ips_del,
            )

        # Add any missing IPs to the PF Table File (Active Redis record)
        f_ips_add = list(db_set - f_set)
        if f_ips_add:
            file_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                file=self.file,
                ip_list=f_ips_add,
            )


class PFUI_Firewall(Service):
    """Main PFUI Firewall Service Class."""

    def __init__(self, *args, **kwargs):
        """Load Yaml configuration and Init logger"""

        super(PFUI_Firewall, self).__init__(*args, **kwargs)  # Run Service __init__
        self.threads = []
        self.soc = None  # UDP Listen Socket
        self.conn = None  # TCP Listen Socket
        self.unix = None  # Local (AF_UNIX) Listen Socket
        self.db = None

        # Load YAML Configuration
        try:
            self.cfg = load_config()
        except Exception as e:
            print(f"YAML Config File not found or cannot load. {e}")
            sys.exit(2)

        # Init Logging
        self.logger.addHandler(
            SysLogHandler(address=find_syslog(), facility=SysLogHandler.LOG_DAEMON)
        )
        # Both the timing probes and the summary below use this one flag
        self.stats = (
            bool(self.cfg["LOGGING"]) and self.cfg["LOG_LEVEL"] == "DEBUG"
        )

        if self.cfg["LOG_LEVEL"] == "DEBUG":
            self.logger.setLevel(logging.DEBUG)
        elif self.cfg["LOG_LEVEL"] == "INFO":
            self.logger.setLevel(logging.INFO)
        else:
            self.logger.setLevel(logging.ERROR)

    def run(self):
        """Connect to Redis, start sync threads, and watch socket (spawn Receiver each session)  (PFUI_Unbound))."""

        # Connect to Redis DB
        try:
            self.db = StrictRedis(
                str(self.cfg["REDIS_HOST"]),
                int(self.cfg["REDIS_PORT"]),
                int(self.cfg["REDIS_DB"]),
            )
        except Exception:
            self.logger.exception("PFUIFW: Failed to connect to Redis DB.")
            sys.exit(3)

        # Start background scan and sync threads (Expire IPs in Redis tables, PF tables and Files)
        try:
            af4_thread = ScanSync(
                logger=self.logger,
                cfg=self.cfg,
                db=self.db,
                af=AF_INET,
                table=self.cfg["AF4_TABLE"],
                file=self.cfg["AF4_FILE"],
            )
            af4_thread.start()
            self.threads.append(af4_thread)
            af6_thread = ScanSync(
                logger=self.logger,
                cfg=self.cfg,
                db=self.db,
                af=AF_INET6,
                table=self.cfg["AF6_TABLE"],
                file=self.cfg["AF6_FILE"],
            )
            af6_thread.start()
            self.threads.append(af6_thread)
        except Exception:
            self.logger.exception("PFUIFW: Scanning thread failed.")
            sys.exit(4)
        self.logger.info("PFUIFW: [+] PFUI_Firewall Service Started.")

        # Bounded worker pool. ThreadPoolExecutor alone would not degrade
        # gracefully: its queue is unbounded, so a flood still holds one accepted
        # fd per queued item until fds or memory run out.
        workers = int(self.cfg["MAX_WORKERS"])
        self.max_inflight = workers * 2
        self.pool = ThreadPoolExecutor(max_workers=workers)
        self.slots = BoundedSemaphore(self.max_inflight)

        if (
            self.cfg["SOCKET_PROTO"] == "UDP"
            and self.cfg.get("SOCKET_LISTEN")
            and not self.cfg["ALLOW_INSECURE_UDP"]
        ):
            self.logger.error(
                "PFUIFW: UDP mode is spoofable (a datagram source address is not "
                "verified) and is intended for lab use only. Set "
                "ALLOW_INSECURE_UDP: True in /etc/pfui_firewall.yml to proceed, "
                "or use SOCKET_PROTO: TCP."
            )
            sys.exit(5)

        # Bind every configured listener before serving any of them, so a bind
        # failure is a startup failure rather than a thread that quietly died
        servers = []
        try:
            if self.cfg["SOCKET_UNIX"]:
                self.unix = self._bind_unix(self.cfg["SOCKET_UNIX"])
                servers.append((self._serve_stream, ("UNIX", self.unix)))
            if self.cfg.get("SOCKET_LISTEN"):
                if self.cfg["SOCKET_PROTO"] == "TCP":
                    self.conn = self._bind_tcp()
                    servers.append((self._serve_stream, ("TCP", self.conn)))
                else:
                    self.soc = self._bind_udp()
                    servers.append((self._serve_udp, (self.soc,)))
        except Exception:
            # _bind_unix exits by itself, and SystemExit is not an Exception, so
            # this is the network listener failing after the local one succeeded:
            # unlink it rather than leave a node for the next start to reclaim
            self.logger.exception("PFUIFW: Failed to bind a listener")
            self._remove_unix_socket()
            sys.exit(6)

        if not servers:  # load_config refuses this, so reaching it is a bug
            self.logger.error("PFUIFW: No listener configured; nothing to serve.")
            sys.exit(6)

        # One thread per listener rather than one poll loop over all of them: each
        # loop already blocks only for SOCKET_TIMEOUT before re-checking for TERM,
        # and the pool, the slot semaphore and the shed path are shared and
        # thread-safe, so this keeps each accept path exactly as it was
        listen_threads = []
        for target, args in servers:
            thread = Thread(target=self._serve, args=(target, args), daemon=True)
            thread.start()
            listen_threads.append(thread)
        for thread in listen_threads:
            thread.join()

        # Shut down
        self.pool.shutdown(wait=True)
        for t in self.threads:
            t.join()
        self._remove_unix_socket()
        self.db.close()
        self.logger.info("PFUIFW: [-] PFUI_Firewall Service Stopped.")

    def _serve(self, target, args):
        """Run one listener's loop, surviving anything it raises.

        A listener thread that died silently would leave the daemon running and
        apparently healthy while nothing was being whitelisted on that transport.
        """
        try:
            target(*args)
        except Exception:
            self.logger.exception("PFUIFW: Listener loop failed")

    def _bind_tcp(self):
        """Bind the network stream listener.

        Default TCP time_wait = 60; 64000 / 60 = 1,066qps
        sysctl net.inet.tcp.keepidle=10; 64000 / 10 = 6,400qps
        """
        conn = socket(AF_INET, SOCK_STREAM)  # TCP Stream Socket
        conn.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)  # Disable Nagle
        # conn.setsockopt(socket.SOL_TCP, 23, 5)
        # 23 = TCP_FASTOPEN, 5 = Max TFO queue (not yet supported in OpenBSD)
        conn.setsockopt(SOL_SOCKET, SO_REUSEADDR, True)  # Fast Listen Socket reuse
        conn.settimeout(
            self.cfg["SOCKET_TIMEOUT"]
        )  # accept() connection timeout to check TERM
        conn.bind((self.cfg["SOCKET_LISTEN"], self.cfg["SOCKET_PORT"]))
        conn.listen(self.cfg["SOCKET_BACKLOG"])
        self.logger.info(
            f"PFUIFW: [+] Listening on TCP "
            f"{self.cfg['SOCKET_LISTEN']}:{self.cfg['SOCKET_PORT']}"
        )
        return conn

    def _bind_udp(self):
        """Bind the network datagram listener.

        UDP is experimental and spoofable. The Unbound module runs per lookup, so
        each lookup is a fresh exchange; with UDP defaults that caps out near
        213qps.
        """
        soc = socket(AF_INET, SOCK_DGRAM)  # UDP Datagram Socket
        soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, True)
        soc.settimeout(
            self.cfg["SOCKET_TIMEOUT"]
        )  # recvfrom() data timeout to check TERM
        soc.bind((self.cfg["SOCKET_LISTEN"], self.cfg["SOCKET_PORT"]))
        self.logger.info(
            f"PFUIFW: [+] Listening on UDP "
            f"{self.cfg['SOCKET_LISTEN']}:{self.cfg['SOCKET_PORT']}"
        )
        return soc

    def _bind_unix(self, path):
        """Bind the local stream listener for a resolver on this same host.

        The filesystem is the whole access control here, in place of the pf.conf
        source restriction that guards the network listener, so this fails closed:
        anything that would leave the socket reachable by more than the configured
        group exits the daemon instead of serving.
        """
        parent = os.path.dirname(path) or "/"
        if not os.path.isdir(parent):
            self.logger.error(
                f"PFUIFW: SOCKET_UNIX directory {parent} does not exist; "
                f"rc.d/pfui_firewall creates it on start."
            )
            sys.exit(6)

        # A world-writable parent means anyone can replace the socket with their
        # own and be handed the resolver's messages, whatever the socket's mode
        parent_mode = os.stat(parent).st_mode
        if parent_mode & stat.S_IWOTH and not parent_mode & stat.S_ISVTX:
            self.logger.error(
                f"PFUIFW: SOCKET_UNIX directory {parent} is world-writable "
                f"({oct(stat.S_IMODE(parent_mode))}); refusing to bind there."
            )
            sys.exit(6)

        self._reclaim_unix_socket(path)

        listener = socket(AF_UNIX, SOCK_STREAM)
        listener.settimeout(self.cfg["SOCKET_TIMEOUT"])  # accept() checks TERM
        # bind() creates the node with the process umask, so it is narrowed here
        # rather than by a chmod afterwards: otherwise the socket is connectable
        # by everyone for the moment in between
        previous_umask = os.umask(UNIX_SOCKET_UMASK)
        try:
            listener.bind(path)
        finally:
            os.umask(previous_umask)

        try:
            self._grant_unix_socket(path)
        except Exception:
            self.logger.exception(
                f"PFUIFW: Cannot restrict {path} to group "
                f"{self.cfg['SOCKET_UNIX_GROUP']}; refusing to serve on it."
            )
            # Explicit path and listener: self.unix is not set until run() has the
            # bound socket back, so a refused start would otherwise leave the node
            # behind for the next start to reclaim
            self._remove_unix_socket(path=path, listener=listener)
            sys.exit(6)

        listener.listen(self.cfg["SOCKET_BACKLOG"])
        self.logger.info(
            f"PFUIFW: [+] Listening on UNIX {path} "
            f"(group {self.cfg['SOCKET_UNIX_GROUP']}, mode {oct(UNIX_SOCKET_MODE)})"
        )
        return listener

    def _reclaim_unix_socket(self, path):
        """Remove a socket file left behind by an unclean stop.

        bind() fails with EADDRINUSE on a leftover node, so it has to go, but only
        once nothing answers on it: unlinking a live daemon's socket would leave
        that daemon running and unreachable.
        """
        if not os.path.exists(path):
            return
        probe = socket(AF_UNIX, SOCK_STREAM)
        probe.settimeout(1)
        try:
            probe.connect(path)
        except (ConnectionRefusedError, FileNotFoundError):
            pass  # Nothing is listening; the node is stale
        except OSError as e:
            self.logger.error(
                f"PFUIFW: {path} exists and cannot be tested ({e}); "
                f"remove it by hand if no PFUI_Firewall is running."
            )
            sys.exit(6)
        else:
            self.logger.error(
                f"PFUIFW: Another PFUI_Firewall is already listening on {path}."
            )
            sys.exit(6)
        finally:
            probe.close()
        self.logger.info(f"PFUIFW: Removing stale socket {path}")
        os.unlink(path)

    def _grant_unix_socket(self, path):
        """Hand the socket to SOCKET_UNIX_GROUP, and to nobody else."""
        group = self.cfg["SOCKET_UNIX_GROUP"]
        gid = grp.getgrnam(str(group)).gr_gid  # KeyError if the group is missing
        os.chown(path, -1, gid)
        os.chmod(path, UNIX_SOCKET_MODE)
        granted = stat.S_IMODE(os.stat(path).st_mode)
        if granted != UNIX_SOCKET_MODE:
            raise OSError(f"{path} is mode {oct(granted)}, expected {oct(UNIX_SOCKET_MODE)}")

    def _remove_unix_socket(self, path=None, listener=None):
        """Unlink our own socket on the way out, so the next start is clean.

        Defaults to the running daemon's socket; both are passed explicitly by the
        bind path, which has to clean up a socket run() has not been handed yet.
        """
        path = path or self.cfg.get("SOCKET_UNIX")
        listener = listener if listener is not None else self.unix
        if not path or listener is None:
            return
        try:
            listener.close()
            os.unlink(path)
        except FileNotFoundError:
            pass
        except Exception:
            self.logger.exception(f"PFUIFW: Could not remove {path}")

    def _serve_stream(self, kind, listener):
        """Accept loop shared by the TCP and UNIX listeners.

        Both carry the same length-prefixed frames and get the same replies, so
        the only difference is how a peer is named in the log: an address and port
        for TCP, the socket path for UNIX, where accept() reports no peer at all.
        """
        while not self.got_sigterm():  # Watch Socket until TERM
            try:
                # Hand each accepted connection to the pool
                conn, address = listener.accept()  # Waits listener.settimeout
                if kind == "UNIX":
                    peer, ip, port = self.cfg["SOCKET_UNIX"], None, None
                else:
                    ip, port = address
                    peer = f"{ip}:{port}"
                self._prepare_conn(conn)
                if not self.slots.acquire(blocking=False):
                    # Shed rather than queue: PF still denies the traffic, and
                    # PFUI_Unbound sees a socket failure instead of a stall
                    self.logger.error(
                        f"PFUIFW: At capacity ({self.max_inflight}), shedding {peer}"
                    )
                    conn.close()
                    continue
                try:
                    self._submit(proto=kind, conn=conn, peer=peer, ip=ip, port=port)
                except Exception:
                    self.slots.release()
                    conn.close()
                    self.logger.exception("PFUIFW: Error starting receiver thread")
            except socket_timeout:
                continue
            except socket_error as e:
                # accept() can fail transiently: ECONNABORTED when a peer
                # goes away, EMFILE/ENFILE under fd pressure. Neither is a
                # reason to stop serving.
                self.logger.error(f"PFUIFW: accept() failed, continuing. {e}")
                sleep(0.1)
                continue
            except Exception:
                self.logger.exception("PFUIFW: Unexpected accept() error, continuing")
                sleep(0.5)
                continue

    def _serve_udp(self, soc):
        """Receive loop for the network datagram listener."""
        while not self.got_sigterm():  # Watch Socket until TERM
            try:
                # KNOWN LIMITATION, UDP mode only: this buffer is the hard
                # ceiling on a PFUI message over UDP. A larger datagram is
                # truncated by the kernel, the decode then fails, and the
                # answer is never whitelisted. Reading one byte past the
                # ceiling is what makes that detectable instead of silent.
                #
                # Raising the buffer would not make large answers work: a
                # datagram above the link MTU fragments, and PF commonly
                # drops fragments. UDP mode therefore cannot carry the large
                # answers TCP handles via MAX_MESSAGE, and this is one reason
                # UDP is gated behind ALLOW_INSECURE_UDP. TCP has no such
                # limit; use it, or SOCKET_UNIX on the same host.
                dgram, (ip, port) = soc.recvfrom(UDP_DGRAM_CEILING + 1)
                if len(dgram) > UDP_DGRAM_CEILING:
                    self.logger.error(
                        f"PFUIFW: Datagram from {ip}:{port} exceeds the "
                        f"{UDP_DGRAM_CEILING} byte UDP ceiling "
                        f"({len(dgram)}+ bytes); dropping. This answer cannot "
                        f"be whitelisted over UDP - switch SOCKET_PROTO to TCP."
                    )
                    continue
                # ACKDATA is sent by receiver_thread once the datagram has
                # decoded to a valid PFUI structure, so this cannot be used
                # as a blind reflector
            except socket_timeout:
                continue
            except socket_error:
                continue
            except Exception as e:
                self.logger.exception(f"PFUIFW: UDP socket exception {e}")
                sleep(0.5)
                continue

            if dgram:  # Hand each datagram to the pool
                if not self.slots.acquire(blocking=False):
                    self.logger.error(
                        f"PFUIFW: At capacity ({self.max_inflight}), dropping {ip}:{port}"
                    )
                    continue
                try:
                    self._submit(
                        proto="UDP", dgram=dgram, peer=f"{ip}:{port}", ip=ip, port=port
                    )
                except Exception:
                    self.slots.release()
                    self.logger.exception("PFUIFW: Error in receiver thread")

    def _prepare_conn(self, conn):
        """Apply per-connection options to a freshly accepted socket.

        accept() does not carry over the listener's settings: Python returns the
        new socket in blocking mode with no timeout, so without this a peer that
        connects and stalls occupies a worker slot permanently. TCP_NODELAY is
        set here too rather than relying on inheritance from the listener, which
        is not guaranteed across platforms.
        """
        conn.settimeout(float(self.cfg["SOCKET_TIMEOUT"]))
        # Nagle is a TCP algorithm and there is nothing to disable on a local
        # socket, where setting it raises rather than being ignored
        if conn.family in (AF_INET, AF_INET6):
            try:
                conn.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)
            except Exception:  # Not fatal; costs latency, not correctness
                self.logger.exception(
                    "PFUIFW: Could not set TCP_NODELAY on connection"
                )
        return conn

    def _submit(self, **kwargs):
        """Run receiver_thread in the pool, releasing its slot when it finishes."""
        future = self.pool.submit(self.receiver_thread, **kwargs)
        future.add_done_callback(self._task_done)

    def _task_done(self, future):
        self.slots.release()
        exc = future.exception()
        if exc is not None:
            # Futures store exceptions instead of reaching threading.excepthook,
            # so without this a recurring receiver failure would be silent
            self.logger.error(f"PFUIFW: Receiver task failed: {exc!r}", exc_info=exc)

    def receiver_thread(self, proto, conn=None, dgram=None, peer="", ip=None,
                        port=None):
        """Receive all data, update PF Table and Redis DB
        Data Structure:
        {'kind': 'rr'|'cache', 'qname': qname, 'AF4': [{"ip": ipv4_addr, "ttl": ip_ttl}], 'AF6': [...]}
        For performance, we want entire message sent in a single segment, with small socket buffers (no delay).
        SOCKET_BUFFER is the read chunk size, not a message limit; message size is
        bounded by the protocol's MAX_MESSAGE. Raising it costs memory per
        connection and saves syscalls on large answers.

        'peer' is how this sender is named in the log. AF_UNIX accept() reports
        no peer address at all, so it cannot be derived here; ip and port stay
        for the UDP reply, which is the only path that needs to address one.
        """
        peer = peer or f"{ip}:{port}"

        def disconnect(proto, soc, conn, msg):
            if msg:
                msg = msg.encode("utf-8")
            else:
                msg = b"ACK"

            self.logger.info(f"PFUIFW: Close msg: {msg}")

            if proto == "UDP":
                # Only reply to a datagram that validated. A refusal sent to an
                # unverified source address would make this a reflector, the very
                # thing that moving ACKDATA after validation prevents.
                if msg == b"ACKUPDATE":
                    try:
                        soc.sendto(msg, (ip, port))
                    except Exception:
                        pass  # PFUI_Unbound may have closed socket already (non-blocking cache responses)
                # Do not soc.close(), as this stops the listening socket
            elif proto in ("TCP", "UNIX"):
                try:
                    conn.sendall(msg)
                except Exception:
                    pass  # PFUI_Unbound may have closed connection already (non-blocking cache responses)
                finally:
                    conn.close()

        if self.stats:
            stime = time()

        # Read data from network
        data = None
        if proto in ("TCP", "UNIX"):

            received = []

            def recv_exactly(n):
                """Read exactly n bytes; None if the peer closed first."""
                buf = bytearray()
                while len(buf) < n:
                    chunk = conn.recv(min(n - len(buf), int(self.cfg["SOCKET_BUFFER"])))
                    if not chunk:
                        return None
                    buf += chunk
                received.append(len(buf))
                return bytes(buf)

            try:
                data = read_frame(recv_exactly, compress=self.cfg["COMPRESS"])
                if data is None and not received:
                    # read_frame returns None when no header arrived at all, which
                    # PROTOCOL.md makes a non-error. A payload of JSON null also
                    # decodes to None, and calling that an empty payload was
                    # wrong: it falls through to the shape check below instead
                    self.logger.error(
                        f"PFUIFW: Empty payload, disconnecting {peer}"
                    )
                    disconnect(proto, self.soc, conn, msg="Empty payload")
                    return
            except socket_timeout:
                self.logger.error(f"PFUIFW: Socket recv timeout {peer}")
                disconnect(proto, self.soc, conn, msg="Socket timeout")
                return
            except BadLength as e:
                # Reported separately from a truncated payload, as PROTOCOL.md
                # documents and server-c already distinguishes: a bad prefix is
                # a different diagnosis from a sender that under-delivered
                self.logger.error(
                    f"PFUIFW: Bad frame length from {peer}, disconnecting. {e}"
                )
                disconnect(proto, self.soc, conn, msg="Bad length")
                return
            except Truncated as e:
                self.logger.error(
                    f"PFUIFW: Truncated payload from {peer}, disconnecting. {e}"
                )
                disconnect(proto, self.soc, conn, msg="Truncated")
                return
            except WireError as e:
                self.logger.error(
                    f"PFUIFW: Bad frame from {peer}, disconnecting. {e}"
                )
                disconnect(proto, self.soc, conn, msg="Bad frame")
                return
            except Exception:
                self.logger.exception(
                    f"PFUIFW: Failed to decode stream, disconnecting {peer}"
                )
                disconnect(proto, self.soc, conn, msg="Failed to decode")
                return

        elif proto == "UDP":
            try:
                if len(dgram) > MAX_MESSAGE:
                    raise WireError(f"datagram of {len(dgram)} bytes too large")
                data = decode(dgram, compress=self.cfg["COMPRESS"])
            except Exception:
                self.logger.exception(
                    f"PFUIFW: Failed to decode datagram {peer} {dgram}"
                )
                disconnect(proto, self.soc, conn, "Failed to decode")
                return

        if self.stats:
            ntime = time()
            self.logger.info(f"PFUIFW: Received {data} from {peer} ({proto})")

        # Input Request
        # Shape first, then contents: a non-dict payload has no 'kind' to be
        # missing, and reporting one as a version skew sent the wrong operator
        # down the wrong path
        af4_data, af6_data = [], []
        if not isinstance(data, dict):
            self.logger.error(
                f"PFUIFW: Message decoded to {type(data).__name__}, not a PFUI "
                f"object. Dropping. Non-PFUI_Unbound sender ?"
            )
            disconnect(proto, self.soc, conn, msg="Invalid datatype")
            return False

        kind = data.get("kind")
        qname = data.get("qname", "")
        if kind not in ("rr", "cache"):
            self.logger.error(
                f"PFUIFW: Message has no valid 'kind' ({kind}), dropping. "
                f"PFUI_Unbound must be running the same release as PFUI_Firewall."
            )
            disconnect(proto, self.soc, conn, msg="Missing kind")
            return False

        try:
            af4_data = extract(data.get("AF4"), version=4)
            af6_data = extract(data.get("AF6"), version=6)
        except Exception:
            self.logger.exception(
                f"PFUIFW: Cannot extract PFUI record from data '{data}' {type(data)}"
            )

        if not af4_data and not af6_data:
            self.logger.error(
                f"PFUIFW: No routable records in {data}. Nothing to act on."
            )
            disconnect(proto, self.soc, conn, msg="No records")
            return False

        if proto == "UDP":
            # Post-validation, so an unvalidated datagram cannot elicit a reply
            try:
                self.soc.sendto(b"ACKDATA", (ip, port))
            except Exception:
                self.logger.exception(f"PFUIFW: Failed to ACKDATA {peer}")

        if self.stats:
            vtime = time()

        # Update PF Tables
        if af4_data:
            table_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                cfg=self.cfg,
                af=AF_INET,
                table=self.cfg["AF4_TABLE"],
                ip_list=[x[0] for x in af4_data],
            )
        if af6_data:
            table_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                cfg=self.cfg,
                af=AF_INET6,
                table=self.cfg["AF6_TABLE"],
                ip_list=[x[0] for x in af6_data],
            )

        if self.cfg["LOGGING"]:
            self.logger.info(f"PFUIFW: PF Table updated {af4_data}, {af6_data}")
        if self.stats:
            ttime = time()

        # Unblock PFUI_Unbound DNS Client
        disconnect(proto, self.soc, conn, msg="ACKUPDATE")

        if self.stats:
            n1time = time()

        # Update Redis DB
        if af4_data:  # Always update Redis DB
            db_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                db=self.db,
                table=self.cfg["AF4_TABLE"],
                data=af4_data,
                kind=kind,
                qname=qname,
                cfg=self.cfg,
            )
        if af6_data:
            db_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                db=self.db,
                table=self.cfg["AF6_TABLE"],
                data=af6_data,
                kind=kind,
                qname=qname,
                cfg=self.cfg,
            )

        if self.stats:
            rtime = time()

        # Update PF Table Persist Files
        if af4_data:  # Update if new records
            file_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                file=self.cfg["AF4_FILE"],
                ip_list=[x[0] for x in af4_data],
            )
        if af6_data:
            file_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                file=self.cfg["AF6_FILE"],
                ip_list=[x[0] for x in af6_data],
            )

        # Print statistics; one structured line, so DEBUG stays affordable
        if self.stats:
            etime = time()
            self.logger.info(
                "PFUIFW: latency microsecs "
                "network={0:.2f} check={1:.2f} pf={2:.2f} ack={3:.2f} "
                "client_block={4:.2f} redis={5:.2f} file={6:.2f} total={7:.2f}".format(
                    (ntime - stime) * (10**6),
                    (vtime - ntime) * (10**6),
                    (ttime - vtime) * (10**6),
                    (n1time - ttime) * (10**6),
                    (n1time - stime) * (10**6),
                    (rtime - n1time) * (10**6),
                    (etime - rtime) * (10**6),
                    (etime - stime) * (10**6),
                )
            )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Syntax: {} {{start|stop|kill|restart|check}}".format(sys.argv[0]))
        exit(1)

    cmd = sys.argv[1].lower()
    # /var/run is root-owned; rc_pre creates this directory for the daemon user
    service = PFUI_Firewall("pfui_firewall", pid_dir="/var/run/pfui")

    if cmd == "start":
        if not service.is_running():
            service.start()
            sleep(1)
        if service.is_running():
            print("PFUI_Firewall started.")
            exit(0)
        else:
            exit(1)

    elif cmd == "stop":
        if service.is_running():
            service.stop()
        if not service.is_running():
            print("PFUI_Firewall stopped.")
            exit(0)
        else:
            exit(1)

    elif cmd == "kill":
        try:
            service.kill()
        except ValueError:
            print("PFUI_Firewall is not running.")
        if not service.is_running():
            exit(0)
        else:
            exit(1)

    elif cmd == "restart":
        while service.is_running():
            print("PFUI_Firewall is stopping.")
            service.stop()
            sleep(1)
        service.start()
        if service.is_running():
            print("PFUI_Firewall started.")
            exit(0)
        else:
            exit(1)

    elif cmd == "status" or cmd == "check":
        if service.is_running():
            print("PFUI_Firewall is running.")
            exit(0)
        else:
            print("PFUI_Firewall is not running.")
            exit(1)
    else:
        sys.exit('Unknown command "%s".' % cmd)
