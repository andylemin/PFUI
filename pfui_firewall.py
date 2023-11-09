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

import errno
import logging
import subprocess
import sys
from ctypes import *
from fcntl import LOCK_EX, LOCK_NB, LOCK_UN, flock, ioctl
from json import loads
from logging.handlers import SysLogHandler
from os import rename
from threading import Event, Thread
from time import sleep, time

import lz4.frame
from redis import StrictRedis
from service import Service, find_syslog
from yaml import safe_load

from socket import AF_INET, AF_INET6, SOCK_DGRAM, SO_REUSEADDR, SOL_SOCKET, SO_SNDBUF
from socket import SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY, AddressFamily
from socket import error as socket_error, timeout as socket_timeout
from socket import socket, inet_aton, inet_pton

CONFIG_LOCATION = "/etc/pfui_firewall.yml"

# Constants
IFNAMSIZ = 16  # From /usr/include/net/if.h
PF_TABLE_NAME_SIZE = 32  # From /usr/include/net/pfvar.h
PATH_MAX = 1024  # From /usr/include/sys/syslimits.h
PFRKE_PLAIN = 0  # pfrke type (from /usr/include/net/pfvar.h)

# Table flags (from /usr/include/net/pfvar.h)
PFR_TFLAG_PERSIST = 0x01
PFR_TFLAG_CONST = 0x02
PFR_TFLAG_ACTIVE = 0x04
PFR_TFLAG_INACTIVE = 0x08
PFR_TFLAG_REFERENCED = 0x10
PFR_TFLAG_REFDANCHOR = 0x20
PFR_TFLAG_COUNTERS = 0x40
PFR_TFLAG_USRMASK = 0x43
PFR_TFLAG_SETMASK = 0x3C
PFR_TFLAG_ALLMASK = 0x7F

# ioctl() operations
IOCPARM_MASK = 0x1FFF
IOC_OUT = 0x40000000
IOC_IN = 0x80000000
IOC_INOUT = IOC_IN | IOC_OUT


# C Structures
class pfr_table(Structure):  # From /usr/include/net/pfvar.h
    """Data class to create pfr_table struct"""

    _fields_ = [
        ("pfrt_anchor", c_char * PATH_MAX),
        ("pfrt_name", c_char * PF_TABLE_NAME_SIZE),
        ("pfrt_flags", c_uint32),
        ("pfrt_fback", c_uint8),
    ]


class pfioc_table(Structure):  # From /usr/include/net/pfvar.h
    """Data class to create pfioc_table struct, holds pfr_table struct with pfr_addr structs"""

    _fields_ = [
        ("pfrio_table", pfr_table),  # Set target PF Table attributes
        (
            "pfrio_buffer",
            c_void_p,
        ),  # Pointer to byte array of pfr_addr's (pfrio_size elements)
        ("pfrio_esize", c_int),  # size of struct pfr_addr
        ("pfrio_size", c_int),  # total size of all elements
        ("pfrio_size2", c_int),
        ("pfrio_nadd", c_int),  # Returns number of addresses effectively added
        ("pfrio_ndel", c_int),
        ("pfrio_nchange", c_int),
        ("pfrio_flags", c_int),
        ("pfrio_ticket", c_uint32),
    ]


class pfr_addr(Structure):  # From /usr/include/net/pfvar.h
    """Data class to create pfr_addr struct"""

    class _pfra_u(Union):
        _fields_ = [
            ("pfra_ip4addr", c_uint32),  # struct in_addr
            ("pfra_ip6addr", c_uint32 * 4),
        ]  # struct in6_addr

    _fields_ = [
        ("pfra_u", _pfra_u),
        ("pfra_ifname", c_char * IFNAMSIZ),
        ("pfra_states", c_uint32),
        ("pfra_weight", c_uint16),
        ("pfra_af", c_uint8),
        ("pfra_net", c_uint8),
        ("pfra_not", c_uint8),
        ("pfra_fback", c_uint8),
        ("pfra_type", c_uint8),
        ("pad", c_uint8 * 7),
    ]
    _anonymous_ = ("pfra_u",)


def IOCTL(logger, dev: str, iocmd, af: AddressFamily, table: str, addrs: list):
    """
    Populate a complete pfioc_table Structure with target table and IPs,
    and push struct with Action to /dev/pf ioctl interface.
    """

    def pfr_addr_struct(logger, af: AddressFamily, addr: str):
        """Convert this object to a pfr_addr structure."""
        a = pfr_addr()

        try:
            addr = inet_pton(af, str(addr))  # IP string to packed binary format
            # Copy Addr to v6
            memmove(
                a.pfra_ip6addr, c_char_p(addr), len(addr)
            )  # (dst, <- src, bytes count)
        except Exception as e:
            logger.info(f"Error building struct for ip {addr} {e}")

        a.pfra_af = af
        if af == AF_INET:
            a.pfra_net = 32
        elif af == AF_INET6:
            a.pfra_net = 128
        a.pfra_not = 0
        a.pfra_fback = 0
        a.pfra_ifname = b""
        a.pfra_type = PFRKE_PLAIN
        a.states = 0
        a.pfra_weight = 0
        return a

    # Init pfr_table(Structure); with target table
    table = pfr_table(pfrt_name=table.encode())

    # Populate pfioc_table(Structure); load the pfr_table(Structure) object,
    # set mem size (bytes) of pfr_addr(Structure), set count of pfr_addr instances
    io = pfioc_table(
        pfrio_table=table, pfrio_esize=sizeof(pfr_addr), pfrio_size=len(addrs)
    )

    # Build list of populated pfr_addr(Structure)'s;
    _addrs = []
    for _addr in addrs:
        _addrs.append(pfr_addr_struct(logger, af, _addr))

    # Populate buffer byte-array of pfr_addr's (echo containing at least pfrio_size elements to add to the table)
    buffer = (pfr_addr * len(addrs))(*[a for a in _addrs])

    # Populate pfioc_table(Structure); set pointer to buffer containing pfr_addr byte array
    io.pfrio_buffer = addressof(buffer)

    with open(dev, "w") as d:
        ioctl(d, iocmd, io)
    return io.pfrio_nadd  # Successful commits


def _IOWR(group, num, type):
    def _IOC(inout, group, num, len):
        return inout | ((len & IOCPARM_MASK) << 16) | group << 8 | num

    return _IOC(IOC_INOUT, ord(group), num, sizeof(type))


DIOCRADDADDRS = _IOWR("D", 67, pfioc_table)
DIOCRDELADDRS = _IOWR("D", 68, pfioc_table)


def table_push(
    logger, log: bool, cfg: dict, af: AddressFamily, table: str, ip_list: list
):
    """
    Install IP(s) into PF Table, Latency sensitive operation.
    Returns the number of IPs successfully pushed onto table
    """

    def pfctl_add_addr(table, ip_list):
        r = subprocess.run(
            ["pfctl", "-t", table, "-T", "add"] + ip_list, stdout=subprocess.DEVNULL
        )
        if r.returncode != 0:  # Non-zero error codes
            logger.error(f"PFCTL push failed: {r}")
        else:
            return len(ip_list)

    if log:
        logger.info(f"PFUIFW: Adding '{ip_list}' to PF Table {table}")

    if cfg["CTL"] == "IOCTL":
        try:
            return IOCTL(
                logger=logger,
                dev=cfg["DEVPF"],
                iocmd=DIOCRADDADDRS,
                af=af,
                table=table,
                addrs=ip_list,
            )
        except Exception as e:
            logger.error(
                f"PFUIFW: IOCTL Failed to install {ip_list} into PF Table {table}, trying PFCTL. {e}"
            )

    # pfctl cli fallback
    try:
        return pfctl_add_addr(table, ip_list)
    except Exception as e:
        logger.error(
            f"PFUIFW: PFCTL Failed to install {ip_list} into PF Table {table}. {e}"
        )
        return 0


def table_pop(
    logger, log: bool, cfg: dict, af: AddressFamily, table: str, ip_list: list
):
    """
    Remove IP(s) from PF Table.
    Returns the number of IPs successfully popped from table
    """

    def pfctl_del_addr(table, ip_list):
        r = subprocess.run(
            ["pfctl", "-t", table, "-T", "delete"] + ip_list, stdout=subprocess.DEVNULL
        )
        if r.returncode != 0:  # Non-zero error codes
            logger.error(f"PFCTL pop failed: {r}")
        else:
            return 1

    if log:
        logger.info(f"PFUIFW: Clearing '{ip_list}' from PF Table {table}")

    if cfg["CTL"] == "IOCTL":
        try:
            return IOCTL(
                logger=logger,
                dev=cfg["DEVPF"],
                iocmd=DIOCRDELADDRS,
                af=af,
                table=table,
                addrs=ip_list,
            )

        except Exception as e:
            logger.error(
                f"PFUIFW: IOCTL Failed to delete {ip_list} from PF Table {table}, trying PFCTL. {e}"
            )
    try:
        return pfctl_del_addr(table, ip_list)
    except Exception as e:
        logger.error(
            f"PFUIFW: PFCTL Failed to delete {ip_list} from PF Table {table}. {e}"
        )
        return 0


def db_push(logger, log: bool, db, table: str, data: list):
    """Store IP(s) and metadata to Redis database table"""

    if log:
        logger.info(f"PFUIFW: Storing '{data}' to Redis")

    try:
        pipe = db.pipeline()
        now = int(time())
        for ip, ttl, qname in data:
            key = f"{table}^{ip}"
            if ttl < 604800:  # DNS TTL from RR, else Unbound cache expire tstamp
                if ttl < 3600:
                    ttl = 3600  # min ttl = 1 hour
                pipe.hmset(key, {"epoch": now, "ttl": ttl, "qname": qname})
            else:  # Cached result; TTL = Expiry time (dont overwrite ttl), update 'epoch' and 'expires'
                pipe.hmset(key, {"epoch": now, "expires": ttl, "qname": qname})
        pipe.execute()
        return True
    except:
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
    except:
        logger.exception(f"PFUIFW: Failed to delete {ip_list} from Redis")
        return False


def file_push(logger, log: bool, file: str, ip_list: list):
    """Add IP(s) to PF Table's File"""
    if log:
        logger.info(f"PFUIFW: Adding '{ip_list}' to PF Table File {file}")

    unique = []
    try:
        with open(file, "r+") as f:  # Reading and writing with pointer at beginning
            # Read file without lock
            lines = f.readlines()
            missing = [
                f"{ip}\n" for ip in ip_list if f"{ip}\n" not in lines
            ]  # Check not exists

            if missing:  # Get exclusive file lock
                while True:
                    try:
                        flock(f, LOCK_EX | LOCK_NB)
                        break
                    except IOError as e:
                        if e.errno != errno.EAGAIN:
                            raise  # raise other file access issues
                        else:
                            if log:
                                logger.info(
                                    f"PFUIFW: PF Table File {file} already Locked. Waiting 2ms"
                                )
                            sleep(0.01)  # Wait 2ms
                try:
                    f.write("".join(missing))  # append lines
                except Exception as e:
                    logger.exception(f"PFUIFW: f.write exception: {e}")
                flock(f, LOCK_UN)
        return True
    except:
        logger.exception(f"PFUIFW: Failed to append {ip_list} to {file}.")
        return False


def file_pop(logger, log: bool, file: str, ip_list: list):
    """Remove IP from PF Table's File"""

    if log:
        logger.info(f"PFUIFW: Clearing '{ip_list}' from PF Table File {file}")

    try:
        to_del = [f"{ip}\n" for ip in ip_list] + [""]
        tmp_file = file + str(int(time()))
        with open(file, "r") as f, open(tmp_file, "w") as tmp:
            # Read all lines not matching IP(s) to exclude
            lines = [ip for ip in f if ip not in to_del]
            lines = sorted(list(set(lines)))

            # Copy on Write safety. Save to tmp file, lock and swap
            tmp.writelines(lines)
            while True:  # Set lock - blocking
                try:
                    flock(f, LOCK_EX | LOCK_NB)
                    break
                except IOError as e:
                    if e.errno != errno.EAGAIN:
                        raise  # raise other file access issues
                    else:
                        if log:
                            logger.info(
                                f"PFUIFW: PF Table File {file} already Locked. Waiting 2ms"
                            )
                        sleep(0.002)  # Wait 2ms
            rename(tmp_file, file)
            flock(f, LOCK_UN)
    except:
        logger.exception(f"PFUIFW: Failed to delete IP(s) {ip_list} from {file}")
        return False


def is_ipv4(address: str):
    try:
        inet_pton(AF_INET, address)
    except AttributeError:  # pton not found, use slower aton
        try:
            inet_aton(address)
        except socket_error:
            return False
    except socket_error:  # not a valid address
        return False
    return address


def is_ipv6(address: str):
    try:
        inet_pton(AF_INET6, address)
    except socket_error:  # not a valid address
        return False
    return address


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
        super().join()

    def run(self):
        """Start Scanner loop"""

        class Break(Exception):
            pass

        try:
            while not self.stop_event.is_set():
                # Clean Redis
                self.scan_redis_db()
                # Read Redis for sync
                keys = self.db.keys(f"{self.table}*")
                self.sync_pf_table(keys=keys)
                self.sync_pf_file(keys=keys)
                for _ in range(int(self.cfg["SCAN_PERIOD"])):
                    if self.stop_event.is_set():
                        raise Break
                    sleep(1)
        except Break:
            self.logger.info(f"PFUIFW: [-] Sync thread closing for {self.table}")
        except Exception as e:
            self.logger.exception(f"PFUIFW: Sync thread died for {self.table}! {e}")

    def scan_redis_db(self):
        """Expire IPs with last update epoch/timestamp older than (TTL * TTL_MULTIPLIER)."""

        if self.cfg["LOGGING"]:
            self.logger.info(
                f"PFUIFW: Scan DB({self.cfg['REDIS_DB']}) for expiring {self.table} IPs."
            )

        try:
            keys = self.db.keys(f"{self.table}*")
        except:
            self.logger.exception("PFUIFW: Failed to get keys from Redis.")
            return

        now = int(time())
        expired_ips = []
        for k in keys:
            # Check key is expired
            db_last, db_ttl, db_expires = 0, 0, None
            v = None
            try:
                v = self.db.hgetall(k)
                db_last = int(v[b"epoch"].decode("utf-8"))
                db_ttl = int(v[b"ttl"].decode("utf-8"))
            except KeyError as e:
                self.logger.error(
                    f"PFUIFW: Metadata not found! k={k} Trying 'expires' timestamp. {e}"
                )
                try:
                    db_expires = int(v[b"expires"].decode("utf-8"))
                except KeyError as e:
                    self.logger.error(f"PFUIFW: No 'expires' meta found either! {e}")
                if db_expires is None or db_expires <= now:  # Purge
                    db_last, db_ttl = now, 0
            except Exception as e:
                self.logger.error(f"PFUIFW: Exception getting key '{k}' values. {e}")
                db_last, db_ttl = now, 0

            if db_last + (db_ttl * self.cfg["TTL_MULTIPLIER"]) <= now:
                ip = k.decode("utf-8").split("^")[1]
                if self.cfg["LOGGING"]:
                    self.logger.info(f"PFUIFW: TTL Expired for IP {ip}")
                expired_ips.append(ip)

        # Purge if expired
        if expired_ips:
            db_pop(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                db=self.db,
                table=self.table,
                ip_list=expired_ips,
            )

    def sync_pf_table(self, keys=None):
        """
        Sync the Redis table with the PF Table. Uses pfctl rather IOCTL to read PF Table for now until IOCTL show added
        """
        if self.cfg["LOGGING"]:
            self.logger.info(
                f"PFUIFW: Sync PF Table {self.table} with DB({self.cfg['REDIS_DB']})"
            )

        db_ips, t_ips = [], []
        try:
            # Get all Redis IPs
            if keys is None:
                try:
                    keys = self.db.keys(f"{self.table}*")
                except:
                    self.logger.exception("PFUIFW: Failed to get keys from Redis.")
                    return
            db_ips = [k.decode("utf-8").split("^")[1] for k in keys]

            # Get all PF Table IPs - TODO pfctl show is slow, implement IOCTL show.
            entries = list(
                subprocess.Popen(
                    ["pfctl", "-t", self.table, "-T", "show"], stdout=subprocess.PIPE
                ).stdout
            )
            t_ips = [l.decode("utf-8").strip() for l in entries]
        except:
            self.logger.error(
                f"PFUIFW: Failed to read and decode data for {self.table}"
            )

        # Remove expired IPs from pf_table (Redis record purged)
        t_ips_del = [t_ip for t_ip in t_ips if t_ip not in db_ips]
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
        t_ips_add = [db_ip for db_ip in db_ips if db_ip not in t_ips]
        if t_ips_add:
            table_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                cfg=self.cfg,
                af=self.af,
                table=self.table,
                ip_list=t_ips_add,
            )

    def sync_pf_file(self, keys=None):
        """
        Sync the Redis DB with the PF File.
        """
        if self.cfg["LOGGING"]:
            self.logger.info(
                f"PFUIFW: Sync PF File {self.table} with DB({self.cfg['REDIS_DB']})"
            )

        db_ips, f_ips = [], []
        try:
            if keys is None:
                try:
                    keys = self.db.keys(f"{self.table}*")
                except:
                    self.logger.exception("PFUIFW: Failed to get keys from Redis.")
                    return
            db_ips = [k.decode("utf-8").split("^")[1] for k in keys]

            with open(self.file) as f:
                content = f.readlines()
            f_ips = [x.strip() for x in content if x != "\n" or ""]
        except:
            self.logger.error(f"PFUIFW: Failed to read stores for {self.file}")

        # Remove expired IPs from PF Table File (Redis record purged)
        f_ips_del = [f_ip for f_ip in f_ips if f_ip not in db_ips]
        if f_ips_del:
            file_pop(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                file=self.file,
                ip_list=f_ips_del,
            )

        # Add any missing IPs to the PF Table File (Active Redis record)
        f_ips_add = [db_ip for db_ip in db_ips if db_ip not in f_ips]
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
        self.db = None

        # Load YAML Configuration
        try:
            self.cfg = safe_load(open(CONFIG_LOCATION))
            if "LOGGING" not in self.cfg:
                self.cfg["LOGGING"] = True
            if "LOG_LEVEL" not in self.cfg:
                self.cfg["LOG_LEVEL"] = "DEBUG"
            if "SOCKET_LISTEN" not in self.cfg:
                self.cfg["SOCKET_LISTEN"] = "0.0.0.0"
            if "SOCKET_PROTO" not in self.cfg:
                self.cfg["SOCKET_PROTO"] = "TCP"
            if "SOCKET_PORT" not in self.cfg:
                self.cfg["SOCKET_PORT"] = 10001
            if "SOCKET_TIMEOUT" not in self.cfg:
                self.cfg["SOCKET_TIMEOUT"] = 3
            if "SOCKET_BUFFER" not in self.cfg:
                self.cfg["SOCKET_BUFFER"] = 1024
            if "SOCKET_BACKLOG" not in self.cfg:
                self.cfg["SOCKET_BACKLOG"] = 5
            if "COMPRESS" not in self.cfg:
                self.cfg["COMPRESS"] = True
            if "REDIS_HOST" not in self.cfg:
                self.cfg["REDIS_HOST"] = "127.0.0.1"
            if "REDIS_PORT" not in self.cfg:
                self.cfg["REDIS_PORT"] = 6379
            if "REDIS_DB" not in self.cfg:
                self.cfg["REDIS_DB"] = 1024
            if "SCAN_PERIOD" not in self.cfg:
                self.cfg["SCAN_PERIOD"] = 60
            if "TTL_MULTIPLIER" not in self.cfg:
                self.cfg["TTL_MULTIPLIER"] = 2
            if "CTL" not in self.cfg:
                self.cfg["CTL"] = "IOCTL"
            if "DEVPF" not in self.cfg:
                self.cfg["DEVPF"] = "/dev/pf"
            if "AF4_TABLE" not in self.cfg:
                print(
                    "AF4_TABLE (PF Table) not found in YAML Config File. Please configure. Exiting."
                )
                sys.exit(2)
            if "AF4_FILE" not in self.cfg:
                print(
                    "AF4_FILE (PF Persist file) not found in YAML Config File. Please configure. Exiting."
                )
                sys.exit(2)
            if "AF6_TABLE" not in self.cfg:
                print(
                    "AF6_TABLE (PF Table) not found in YAML Config File. Please configure. Exiting."
                )
                sys.exit(2)
            if "AF6_FILE" not in self.cfg:
                print(
                    "AF6_FILE (PF Persist file) not found in YAML Config File. Please configure. Exiting."
                )
                sys.exit(2)
        except Exception as e:
            print(f"YAML Config File not found or cannot load. {e}")
            sys.exit(2)

        # Init Logging
        self.logger.addHandler(
            SysLogHandler(address=find_syslog(), facility=SysLogHandler.LOG_DAEMON)
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
        except:
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
        except:
            self.logger.exception("PFUIFW: Scanning thread failed.")
            sys.exit(4)
        self.logger.info("PFUIFW: [+] PFUI_Firewall Service Started.")

        # Listen for connections
        # Default TCP time_wait = 60; 64000 / 60 = 1,066qps
        # sysctl net.inet.tcp.keepidle=10; 64000 / 10 = 6,400qps
        if self.cfg["SOCKET_PROTO"] == "TCP":
            self.conn = socket(AF_INET, SOCK_STREAM)  # TCP Stream Socket
            self.conn.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)  # Disable Nagle
            # self.conn.setsockopt(socket.SOL_TCP, 23, 5)
            # 23 = TCP_FASTOPEN, 5 = Max TFO queue (not yet supported in OpenBSD)
            self.conn.setsockopt(
                SOL_SOCKET, SO_REUSEADDR, True
            )  # Fast Listen Socket reuse
            self.conn.setsockopt(
                SOL_SOCKET, SO_SNDBUF, 0
            )  # Zero-size send Buffer (Send immediately)
            self.conn.settimeout(
                self.cfg["SOCKET_TIMEOUT"]
            )  # accept() connection timeout to check TERM
            self.conn.bind((self.cfg["SOCKET_LISTEN"], self.cfg["SOCKET_PORT"]))
            self.conn.listen(self.cfg["SOCKET_BACKLOG"])

            while not self.got_sigterm():  # Watch Socket until TERM
                try:
                    # Start receive thread for each received update
                    conn, (ip, port) = self.conn.accept()  # Waits self.conn.settimeout
                    try:
                        Thread(
                            target=self.receiver_thread,
                            kwargs={
                                "proto": "TCP",
                                "conn": conn,
                                "ip": ip,
                                "port": port,
                            },
                        ).start()
                    except:
                        self.logger.exception("PFUIFW: Error starting receiver thread")
                except socket_timeout:
                    continue

        # TODO UDP support is not recommended (experimental) as Unbound Python Module is executed every lookup,
        #  generating new connection for each lookup. With UDP defaults, this results in ~213qps
        elif self.cfg["SOCKET_PROTO"] == "UDP":
            # setup listen socket
            self.soc = socket(AF_INET, SOCK_DGRAM)  # UDP Datagram Socket
            self.soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, True)
            self.soc.setsockopt(SOL_SOCKET, SO_SNDBUF, 36)  # 'ACK' = 36bytes
            self.soc.settimeout(
                self.cfg["SOCKET_TIMEOUT"]
            )  # recvfrom() data timeout to check TERM
            self.soc.bind((self.cfg["SOCKET_LISTEN"], self.cfg["SOCKET_PORT"]))

            while not self.got_sigterm():  # Watch Socket until TERM
                try:
                    dgram, (ip, port) = self.soc.recvfrom(1400)
                    # ACK PFUI_Unbound (UDP)
                    self.soc.sendto(b"ACKDATA", (ip, port))
                    self.logger.info(f"PFUIFW: Sent 'ACKDATA' to {(ip, port)}")
                except socket_timeout:
                    continue
                except socket_error:
                    continue
                except Exception as e:
                    self.logger.exception(f"PFUIFW: UDP socket exception {e}")
                    sleep(0.5)
                    continue

                if dgram:  # Start receive thread for each received update
                    try:
                        Thread(
                            target=self.receiver_thread,
                            kwargs={
                                "proto": "UDP",
                                "dgram": dgram,
                                "ip": ip,
                                "port": port,
                            },
                        ).start()
                    except:
                        self.logger.exception("PFUIFW: Error in receiver thread")

        # Shut down
        for t in self.threads:
            t.join()
        self.db.close()
        self.logger.info("PFUIFW: [-] PFUI_Firewall Service Stopped.")

    def receiver_thread(self, proto, conn=None, dgram=None, ip=None, port=None):
        """Receive all data, update PF Table and Redis DB
        Data Structure:
        {'AF4': [{"ip": ipv4_addr, "ttl": ip_ttl, 'qname': qname}], 'AF6': [{"ip": ipv6_addr, "ttl": ip_ttl, 'qname': qname}]}
        For performance, we want entire message sent in a single segment, with small socket buffers (no delay).
        Ensure SOCKET_BUFFER is small, but large enough for maximum expected record size.
        """

        def disconnect(proto, soc, conn, msg):
            if msg:
                msg = msg.encode("utf-8")
            else:
                msg = b"ACK"

            self.logger.info(f"PFUIFW: Close msg: {msg}")

            if proto == "UDP":
                try:
                    soc.sendto(msg, (ip, port))
                except:
                    pass  # PFUI_Unbound may have closed socket already (non-blocking cache responses)
                # Do not soc.close(), as this stop listening socket
            elif proto == "TCP":
                try:
                    conn.sendall(msg)
                except:
                    pass  # PFUI_Unbound may have closed connection already (non-blocking cache responses)
                finally:
                    conn.close()

        if self.cfg["LOGGING"]:
            stime = time()

        # Read data from network
        data = None
        if proto == "TCP":
            chunks, stream = [], b""
            while True:  # Receive all TCP stream chunks and build contiguous data
                try:
                    payload = conn.recv(int(self.cfg["SOCKET_BUFFER"]))
                    if payload:
                        chunks.append(payload)
                        stream = b"".join(
                            chunks[-2:]
                        )  # 'EOT' Footer may cross last chunk boundary
                        if stream[-3:] == b"EOT":  # End of Transmission
                            try:
                                stream = stream[:-3]  # Drop EOT
                                if self.cfg["COMPRESS"]:  # Decompress
                                    stream = lz4.frame.decompress(stream)
                                data = loads(stream)  # Load JSON
                                break
                            except:
                                self.logger.exception(
                                    f"PFUIFW: Failed to decode stream, disconnecting {ip}:{port}: '{stream}'"
                                )
                                disconnect(
                                    proto, self.soc, conn, msg="Failed to decode"
                                )
                                return
                    else:
                        self.logger.error(
                            f"PFUIFW: Empty payload, disconnecting {ip}:{port}"
                        )
                        disconnect(proto, self.soc, conn, msg="Empty payload")
                        return
                except socket_timeout:
                    self.logger.error(f"PFUIFW: Socket recv timeout {ip}:{port}")
                    break

        elif proto == "UDP":
            try:
                if self.cfg["COMPRESS"]:
                    dgram = lz4.frame.decompress(dgram)
                data = loads(dgram)
            except:
                self.logger.exception(
                    f"PFUIFW: Failed to decode datagram {ip}:{port} {dgram}"
                )
                disconnect(proto, self.soc, conn, "Failed to decode")
                return

        if self.cfg["LOGGING"]:
            ntime = time()
            self.logger.info(f"PFUIFW: Received {data} from {ip}:{port} ({proto})")

        # Input Request
        af4_data, af6_data = [], []
        if isinstance(data, dict):
            try:
                af4_data = [
                    (rr["ip"], int(rr["ttl"]), rr.get("qname"))
                    for rr in data.get("AF4")
                    if is_ipv4(rr.get("ip")) and rr.get("ttl")
                ]
                af6_data = [
                    (rr["ip"].lower(), int(rr["ttl"]), rr.get("qname"))
                    for rr in data.get("AF6")
                    if is_ipv6(rr.get("ip")) and rr.get("ttl")
                ]
            except:
                self.logger.exception(
                    f"PFUIFW: Cannot extract PFUI record from data '{data}' {type(data)}"
                )
        else:
            self.logger.error(f"PFUIFW: No data in message. Dropping message")
            disconnect(proto, self.soc, conn, msg="No data")
            return False

        if not af4_data and not af6_data:
            self.logger.error(
                f"PFUIFW: Invalid datatype received {data} {type(data)}. Non-PFUI_Unbound datagram ?"
            )
            disconnect(proto, self.soc, conn, msg="Invalid datatype")
            return False

        if self.cfg["LOGGING"]:
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
            ttime = time()

        # Unblock PFUI_Unbound DNS Client
        disconnect(proto, self.soc, conn, msg="ACKUPDATE")

        if self.cfg["LOGGING"]:
            n1time = time()

        # Update Redis DB
        if af4_data:  # Always update Redis DB
            db_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                db=self.db,
                table=self.cfg["AF4_TABLE"],
                data=af4_data,
            )
        if af6_data:
            db_push(
                logger=self.logger,
                log=self.cfg["LOGGING"],
                db=self.db,
                table=self.cfg["AF6_TABLE"],
                data=af6_data,
            )

        if self.cfg["LOGGING"]:
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

        # Print statistics
        if self.cfg["LOGGING"]:
            etime = time()
            tntime = (ntime - stime) * (10**6)  # Network Receive Time
            tvtime = (vtime - ntime) * (10**6)  # Data Validation Time
            tptime = (ttime - vtime) * (10**6)  # PF Table Write Time
            tn1time = (n1time - ttime) * (10**6)  # Network Acknowledge Time
            tcbtime = (n1time - stime) * (10**6)  # Approximate client block Time
            trtime = (rtime - n1time) * (10**6)  # Redis Update Time
            tftime = (etime - rtime) * (10**6)  # File Update Time
            ttime = (etime - stime) * (10**6)  # Total Time
            self.logger.info("PFUIFW: Network Latency {0:.2f} microsecs".format(tntime))
            self.logger.info(
                "PFUIFW: Data Check Latency {0:.2f} microsecs".format(tvtime)
            )
            self.logger.info(
                "PFUIFW: PF Update Latency {0:.2f} microsecs".format(tptime)
            )
            self.logger.info("PFUIFW: ACK Latency {0:.2f} microsecs".format(tn1time))
            self.logger.info(
                "PFUIFW: Client block time {0:.2f} microsecs".format(tcbtime)
            )
            self.logger.info("PFUIFW: Redis Latency {0:.2f} microsecs".format(trtime))
            self.logger.info("PFUIFW: File Latency {0:.2f} microsecs".format(tftime))
            self.logger.info("PFUIFW: Total Latency {0:.2f} microsecs".format(ttime))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Syntax: {} {{start|stop|kill|restart|check}}".format(sys.argv[0]))
        exit(1)

    cmd = sys.argv[1].lower()
    service = PFUI_Firewall("pfui_firewall", pid_dir="/var/run")

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

    elif cmd == "restart" or cmd == "reload":
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
