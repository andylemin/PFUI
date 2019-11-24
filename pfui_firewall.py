#!/usr/bin/env python3
"""
    The server daemon (pfui_firewall.py) receives (from pfui_unbound.py) all successfully resolved (by Unbound) domains,
      and installs the resolved IPs into local "PF Tables" (v4 & v6), to facilitate traffic filtering with PF.
      `pfctl -t pfui_ipv4_domains -T [add|show|delete]` https://www.openbsd.org/faq/pf/tables.html

    DNS Resource Record (A & AAAA) age (last query timestamp) and max-age (TTL) are tracked using Redis, and IPs are
      expired from the PF Tables (blocked again) when the last query is older than "EPOCH - (TTL * TTL_MULTIPLIER)".

    The most common PFUI use case blocks all egress traffic by default, allowing egress traffic only for the
      corporate/internal Unbound DNS servers. Therefore;
      Any direct outbound connections without a prior DNS lookup will fail..
      Effectively blocks DoH (DNS over HTTPS), forcing clients to use the internal Unbound DNS servers (pfui_unbound).
      Enforces compliance with corporate DNS-BlackLists for all hosts on the network (including private BYODs).

    This approach blocks most Botnets, Malware, and Randsomware by blocking their Command & Control and Spreading.
    pfctl -t pfui_ipv4_domains -T [add|show|delete]

    The PF Table interface supports expiring old entries (pfctl -t pfui_ipv4_domains -T expire 3600), however
    subsequent queries/updates do _not_ refresh the cleared timestamp. Therefore Redis used to track entries.
    ioctl (pfctl) calls implemented DIOCRADDADDRS, DIOCRDELADDRS (OpenBSD).
    https://man.openbsd.org/ioctl.2 https://docs.python.org/2/library/fcntl.html
"""

import ast
import sys
import errno
import socket
import logging
import subprocess

from os import rename

from ctypes import *
from fcntl import ioctl, flock, LOCK_EX, LOCK_NB, LOCK_UN

from time import sleep, time
from json import loads
from yaml import safe_load
from redis import StrictRedis

from threading import Thread, Event
from service import find_syslog, Service
from logging.handlers import SysLogHandler


CONFIG_LOCATION = "/etc/pfui_firewall.yml"

# Constants
IFNAMSIZ             = 16               # From /usr/include/net/if.h
PF_TABLE_NAME_SIZE   = 32               # From /usr/include/net/pfvar.h
PATH_MAX             = 1024             # From /usr/include/sys/syslimits.h
PFRKE_PLAIN          = 0             # pfrke type (from /usr/include/net/pfvar.h)

# Table flags (from /usr/include/net/pfvar.h)
PFR_TFLAG_PERSIST    = 0x01
PFR_TFLAG_CONST      = 0x02
PFR_TFLAG_ACTIVE     = 0x04
PFR_TFLAG_INACTIVE   = 0x08
PFR_TFLAG_REFERENCED = 0x10
PFR_TFLAG_REFDANCHOR = 0x20
PFR_TFLAG_COUNTERS   = 0x40
PFR_TFLAG_USRMASK    = 0x43
PFR_TFLAG_SETMASK    = 0x3C
PFR_TFLAG_ALLMASK    = 0x7F

# ioctl() operations
IOCPARM_MASK         = 0x1fff
IOC_OUT              = 0x40000000
IOC_IN               = 0x80000000
IOC_INOUT            = IOC_IN | IOC_OUT


# C Structures
class pfr_table(Structure):     # From /usr/include/net/pfvar.h
    _fields_ = [("pfrt_anchor",       c_char * PATH_MAX),
                ("pfrt_name",         c_char * PF_TABLE_NAME_SIZE),
                ("pfrt_flags",        c_uint32),
                ("pfrt_fback",        c_uint8)]


class pfioc_table(Structure):   # From /usr/include/net/pfvar.h
    _fields_ = [("pfrio_table",       pfr_table),  # Set target PF Table attributes
                ("pfrio_buffer",      c_void_p),  # Pointer to byte array of pfr_addr's (pfrio_size elements)
                ("pfrio_esize",       c_int),  # size of struct pfr_addr
                ("pfrio_size",        c_int),  # total size of all elements
                ("pfrio_size2",       c_int),
                ("pfrio_nadd",        c_int),  # Returns number of addresses effectively added
                ("pfrio_ndel",        c_int),
                ("pfrio_nchange",     c_int),
                ("pfrio_flags",       c_int),
                ("pfrio_ticket",      c_uint32)]


class pfr_addr(Structure):      # From /usr/include/net/pfvar.h
    class _pfra_u(Union):
        _fields_ = [("pfra_ip4addr",  c_uint32),      # struct in_addr
                    ("pfra_ip6addr",  c_uint32 * 4)]  # struct in6_addr

    _fields_ = [("pfra_u",            _pfra_u),
                ("pfra_ifname",       c_char * IFNAMSIZ),
                ("pfra_states",       c_uint32),
                ("pfra_weight",       c_uint16),
                ("pfra_af",           c_uint8),
                ("pfra_net",          c_uint8),
                ("pfra_not",          c_uint8),
                ("pfra_fback",        c_uint8),
                ("pfra_type",         c_uint8),
                ("pad",               c_uint8 * 7)]
    _anonymous_ = ("pfra_u",)


def IOCTL(logger, dev: str, iocmd, af: socket.AddressFamily, table: str, addrs: list):
    """ Populate complete pfioc_table(Structure) with table and IPs,
    and write with given command to /dev/pf ioctl interface. """

    def pfr_addr_struct(logger, af: socket.AddressFamily, addr: str):
        """Convert this instance to a pfr_addr structure."""
        a = pfr_addr()

        try:
            addr = socket.inet_pton(af, str(addr))  # IP string format to packed binary format
            memmove(a.pfra_ip6addr, c_char_p(addr), len(addr))  # (dst, src, count)
        except Exception as e:
            logger.info("Error building struct for ip {} {}".format(addr, e))

        a.pfra_af = af
        if af == socket.AF_INET:
            a.pfra_net = 32
        elif af == socket.AF_INET6:
            a.pfra_net = 128
        a.pfra_not = 0
        a.pfra_fback = 0
        a.pfra_ifname = b""
        a.pfra_type = PFRKE_PLAIN
        a.states = 0
        a.pfra_weight = 0
        return a

    # Populate pfr_table(Structure); with target table
    table = pfr_table(pfrt_name=table.encode())

    # Populate pfioc_table(Structure); load the pfr_table(Structure) object,
    # set mem size (bytes) of pfr_addr(Structure), set count of pfr_addr instances
    io = pfioc_table(pfrio_table=table, pfrio_esize=sizeof(pfr_addr), pfrio_size=len(addrs))

    # Build list of populated pfr_addr(Structure)'s;
    _addrs = []
    for _addr in addrs:
        _addrs.append(pfr_addr_struct(logger, af, _addr))

    # Populate byte array of pfr_addr's (containing at least pfrio_size elements to add to the table)
    buffer = (pfr_addr * len(addrs))(*[a for a in _addrs])

    # Populate pfioc_table(Structure); set pointer to buffer containing pfr_addr byte array
    io.pfrio_buffer = addressof(buffer)

    with open(dev, 'w') as d:
        ioctl(d, iocmd, io)
    return io.pfrio_nadd  # Successful commits


def _IOWR(group, num, type):
    def _IOC(inout, group, num, len):
        return inout | ((len & IOCPARM_MASK) << 16) | group << 8 | num
    return _IOC(IOC_INOUT, ord(group), num, sizeof(type))


DIOCRADDADDRS = _IOWR('D', 67, pfioc_table)
DIOCRDELADDRS = _IOWR('D', 68, pfioc_table)


def table_push(logger, log: bool, cfg: dict, af: socket.AddressFamily, table: str, ip_list: list):

    def pfctl_add(table, ip_list):
        r = subprocess.run(["pfctl", "-t", table, "-T", "add"] + ip_list, stdout=subprocess.DEVNULL)
        if r.returncode != 0:  # Non-zero error codes
            logger.error("Could not install {} into {}".format(ip_list, table))
        else:
            return 1

    if log:
        logger.info("PFUIFW: Installing {} into table {}".format(ip_list, table))
    try:
        if cfg['CTL'] == "IOCTL":
            try:
                r = IOCTL(logger, cfg['DEVPF'], DIOCRADDADDRS, af, table, ip_list)
            except Exception as e:
                logger.error("PFUIFW: IOCTL Failed to install {} into {}, trying PFCTL. {}".format(ip_list, table, e))
                r = pfctl_add(table, ip_list)
        else:
            r = pfctl_add(table, ip_list)
        return r
    except Exception as e:
        logger.error("PFUIFW: Failed to install {} into table {}. {}".format(ip_list, table, e))
        return False


def table_pop(logger, log: bool, cfg: dict, af: socket.AddressFamily, table: str, ip: str):
    if log:
        logger.info("PFUIFW: Clearing {} from table {}".format(ip, table))
    try:
        if cfg['CTL'] == "IOCTL":
            r = IOCTL(logger, cfg['DEVPF'], DIOCRDELADDRS, af, table, [ip])
        elif cfg['CTL'] == "PFCTL":
            r = subprocess.run(["pfctl", "-t", table, "-T", "delete", ip], stdout=subprocess.DEVNULL)
            if r.returncode != 0:
                logger.error("Could not clear {} from {}".format(ip, table))
            else:
                return 1
        return r  # Successful commits
    except Exception as e:
        logger.error("PFUIFW: Failed to delete {} from table {}. {}".format(ip, table, e))
        return False


def db_push(logger, log: bool, db, table: str, data: list):
    if log:
        logger.info("PFUIFW: Installing {} into Redis DB".format(data))
    now = int(time())
    try:
        pipe = db.pipeline()
        for ip, ttl in data:
            key = "{}{}{}".format(table, "^", ip)
            if ttl < now:  # Real TTL
                if ttl < 3600:  # Always allow for min 1 hour
                    ttl = 3600
                pipe.hmset(key, {'epoch': now, 'ttl': ttl})
            else:  # Cached entry TTL = Future Expiry Epoch
                pipe.hmset(key, {'epoch': now, 'expires': ttl})
        pipe.execute()
        return True
    except Exception as e:
        logger.error("PFUIFW: Failed to install {} as {} into Redis DB. {}".format(ip, key, e))
        return False


def db_pop(logger, log: bool, db, table: str, ip: str):
    if log:
        logger.info("PFUIFW: Clearing {} from Redis DB".format(ip, db))
    try:
        db.delete("{}{}{}".format(table, "^", ip))
        return True
    except Exception as e:
        logger.error("PFUIFW: Failed to delete {} from Redis DB. {}".format(ip, e))
        return False


def file_push(logger, log: bool, file: str, ip_list: list):
    if log:
        logger.info("PFUIFW: Installing {} into file {}".format(ip_list, file))
    unique = []
    try:
        with open(file, "r+") as f:  # Open for reading and writing with pointer at beginning
            while True:
                try:
                    flock(f, LOCK_EX | LOCK_NB)
                    break
                except IOError as e:
                    if e.errno != errno.EAGAIN:
                        raise  # raise other file access issues
                    else:
                        if log:
                            logger.info("PFUIFW: File {} Locked.".format(file))
                        sleep(0.001)  # 1ms
            lines = f.readlines()
            unique = ["{}\n".format(ip) for ip in ip_list if "{}\n".format(ip) not in lines]  # Check not exists
            try:
                f.write("".join(unique))  # append new
            except Exception as e:
                logger.error("PFUIFW: f.write error {}".format(e))
            flock(f, LOCK_UN)
        return True
    except Exception as e:
        logger.error("PFUIFW: Failed to install {} to file {}. {}".format(unique, file, e))
        return False


def file_pop(logger, log: bool, file: str, ip: str):
    # TODO: Implement multiple parallel deletes to reduce disk IO (requires rework of Scanner)
    if log:
        logger.info("PFUIFW: Clearing {} from file {}".format(ip, file))
    try:
        with open(file, "r") as f, open(file + "~", "w") as tmp:
            lines = [l for l in f if l not in ["{}\n".format(ip), ""]]
            lines = list(dict.fromkeys(lines))  # Strip dups
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
                            logger.info("PFUIFW: File {} Locked.".format(file))
                        sleep(0.001)  # 1ms
            rename(file + "~", file)
            flock(f, LOCK_UN)
    except Exception as e:
        logger.error("PFUIFW: Failed to delete IP {} from {}. {}".format(ip, file, e))
        return False


def is_ipv4(address: str):
    try:
        socket.inet_pton(socket.AF_INET, address)
    except AttributeError:  # no inet_pton
        try:
            socket.inet_aton(address)
        except socket.error:
            return False
        return address
    except socket.error:  # not a valid address
        return False
    return address


def is_ipv6(address: str):
    try:
        socket.inet_pton(socket.AF_INET6, address)
    except socket.error:  # not a valid address
        return False
    return address


class ScanSync(Thread):
    """ scan_redis_db: Expires IPs with last update epoch/timestamp older than (TTL * TTL_MULTIPLIER).
        sync_pf_table: Removes orphaned IPs (no DB entry) from the PF Table, and adds missing IPs to the PF Table.
        sync_pf_file: Removes orphaned IPs (no DB entry) from the PF File, and adds missing IPs to the PF File. """

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
        self.logger.info("PFUIFW: [+] Sync thread started for {}".format(self.table))

    def join(self):
        self.stop_event.set()
        super().join()

    def run(self):
        class Break(Exception):
            pass
        try:
            while not self.stop_event.is_set():
                self.scan_redis_db()
                self.sync_pf_table()
                self.sync_pf_file()
                for _ in range(int(self.cfg['SCAN_PERIOD'])):
                    if self.stop_event.is_set():
                        raise Break
                    sleep(1)
        except Break:
            self.logger.info("PFUIFW: [-] Sync thread closing for {}".format(self.table))
        except Exception as e:
            self.logger.error("PFUIFW: Sync thread died for {}! {}".format(self.table, e))

    def scan_redis_db(self):
        """ Expire IPs with last update epoch/timestamp older than (TTL * TTL_MULTIPLIER). """
        if self.cfg['LOGGING']:
            self.logger.info("PFUIFW: Scan DB({}) for expiring {} IPs.".format(self.cfg['REDIS_DB'], self.table))
        now = int(time())
        try:
            keys = self.db.keys("{}*".format(self.table))
        except Exception as e:
            self.logger.error("PFUIFW: Failed to get keys from Redis. {}".format(e))
            return
        for k in keys:
            db_last, db_ttl, db_expires = 0, 0, 0
            try:
                v = self.db.hgetall(k)
                db_last = int(v[b'epoch'].decode('utf-8'))
                db_ttl = int(v[b'ttl'].decode('utf-8'))
            except KeyError as e:
                self.logger.error("PFUIFW: Metadata not found! Trying 'expires' timestamp. {}".format(e))
                try:
                    db_expires = int(v[b'expires'].decode('utf-8'))
                except KeyError as e:
                    self.logger.error("PFUIFW: No 'expires' found either! {}".format(e))
                    continue
                if db_expires is None or db_expires <= now:
                    db_last, db_ttl = now, 0
            except Exception as e:
                self.logger.error("PFUIFW: Exception getting key '{}' values. {}".format(k, e))
                continue
            if db_last <= now - (db_ttl * self.cfg['TTL_MULTIPLIER']):
                ip = k.decode('utf-8').split("^")[1]
                if self.cfg['LOGGING']:
                    self.logger.info("PFUIFW: TTL Expired for IP {}".format(ip))
                db_pop(self.logger, self.cfg['LOGGING'], self.db, self.table, ip)

    def sync_pf_table(self):
        if self.cfg['LOGGING']:
            self.logger.info("PFUIFW: Sync PF Table {} with DB({})".format(self.table, self.cfg['REDIS_DB']))
        try:
            keys = self.db.keys("{}*".format(self.table))
            db_ips = [k.decode('utf-8').split("^")[1] for k in keys]
            lines = list(subprocess.Popen(["pfctl", "-t", self.table, "-T", "show"], stdout=subprocess.PIPE).stdout)
            t_ips = [l.decode('utf-8').strip() for l in lines]
        except Exception as e:
            self.logger.error("PFUIFW: Failed to read and decode data for {}. Error: {}".format(self.table, e))

        for t_ip in t_ips:  # Remove orphaned IPs from pf_table (no Redis record)
            found = next((db_ip for db_ip in db_ips if db_ip == t_ip), False)
            if not found:  # PF Table host not found in Redis DB
                table_pop(logger=self.logger, log=self.cfg['LOGGING'], cfg=self.cfg,
                          af=self.af, table=self.table, ip=t_ip)

        for db_ip in db_ips:  # Load missing IPs into pf_table (active Redis record)
            found = next((t_ip for t_ip in t_ips if t_ip == db_ip), False)
            if not found:  # Redis Key not found in PF Table
                table_push(logger=self.logger, log=self.cfg['LOGGING'], cfg=self.cfg,
                           af=self.af, table=self.table, ip_list=[db_ip])

    def sync_pf_file(self):
        if self.cfg['LOGGING']:
            self.logger.info("PFUIFW: Sync PF File {} with DB({})".format(self.table, self.cfg['REDIS_DB']))
        try:
            keys = self.db.keys("{}*".format(self.table))
            db_ips = [k.decode('utf-8').split("^")[1] for k in keys]
            with open(self.file) as f:
                content = f.readlines()
            f_ips = [x.strip() for x in content if x != "\n" or ""]
        except Exception as e:
            self.logger.error("PFUIFW: Failed to read stores for {}. Error: {}".format(self.file, e))

        for f_ip in f_ips:  # Remove orphaned IPs from pf_file (no Redis record)
            found = next((db_ip for db_ip in db_ips if db_ip == f_ip), False)
            if not found:  # PF File host not found in Redis DB
                file_pop(logger=self.logger, log=self.cfg['LOGGING'], file=self.file, ip=f_ip)

        for db_ip in db_ips:  # Load missing IPs into pf_file (active Redis record)
            found = next((f_ip for f_ip in f_ips if f_ip == db_ip), False)
            if not found:  # Redis Key not found in PF File
                file_push(logger=self.logger, log=self.cfg['LOGGING'], file=self.file, ip_list=[db_ip])


class PFUI_Firewall(Service):
    """ Main PFUI Firewall Service Class. """

    def __init__(self, *args, **kwargs):
        """ Load Yaml configuration and Init logger """

        super(PFUI_Firewall, self).__init__(*args, **kwargs)
        self.threads = []
        self.soc = None
        self.db = None

        # Load YAML Configuration
        try:
            self.cfg = safe_load(open(CONFIG_LOCATION))
            if "LOGGING" not in self.cfg:
                self.cfg['LOGGING'] = True
            if "LOG_LEVEL" not in self.cfg:
                self.cfg['LOG_LEVEL'] = "DEBUG"
            if "SOCKET_LISTEN" not in self.cfg:
                self.cfg['SOCKET_LISTEN'] = "0.0.0.0"
            if "SOCKET_PORT" not in self.cfg:
                self.cfg['SOCKET_PORT'] = 10001
            if "SOCKET_TIMEOUT" not in self.cfg:
                self.cfg['SOCKET_TIMEOUT'] = 2
            if "SOCKET_BUFFER" not in self.cfg:
                self.cfg['SOCKET_BUFFER'] = 1024
            if "SOCKET_BACKLOG" not in self.cfg:
                self.cfg['SOCKET_BACKLOG'] = 5
            if "REDIS_HOST" not in self.cfg:
                self.cfg['REDIS_HOST'] = "127.0.0.1"
            if "REDIS_PORT" not in self.cfg:
                self.cfg['REDIS_PORT'] = 6379
            if "REDIS_DB" not in self.cfg:
                self.cfg['REDIS_DB'] = 1024
            if "SCAN_PERIOD" not in self.cfg:
                self.cfg['SCAN_PERIOD'] = 60
            if "TTL_MULTIPLIER" not in self.cfg:
                self.cfg['TTL_MULTIPLIER'] = 1
            if "CTL" not in self.cfg:
                self.cfg['CTL'] = "IOCTL"
            if "DEVPF" not in self.cfg:
                self.cfg['DEVPF'] = "/dev/pf"
            if "AF4_TABLE" not in self.cfg:
                print("AF4_TABLE not found in YAML Config File. Exiting.")
                sys.exit(2)
            if "AF4_FILE" not in self.cfg:
                print("AF4_FILE not found in YAML Config File. Exiting.")
                sys.exit(2)
            if "AF6_TABLE" not in self.cfg:
                print("AF6_TABLE not found in YAML Config File. Exiting.")
                sys.exit(2)
            if "AF6_FILE" not in self.cfg:
                print("AF6_FILE not found in YAML Config File. Exiting.")
                sys.exit(2)
        except Exception as e:
            print("YAML Config File not found or cannot load. {}".format(e))
            sys.exit(2)

        # Init Logging
        self.logger.addHandler(SysLogHandler(address=find_syslog(), facility=SysLogHandler.LOG_DAEMON))
        if self.cfg['LOG_LEVEL'] == 'DEBUG' or self.cfg['LOG_LEVEL'] == 'INFO':
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.ERROR)

    def run(self):
        """ Connect to Redis, start sync threads, and watch socket (spawn Receiver each session)  (PFUI_Unbound)). """

        # Connect to Redis DB
        try:
            redisdb = (str(self.cfg['REDIS_HOST']), int(self.cfg['REDIS_PORT']), int(self.cfg['REDIS_DB']))
            self.db = StrictRedis(*redisdb)
        except Exception as e:
            self.logger.error("PFUIFW: Failed to connect to Redis DB. {}".format(e))
            sys.exit(3)

        # Start background scan and sync threads
        try:
            af4_thread = ScanSync(logger=self.logger, cfg=self.cfg, db=self.db,
                                  af=socket.AF_INET, table=self.cfg['AF4_TABLE'], file=self.cfg['AF4_FILE'])
            af4_thread.start()
            af6_thread = ScanSync(logger=self.logger, cfg=self.cfg, db=self.db,
                                  af=socket.AF_INET6, table=self.cfg['AF6_TABLE'], file=self.cfg['AF6_FILE'])
            af6_thread.start()
            self.threads.append(af4_thread)
            self.threads.append(af6_thread)
        except Exception as e:
            self.logger.error("PFUIFW: Scanning thread failed. {}".format(e))
            sys.exit(4)

        self.logger.info("PFUIFW: [+] PFUI_Firewall Service Started.")

        # Listen for connections
        if self.cfg['SOCKET_PROTO'] == "UDP":
            self.soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)  # UDP Datagram Socket
            self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 36)  # 'ACK' = 36bytes
            self.soc.settimeout(self.cfg['SOCKET_TIMEOUT'])  # accept() & recv() blocking timeouts
            self.soc.bind((self.cfg['SOCKET_LISTEN'], self.cfg['SOCKET_PORT']))
            while not self.got_sigterm():  # Watch Socket until Signal
                try:
                    dgram, (ip, port) = self.soc.recvfrom(1400)
                    try:
                        Thread(target=self.receiver_thread,
                               kwargs={"proto": "UDP", "dgram": dgram, "ip": ip, "port": port}).start()
                    except Exception as e:
                        self.logger.error("PFUIFW: Error starting receiver thread: {}".format(e))
                except socket.timeout:
                    continue
                except Exception as e:
                    self.logger.error("PFUIFW: UDP socket exception {}".format(e))
                    continue
        elif self.cfg['SOCKET_PROTO'] == "TCP":
            self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP Stream Socket
            self.soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)  # Disable Nagle
            self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)  # Fast Listen Socket reuse
            self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 0)  # Zero-size send Buffer (Send immediately)
            self.soc.settimeout(self.cfg['SOCKET_TIMEOUT'])  # accept() & recv() blocking timeouts
            self.soc.bind((self.cfg['SOCKET_LISTEN'], self.cfg['SOCKET_PORT']))
            self.soc.listen(self.cfg['SOCKET_BACKLOG'])
            while not self.got_sigterm():  # Watch Socket until Signal
                try:
                    conn, (ip, port) = self.soc.accept()
                    try:
                        Thread(target=self.receiver_thread,
                               kwargs={"proto": "TCP", "conn": conn, "ip": ip, "port": port}).start()
                    except Exception as e:
                        self.logger.error("PFUIFW: Error starting receiver thread: {}".format(e))
                except socket.timeout:
                    continue

        # Shut down
        for t in self.threads:
            t.join()
        self.db.close()
        self.logger.info("PFUIFW: [-] PFUI_Firewall Service Stopped.")

    def receiver_thread(self, proto, conn=None, dgram=None, ip=None, port=None):
        """ Receive all data, update PF Table, and update Redis DB entry.
        Data Structure: {'AF4': [{"ip": ipv4_addr, "ttl": ip_ttl }], 'AF6': [{"ip": ipv6_addr, "ttl": ip_ttl }]}
        For performance, we want entire message sent in a single segment, and a small socket buffer (packet size).
        Ensure SOCKET_BUFFER is small, but large enough for maximum expected record size. """

        def disconnect(proto, soc, conn):
            if proto == "UDP":
                try:
                    soc.sendto(b"ACK", (ip, port))
                except:
                    pass  # PFUI_Unbound may not be waiting (non-blocking)
            elif proto == "TCP":
                try:
                    conn.sendall(b"ACK")
                except:
                    pass  # PFUI_Unbound may have already disconnected (non-blocking)
                conn.close()

        if self.cfg['LOGGING']:
            stime = time()

        if proto == "UDP":
            try:
                data = loads(dgram)
            except Exception as e:
                self.logger.error("PFUIFW: Failed to decode datagram {}:{} {} {}".format(ip, port, dgram, e))
                disconnect(proto, self.soc, conn)
                return
        elif proto == "TCP":
            chunks, stream = [], b""
            while True:  # Receive all TCP stream chunks and build data
                try:
                    payload = conn.recv(int(self.cfg['SOCKET_BUFFER']))
                    if payload:
                        chunks.append(payload)
                        stream = b''.join(chunks)
                        if stream[-3:] == b"EOT":  # End of Transmission
                            try:
                                data = loads(stream[:-3])
                                break
                            except Exception as e:
                                self.logger.error(
                                    "PFUIFW: Failed to decode stream {}:{} {} {}".format(ip, port, stream, e))
                                disconnect(proto, self.soc, conn)
                                return
                    else:
                        self.logger.error("PFUIFW: None payload {}:{}".format(ip, port))
                        disconnect(proto, self.soc, conn)
                        return
                except socket.timeout:
                    self.logger.error("PFUIFW: Socket recv timeout {}:{}".format(ip, port))
                    break
        if isinstance(data, str):
            try:
                data = ast.literal_eval(data)
            except Exception as e:
                self.logger.error("PFUIFW: Failed to parse {} {} {}".format(type(data), data, e))
                disconnect(proto, self.soc, conn)
                return

        if self.cfg['LOGGING']:
            ntime = time()
            self.logger.info("PFUIFW: Received {} from {}:{} ({})".format(data, ip, port, proto))

        # Guard Statements
        if isinstance(data, dict):
            try:
                af4_data = [(rr['ip'], rr['ttl']) for rr in data['AF4'] if is_ipv4(rr['ip']) and rr['ttl']]
                af6_data = [(rr['ip'].lower(), rr['ttl']) for rr in data['AF6'] if is_ipv6(rr['ip']) and rr['ttl']]
            except Exception as e:
                self.logger.error("PFUIFW: Cannot extract meta from data {} {} {}".format(type(data), data, e))
                disconnect(proto, self.soc, conn)
                return
        else:
            self.logger.error("PFUIFW: Invalid datatype received {} {}".format(type(data), data))
            disconnect(proto, self.soc, conn)
            return

        if self.cfg['LOGGING']:
            vtime = time()

        # Update PF Tables
        if af4_data:
            table_push(logger=self.logger, log=self.cfg['LOGGING'], cfg=self.cfg, af=socket.AF_INET,
                       table=self.cfg['AF4_TABLE'], ip_list=[ip for ip, _ in af4_data])
        if af6_data:
            table_push(logger=self.logger, log=self.cfg['LOGGING'], cfg=self.cfg, af=socket.AF_INET6,
                       table=self.cfg['AF6_TABLE'], ip_list=[ip for ip, _ in af6_data])

        if self.cfg['LOGGING']:
            ttime = time()

        # Unblock DNS Client
        disconnect(proto, self.soc, conn)

        if self.cfg['LOGGING']:
            n1time = time()

        # Update Redis DB
        if af4_data:  # Always update Redis DB
            db_push(logger=self.logger, log=self.cfg['LOGGING'], db=self.db,
                    table=self.cfg['AF4_TABLE'], data=af4_data)
        if af6_data:
            db_push(logger=self.logger, log=self.cfg['LOGGING'], db=self.db,
                    table=self.cfg['AF6_TABLE'], data=af6_data)

        if self.cfg['LOGGING']:
            rtime = time()

        # Update PF Table Persist Files
        if af4_data:  # Update if new records
            file_push(logger=self.logger, log=self.cfg['LOGGING'],
                      file=self.cfg['AF4_FILE'], ip_list=[ip for ip, _ in af4_data])
        if af6_data:
            file_push(logger=self.logger, log=self.cfg['LOGGING'],
                      file=self.cfg['AF6_FILE'], ip_list=[ip for ip, _ in af6_data])

        # Print statistics
        if self.cfg['LOGGING']:
            etime = time()
            tntime = (ntime - stime)*(10**6)  # Network Receive Time
            tvtime = (vtime - ntime)*(10**6)  # Data Valid Time
            tptime = (ttime - vtime)*(10**6)  # PF Table Write Time
            tn1time = (n1time - ttime)*(10**6)  # Network ACK Time
            trtime = (rtime - n1time)*(10**6)  # Redis Write Time
            tftime = (etime - rtime)*(10**6)  # File Write Time
            ttime = (etime - stime)*(10**6)   # Total Time
            self.logger.info("PFUIFW: Network Latency {0:.2f} microsecs".format(tntime))
            self.logger.info("PFUIFW: Data Valid Latency {0:.2f} microsecs".format(tvtime))
            self.logger.info("PFUIFW: PF Table Latency {0:.2f} microsecs".format(tptime))
            self.logger.info("PFUIFW: ACK Latency {0:.2f} microsecs".format(tn1time))
            self.logger.info("PFUIFW: Redis Latency {0:.2f} microsecs".format(trtime))
            self.logger.info("PFUIFW: File Latency {0:.2f} microsecs".format(tftime))
            self.logger.info("PFUIFW: Total Latency {0:.2f} microsecs".format(ttime))


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print('Syntax: {} {{start|stop|kill|restart|check}}'.format(sys.argv[0]))
        exit(1)

    cmd = sys.argv[1].lower()
    service = PFUI_Firewall('pfui_firewall', pid_dir='/var/run')

    if cmd == 'start':
        if not service.is_running():
            service.start()
            sleep(1)
        if service.is_running():
            print("PFUI_Firewall started.")
            exit(0)
        else:
            exit(1)
    elif cmd == 'stop':
        if service.is_running():
            service.stop()
        if not service.is_running():
            print("PFUI_Firewall stopped.")
            exit(0)
        else:
            exit(1)
    elif cmd == 'kill':
        try:
            service.kill()
        except ValueError:
            print("PFUI_Firewall is not running.")
        if not service.is_running():
            exit(0)
        else:
            exit(1)
    elif cmd == 'restart' or cmd == 'reload':
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
    elif cmd == 'status' or cmd == 'check':
        if service.is_running():
            print("PFUI_Firewall is running.")
            exit(0)
        else:
            print("PFUI_Firewall is not running.")
            exit(1)
    else:
        sys.exit('Unknown command "%s".' % cmd)
