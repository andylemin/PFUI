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
"""
# TODO: Use the /dev/pf ioctl interface (https://man.openbsd.org/pf) for better performance (pfctl takes ~10-30ms!);
# ioctl calls to implement DIOCRADDADDRS, DIOCRGETADDRS, DIOCRDELADDRS
# ioctl: https://man.openbsd.org/ioctl.2 https://docs.python.org/2/library/fcntl.html
# Python-C structs: https://docs.python.org/2/library/struct.html
# TODO: Change socket protocol to UDP for (slightly) better performance

import ast
import sys
import logging
import fileinput
import subprocess

from socket import *
from ctypes import *
from fcntl import ioctl

from time import sleep
from json import loads
from yaml import safe_load
from redis import StrictRedis
from datetime import datetime
from threading import Thread, Event
from service import find_syslog, Service
from logging.handlers import SysLogHandler

############ Pycharm Debug ############
# import sys
# sys.path.append("pydevd-pycharm.egg")
# import pydevd_pycharm
# pydevd_pycharm.settrace('192.168.174.1', port=12345, stdoutToServer=True, stderrToServer=True)
#######################################

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
IOCPARM_MASK     = 0x1fff
IOC_OUT          = 0x40000000
IOC_IN           = 0x80000000
IOC_INOUT        = IOC_IN | IOC_OUT


# C Structures
class pfr_table(Structure):             # From /usr/include/net/pfvar.h
    _fields_ = [("pfrt_anchor",       c_char * PATH_MAX),
                ("pfrt_name",         c_char * PF_TABLE_NAME_SIZE),
                ("pfrt_flags",        c_uint32),
                ("pfrt_fback",        c_uint8)]


class pfioc_table(Structure):     # From /usr/include/net/pfvar.h
    _fields_ = [("pfrio_table",       pfr_table),  # Set target PF Table attributes
                ("pfrio_buffer",      c_void_p),  # Pointer to byte array of pfr_addr's (containing at least pfrio_size elements to add to the table)
                ("pfrio_esize",       c_int),  # size of struct pfr_addr
                ("pfrio_size",        c_int),  # total size of all elements
                ("pfrio_size2",       c_int),
                ("pfrio_nadd",        c_int),  # Returns number of addresses effectively added
                ("pfrio_ndel",        c_int),
                ("pfrio_nchange",     c_int),
                ("pfrio_flags",       c_int),
                ("pfrio_ticket",      c_uint32)]


class pfr_addr(Structure):              # From /usr/include/net/pfvar.h
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


def _IOC(inout, group, num, len):
    return inout | ((len & IOCPARM_MASK) << 16) | group << 8 | num


def _IOWR(group, num, type):
    return _IOC(IOC_INOUT, ord(group), num, sizeof(type))


def addr_struct(logger, af, host):
    """Convert this instance to a pfr_addr structure."""
    a = pfr_addr()

    try:
        addr = inet_pton(af, str(host))  # IP string format to packed binary format
        memmove(a.pfra_ip6addr, c_char_p(addr), len(addr))  # (dst, src, count)
    except Exception as e:
        logger.info("Error for host {} {}".format(str(host), str(e)))

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


def IOCTL(logger, dev, iocmd, af, table, addrs):
    """ Populate complete pfioc_table(Structure) with table and IPs,
    and write with given command to /dev/pf ioctl interface. """

    # Populate pfr_table(Structure); with target table
    table = pfr_table(pfrt_name=table.encode())

    # Populate pfioc_table(Structure); load the pfr_table(Structure) object,
    # set mem size (bytes) of pfr_addr(Structure), set count of pfr_addr instances
    io = pfioc_table(pfrio_table=table, pfrio_esize=sizeof(pfr_addr), pfrio_size=len(addrs))

    # Build list of populated pfr_addr(Structure)'s;
    _addrs = []
    for _addr in addrs:
        _addrs.append(addr_struct(logger, af, _addr))

    # Populate byte array of pfr_addr's (containing at least pfrio_size elements to add to the table)
    buffer = (pfr_addr * len(addrs))(*[a for a in _addrs])

    # Populate pfioc_table(Structure); set pointer to buffer containing pfr_addr byte array
    io.pfrio_buffer = addressof(buffer)

    with open(dev, 'w') as d:
        ioctl(d, iocmd, io)
    return io.pfrio_nadd


DIOCRADDADDRS = _IOWR('D', 67, pfioc_table)
DIOCRDELADDRS = _IOWR('D', 68, pfioc_table)


def table_push(logger, log, cfg, af, table, ip_list: list):
    if log:
        logger.info("PFUIFW: Installing {} into {}".format(str(ip_list), table))

    try:
        if cfg['CTL'] == "IOCTL":
            r = IOCTL(logger, cfg['DEVPF'], DIOCRADDADDRS, af, table, ip_list)
        elif cfg['CTL'] == "PFCTL":
            r = subprocess.run(["pfctl", "-t", table, "-T", "add"] + ip_list, stdout=subprocess.DEVNULL)
            if r.returncode != 0:
                raise Exception()
            else:
                r = 1
        return r  # Successful commits
    except Exception as e:
        logger.error("PFUIFW: Failed to install {} into {}. {} {}".format(str(ip_list), table, str(r), str(e)))
        return False


def table_pop(logger, log, cfg, af, table, ip: str):
    if log:
        logger.info("PFUIFW: Clearing {} from {}".format(str(ip), table))
    try:
        if cfg['CTL'] == "IOCTL":
            r = IOCTL(logger, cfg['DEVPF'], DIOCRDELADDRS, af, table, [ip])
        elif cfg['CTL'] == "PFCTL":
            r = subprocess.run(["pfctl", "-t", table, "-T", "delete", ip], stdout=subprocess.DEVNULL)
            if r.returncode != 0:
                raise Exception()
            else:
                r = 1
        return r  # Successful commits
    except Exception as e:
        logger.error("PFUIFW: Failed to install {} into {}. {} {}".format(str(ip), table, str(r), str(e)))
        return False


def db_push(logger, log, db, table: str, epoch: int, ip: str, ttl: int = 0):
    if log:
        logger.info("PFUIFW: Installing {} into Redis DB".format(ip, db))
    try:
        if ttl:
            db.hmset(table + "^" + ip, {'epoch': epoch, 'ttl': ttl})
        else:
            db.hmset(table + "^" + ip, {'epoch': epoch})
        return True
    except Exception as e:
        logger.error("PFUIFW: Failed to install {} into Redis DB. {}".format(ip, str(e)))
        return False


def db_pop(logger, log, db, table: str, ip: str):
    if log:
        logger.info("PFUIFW: Clearing {} from Redis DB".format(ip, db))
    try:
        db.delete(table + "^" + ip)
        return True
    except Exception as e:
        logger.error("PFUIFW: Failed to delete {} from Redis DB. {}".format(ip, str(e)))
        return False


def file_push(logger, log, line: str, file: str, mode: str = "r+"):
    if log:
        logger.info("PFUIFW: Installing {} into {}".format(line, file))
    try:
        with open(file, mode) as f:
            found = next((l for l in f if line in l), False)
            if not found:  # eof
                f.write(line + "\n")  # append missing data
        return True
    except Exception as e:
        logger.error("PFUIFW: Failed to add IP {} to file {}. {}".format(line, file, str(e)))
        return False


def file_pop(logger, log, line: str, file: str):
    if log:
        logger.info("PFUIFW: Clearing {} from {}".format(line, file))
    try:
        for l in fileinput.input(file, inplace=1):  # Backup file and redirect STDOUT to new file
            if line in l:
                continue  # Skip line to remove
            else:
                sys.stdout.write(l)
        return True
    except Exception as e:
        logger.error("PFUIFW: Failed to remove IP {} from file {}. {}".format(line, file, str(e)))
        return False


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
        self.logger.info("PFUIFW: [+] Background synchronisation thread started for {}".format(self.table))

    def join(self):
        self.stop_event.set()
        super().join()

    def run(self):
        class Break(Exception):
            pass
        try:
            while True:
                self.scan_redis_db()
                self.sync_pf_table()
                self.sync_pf_file()
                for _ in range(int(self.cfg['SCAN_PERIOD'])):
                    if self.stop_event.is_set():
                        raise Break
                    sleep(1)
        except Break:
            self.logger.info("PFUIFW: [-] Background synchronisation thread closing for {}".format(self.table))

    def scan_redis_db(self):
        """ Expire IPs with last update epoch/timestamp older than (TTL * TTL_MULTIPLIER). """
        if self.cfg['LOGGING']:
            self.logger.info("PFUIFW: Scanning DB({}) for expiring {} IPs.".format(str(self.cfg['REDIS_DB']),
                                                                                   self.table))
        keys = self.db.keys(self.table + "*")
        epoch = int(datetime.now().strftime('%s'))
        for key in keys:
            try:
                meta = self.db.hgetall(key)
                ttl = int(meta[b'ttl'].decode('utf-8'))
                db_epoch = int(meta[b'epoch'].decode('utf-8'))
            except:
                db_epoch, ttl = epoch, 0
            if db_epoch <= epoch - (ttl * self.cfg['TTL_MULTIPLIER']):
                ip = key.decode('utf-8').split("^")[1]
                self.logger.info("PFUIFW: TTL Expired for IP {}".format(ip))
                db_pop(self.logger, self.cfg['LOGGING'], self.db, self.table, ip)

    def sync_pf_table(self):
        if self.cfg['LOGGING']:
            self.logger.info("PFUIFW: Syncing PF Table {} with DB({})".format(self.table, str(self.cfg['REDIS_DB'])))
        try:
            keys = self.db.keys(self.table + "*")
            db_ips = [k.decode('utf-8').split("^")[1] for k in keys]
            lines = list(subprocess.Popen(["pfctl", "-t", self.table, "-T", "show"], stdout=subprocess.PIPE).stdout)
            t_ips = [l.decode('utf-8').strip() for l in lines]
        except Exception as e:
            self.logger.error("PFUIFW: Failed to read stores for {}. Error: {}".format(self.table, str(e)))

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
            self.logger.info("PFUIFW: Syncing PF File {} with DB({})".format(self.table, str(self.cfg['REDIS_DB'])))
        try:
            keys = self.db.keys(self.table + "*")
            db_ips = [k.decode('utf-8').split("^")[1] for k in keys]
            with open(self.file) as f:
                content = f.readlines()
            f_ips = [x.strip() for x in content if x != "\n" or ""]
        except Exception as e:
            self.logger.error("PFUIFW: Failed to read stores for {}. Error: {}".format(self.file, str(e)))

        for f_ip in f_ips:  # Remove orphaned IPs from pf_file (no Redis record)
            found = next((db_ip for db_ip in db_ips if db_ip == f_ip), False)
            if not found:  # PF File host not found in Redis DB
                file_pop(self.logger, self.cfg['LOGGING'], f_ip, self.file)

        for db_ip in db_ips:  # Load missing IPs into pf_file (active Redis record)
            found = next((f_ip for f_ip in f_ips if f_ip == db_ip), False)
            if not found:  # Redis Key not found in PF File
                file_push(self.logger, self.cfg['LOGGING'], db_ip, self.file)


class PFUI_Firewall(Service):
    """ Main PFUI Firewall Service Class. """

    def __init__(self, *args, **kwargs):
        """ Load Yaml configuration and Init logger """

        super(PFUI_Firewall, self).__init__(*args, **kwargs)
        self.threads = []
        self.soc = None
        self.db = None

        try:  # Load YAML Configuration
            self.cfg = safe_load(open(CONFIG_LOCATION))
        except Exception as e:
            errno, errstr = e.args
            print("YAML Config File not found or cannot load. {}".format(errstr))
            sys.exit(errno)

        self.logger.addHandler(SysLogHandler(address=find_syslog(), facility=SysLogHandler.LOG_DAEMON))
        if self.cfg['LOG_LEVEL'] == 'DEBUG' or self.cfg['LOG_LEVEL'] == 'INFO':
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.ERROR)

    def run(self):
        """ Connect to Redis, start sync threads, and watch socket (spawn Receiver each session)  (PFUI_Unbound)). """

        try:  # Connect to Redis DB
            self.db = StrictRedis(host=str(self.cfg['REDIS_HOST']),
                                  port=int(self.cfg['REDIS_PORT']),
                                  db=int(self.cfg['REDIS_DB']))
        except Exception as e:
            errno, errstr = e.args
            self.logger.error("PFUIFW: Failed to connect to Redis DB. {}".format(errstr))
            sys.exit(errno)

        try:  # Start background scan and synchronisation threads
            af4_thread = ScanSync(logger=self.logger, cfg=self.cfg, db=self.db,
                                  af=AF_INET, table=self.cfg['AF4_TABLE'], file=self.cfg['AF4_FILE'])
            af4_thread.start()
            af6_thread = ScanSync(logger=self.logger, cfg=self.cfg, db=self.db,
                                  af=AF_INET6, table=self.cfg['AF6_TABLE'], file=self.cfg['AF6_FILE'])
            af6_thread.start()
            self.threads.append(af4_thread)
            self.threads.append(af6_thread)
        except Exception as e:
            self.logger.error("PFUIFW: Scanning thread failed. {}".format(str(e)))
            sys.exit(1)

        if self.cfg['LOGGING']:
            self.logger.info("PFUIFW: [+] PFUI_Firewall Service Started.")

        self.soc = socket(AF_INET, SOCK_STREAM)
        self.soc.setsockopt(IPPROTO_TCP, TCP_NODELAY, True)  # Disable Nagle
        self.soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, True)  # Fast Listen Socket reuse
        self.soc.setsockopt(SOL_SOCKET, SO_SNDBUF, 0)  # Zero size send Buffer (Send immediately)
        self.soc.settimeout(self.cfg['SOCKET_TIMEOUT'])  # accept() & recv() blocking timeouts
        self.soc.bind((self.cfg['SOCKET_LISTEN'], self.cfg['SOCKET_PORT']))
        self.soc.listen(self.cfg['SOCKET_BACKLOG'])
        while not self.got_sigterm():  # Watch Socket
            try:
                (conn, (ip, port)) = self.soc.accept()
                try:
                    Thread(target=self.receiver, args=(conn, ip, port)).start()
                except Exception as e:
                    errno, errstr = e.args
                    self.logger.error("PFUIFW: Unexpected error starting thread: {}".format(errstr))
            except timeout:
                continue

        for t in self.threads:  # Shut down
            t.join()
        self.db.close()

        if self.cfg['LOGGING']:
            self.logger.info("PFUIFW: [-] PFUI_Firewall Service Stopped.")

    def receiver(self, conn, ip, port):
        """ Receive all data, update PF Table, and update Redis DB entry.
        Data Structure: {'AF4': [{"ip": ipv4_addr, "ttl": ip_ttl }], 'AF6': [{"ip": ipv6_addr, "ttl": ip_ttl }]}
        For performance, we want entire message sent in a single segment, and a small socket buffer (packet size).
        Ensure SOCKET_BUFFER is small, but large enough for maximum expected record size. """

        if self.cfg['LOGGING']:
            stime = datetime.now()

        chunks = []
        stream = b""
        data = dict()

        while True:
            try:
                payload = conn.recv(int(self.cfg['SOCKET_BUFFER']))
                if payload:
                    chunks.append(payload)
                    stream = b''.join(chunks)
                    if stream[-3:] == b"EOT":
                        try:
                            data = loads(stream[:-3])
                            if isinstance(data, str):
                                data = ast.literal_eval(data)
                            break
                        except Exception as e:
                            self.logger.error(
                                "PFUIFW: Failed to decode JSON {}:{} {} {}".format(str(ip), str(port),
                                                                                   str(stream), str(e)))
                else:
                    self.logger.error("PFUIFW: None payload {}:{}".format(str(ip), str(port)))
                    break
            except timeout:
                self.logger.error("PFUIFW: Socket recv timeout{}:{}".format(str(ip), str(port)))
                break

        if self.cfg['LOGGING']:
            ntime = datetime.now()
            self.logger.info("PFUIFW: Received: {} from {}:{}".format(str(data), str(ip), str(port)))

        # Update PF Tables
        af4_list = [rr['ip'] for rr in data['AF4'] if rr['ip']]
        if af4_list:
            r4 = table_push(logger=self.logger, log=self.cfg['LOGGING'], cfg=self.cfg,
                            af=AF_INET, table=self.cfg['AF4_TABLE'], ip_list=af4_list)

        af6_list = [rr['ip'].lower() for rr in data['AF6'] if rr['ip']]
        if af6_list:
            r6 = table_push(logger=self.logger, log=self.cfg['LOGGING'], cfg=self.cfg,
                            af=AF_INET6, table=self.cfg['AF6_TABLE'], ip_list=af6_list)

        if self.cfg['LOGGING']:
            ttime = datetime.now()

        try:
            conn.sendall(b"ACK")
        except:  # TODO: Trap correct assert
            pass  # PFUI_Unbound may have already disconnected (non-blocking mode)
        conn.close()

        if self.cfg['LOGGING']:
            n1time = datetime.now()

        # Update Redis DB - TODO Need to add try: and retry logic as we have installed in PF Table first..
        # TODO Add handling for state where no 'real-ttl' record exists (db missed resolver, only cache answers)
        epoch = int(datetime.now().strftime('%s'))
        if af4_list and r4 != 0:
            for addr in data['AF4']:
                if addr['ttl'] < epoch:  # TTL is real (new query)
                    db_push(self.logger, self.cfg['LOGGING'], self.db, self.cfg['AF4_TABLE'],
                            epoch, addr['ip'], addr['ttl'])
                else:  # TTL is Unbound cache response (cache expiry epoch) - update timestamp only
                    db_push(self.logger, self.cfg['LOGGING'], self.db, self.cfg['AF4_TABLE'],
                            epoch, addr['ip'])
        if af6_list and r6 != 0:
            for addr in data['AF6']:
                if addr['ttl'] < epoch:
                    db_push(self.logger, self.cfg['LOGGING'], self.db, self.cfg['AF6_TABLE'],
                            epoch, addr['ip'].lower(), addr['ttl'])
                else:
                    db_push(self.logger, self.cfg['LOGGING'], self.db, self.cfg['AF6_TABLE'],
                            epoch, addr['ip'].lower())

        if self.cfg['LOGGING']:
            rtime = datetime.now()

        # Update PF Table Persist Files
        if af4_list and r4 != 0:
            for addr in data['AF4']:
                file_push(self.logger, self.cfg['LOGGING'], addr['ip'].lower(), self.cfg['AF4_FILE'])
        if af6_list and r6 != 0:
            for addr in data['AF6']:
                file_push(self.logger, self.cfg['LOGGING'], addr['ip'].lower(), self.cfg['AF6_FILE'])

        if self.cfg['LOGGING']:
            etime = datetime.now()
            tntime = ntime - stime  # Total Network Time
            tptime = ttime - ntime  # Total PF Table Time
            tn1time = n1time - ttime  # Total Network ACK Time
            trtime = rtime - n1time  # Total Redis Time
            tftime = etime - rtime  # Total File Time
            ttime = etime - stime   # Total Time
            self.logger.info("PFUIFW: Network Latency {} secs and {} microsecs".format(str(int(tntime.seconds)),
                                                                                       str(int(tntime.microseconds))))
            self.logger.info("PFUIFW: PF Table Latency {} secs and {} microsecs".format(str(int(tptime.seconds)),
                                                                                        str(int(tptime.microseconds))))
            self.logger.info("PFUIFW: ACK Latency {} secs and {} microsecs".format(str(int(tn1time.seconds)),
                                                                                       str(int(tn1time.microseconds))))
            self.logger.info("PFUIFW: Redis Latency {} secs and {} microsecs".format(str(int(trtime.seconds)),
                                                                                     str(int(trtime.microseconds))))
            self.logger.info("PFUIFW: File Latency {} secs and {} microsecs".format(str(int(tftime.seconds)),
                                                                                    str(int(tftime.microseconds))))
            self.logger.info("PFUIFW: Total Latency {} secs and {} microsecs".format(str(int(ttime.seconds)),
                                                                                     str(int(ttime.microseconds))))


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
