#!/usr/bin/env python3
"""
    The server daemon (pfui_server.py) receives (from pfui_client.py) all successfully resolved (by Unbound) domains,
      and installs the resolved IPs into local "PF Tables" (v4 & v6), to facilitate traffic filtering with PF.
      `pfctl -t pfui_ipv4_domains -T [add|show|delete]` https://www.openbsd.org/faq/pf/tables.html

    DNS Resource Record (A & AAAA) age (last query timestamp) and max-age (TTL) are tracked using Redis, and IPs are
      expired from the PF Tables (blocked again) when the last query is older than "EPOCH - (TTL * TTL_MULTIPLIER)".

    The most common PFUI use case blocks all egress traffic by default, allowing egress traffic only for the
      corporate/internal Unbound DNS servers. Therefore;
      Any direct outbound connections without a prior DNS lookup will fail..
      Effectively blocks DoH (DNS over HTTPS), forcing clients to use the internal Unbound DNS servers (pfui_client).
      Enforces compliance with corporate DNS-BlackLists for all hosts on the network (including private BYODs).

    This approach blocks most Botnets, Malware, and Randsomware by blocking their Command and Control.
    pfctl -t pfui_ipv4_domains -T [add|show|delete]

    The PF Table interface supports expiring old entries (pfctl -t pfui_ipv4_domains -T expire 3600), however
    subsequent queries/updates do _not_ refresh the cleared timestamp. Therefore Redis used to track entries.
"""

# TODO: Use the /dev/pf ioctl interface (https://man.openbsd.org/pf) for better performance (pfctl takes ~30ms!);
# ioctl calls to implement DIOCRADDADDRS, DIOCRGETADDRS, DIOCRDELADDRS
# ioctl: https://man.openbsd.org/ioctl.2 https://docs.python.org/2/library/fcntl.html
# Python-C structs: https://docs.python.org/2/library/struct.html
# TODO: Change socket protocol to UDP for better performance

import sys
import logging
import socket
import subprocess

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

CONFIG_LOCATION = "/etc/pfui_server.yml"


class Scanner(Thread):
    """ sync_pf_table: Removes orphaned IPs (no DB entry) from the PF Table, and adds missing IPs to the PF Table.
        scan_redis_db: Expires IPs with last update epoch/timestamp older than (TTL * TTL_MULTIPLIER). """

    def __init__(self, cfg, logger, table, db):
        Thread.__init__(self)
        self.daemon = True
        self.stop_event = Event()
        self.cfg = cfg
        self.logger = logger
        self.table = table
        self.db = db
        self.scan_redis_db()
        self.sync_pf_table()
        self.logger.info("PFUI_S: [+] New background scanner thread started for {}".format(self.table))

    def join(self):
        self.stop_event.set()
        super().join()

    def run(self):
        class Break(Exception):
            pass
        try:
            while True:
                for _ in range(int(self.cfg['SCAN_PERIOD'])):
                    if self.stop_event.is_set():
                        raise Break
                    sleep(1)
                self.scan_redis_db()
        except Break:
            self.logger.info("PFUI_S: [-] Background scanner thread closing for {}".format(self.table))

    def sync_pf_table(self):
        self.logger.info("PFUI_S: Syncing PF Table {} to DB({})".format(self.table, str(self.cfg['REDIS_DB'])))
        try:
            lines = list(subprocess.Popen(["pfctl", "-t", self.table, "-T", "show"], stdout=subprocess.PIPE).stdout)
            keys = self.db.keys(self.table + "*")
        except Exception as e:
            errno, errstr = e.args
            self.logger.error("PFUI_S: Failed to read stores for {}. Error: {}".format(self.table, errstr))

        for line in lines:  # Remove orphaned IPs from pf_table (no Redis record)
            ip = line.decode('utf-8').strip()
            found = next((k for k in keys if k.decode('utf-8').split("^")[1] == ip), False)
            if not found:  # PF Table host not found in Redis DB
                self.logger.info("PFUI_S: Purging orphaned IP {} from PF Table {}".format(ip, self.table))
                r = subprocess.run(["pfctl", "-t", self.table, "-T", "delete", ip])
                if r.returncode != 0:
                    self.logger.error("PFUI_S: Could not delete {} from table {}. {}".format(ip, self.table, str(r)))

        for key in keys:  # Load missing IPs into pf_table (active Redis record)
            ip = key.decode('utf-8').split("^")[1]
            found = next((l for l in lines if l.decode('utf-8').strip() == ip), False)
            if not found:  # Redis Key not found in PF Table hosts
                self.logger.info("PFUI_S: Installing missing IP {} into PF Table {}".format(ip, self.table))
                r = subprocess.run(["pfctl", "-t", self.table, "-T", "add", ip])
                if r.returncode != 0:
                    self.logger.error("PFUI_S: Failed to install {} into table {}. {}".format(ip, self.table, str(r)))

    def scan_redis_db(self):
        self.logger.info("PFUI_S: Scanning DB({}) for expiring {} entries.".format(str(self.cfg['REDIS_DB']), self.table))
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
                self.logger.info("PFUI_S: Expiring IP {} from {}".format(str(ip), self.table))
                r = subprocess.run(["pfctl", "-t", self.table, "-T", "delete", ip])
                if r.returncode != 0:
                    self.logger.error("PFUI_S: Could not delete IP from PF Table {}. {}".format(str(ip), str(r)))
                else:
                    try:
                        self.db.delete(self.table + "^" + ip)
                    except Exception as e:
                        self.logger.error("PFUI_S: Could not delete Key from Redis DB at {}. {}".format(str(ip), str(e)))


class PFUIService(Service):
    """ Main PFUI Server Service Class. """

    def __init__(self, *args, **kwargs):
        """ Load Yaml configuration and Init logger """

        super(PFUIService, self).__init__(*args, **kwargs)
        self.threads = []
        self.soc = ''
        self.db = ''

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
        """ Connect to Redis, start Scanner threads, and watch socket (spawn Receiver thread for each client). """

        try:  # Connect to Redis DB
            self.db = StrictRedis(host=str(self.cfg['REDIS_HOST']),
                                  port=int(self.cfg['REDIS_PORT']),
                                  db=int(self.cfg['REDIS_DB']))
        except Exception as e:
            errno, errstr = e.args
            self.logger.error("PFUI_S: Failed to connect to Redis DB. {}".format(errstr))
            sys.exit(errno)

        try:  # Start background table scanning threads
            af4_thread = Scanner(self.cfg, self.logger, self.cfg['AF4_TABLE'], self.db)
            af4_thread.start()
            af6_thread = Scanner(self.cfg, self.logger, self.cfg['AF6_TABLE'], self.db)
            af6_thread.start()
            self.threads.append(af4_thread)
            self.threads.append(af6_thread)
        except Exception as e:
            self.logger.error("PFUI_S: Scanning thread failed. {}".format(str(e)))
            sys.exit(1)

        if self.cfg['DEBUG']:
            self.logger.info("PFUI_S: [+] PFUI_Server Service Started.")

        self.soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.soc.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)  # Disable Nagle
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)  # Fast Socket reuse
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
                    self.logger.error("PFUI_S: Unexpected error starting thread: {}".format(errstr))
            except socket.timeout:
                continue

        for t in self.threads:  # Shut down
            t.join()
        self.db.close()

        if self.cfg['DEBUG']:
            self.logger.info("PFUI_S: [-] PFUI_Server Service Stopped.")

    def receiver(self, conn, ip, port):
        """ Receive all data, update PF Table, and update Redis DB entry.
        Data Structure: {'AF4': [{"ip": ipv4_addr, "ttl": ip_ttl }], 'AF6': [{"ip": ipv6_addr, "ttl": ip_ttl }]}
        For performance, we want entire message sent in a single segment, and a small socket buffer (packet size).
        Ensure SOCKET_BUFFER is small, but large enough for maximum expected record size. """

        chunks = []
        if self.cfg['DEBUG']:
            stime = datetime.now()
        while True:  # Receive all data
            try:
                raw = conn.recv(self.cfg['SOCKET_BUFFER'])
                if not raw:  # Client disconnected
                    break
            except socket.timeout:
                break
            chunks.append(raw)
        if self.cfg['DEBUG']:
            ntime = datetime.now()
        conn.close()
        if len(chunks) > 1:
            self.logger.info("PFUI_S: Increase SOCKET_BUFFER. Data did not fit into single segment.")
        data = loads(b"".join(chunks))
        if self.cfg['DEBUG']:
            self.logger.info("PFUI_S: Received data: {} from {}:{}".format(str(data), str(ip), str(port)))

        # Update PF Tables
        af4_list = [rr['ip'] for rr in data['AF4'] if rr['ip']]
        if af4_list:
            r4 = subprocess.run(["pfctl", "-t", self.cfg['AF4_TABLE'], "-T", "add"] + af4_list,
                                stdout=subprocess.DEVNULL)
            if r4.returncode != 0:
                self.logger.error("PFUI_S: Failed to install {} into {}. {}".format(str(af4_list),
                                                                                  self.cfg['AF4_TABLE'], str(r4)))
        af6_list = [rr['ip'] for rr in data['AF6'] if rr['ip']]
        if af6_list:
            r6 = subprocess.run(["pfctl", "-t", self.cfg['AF6_TABLE'], "-T", "add"] + af6_list,
                                stdout=subprocess.DEVNULL)
            if r6.returncode != 0:
                self.logger.error("PFUI_S: Failed to install {} into {}. {}".format(str(af6_list),
                                                                                  self.cfg['AF6_TABLE'], str(r6)))
        if self.cfg['DEBUG']:
            ptime = datetime.now()

        # Update Redis DB
        epoch = int(datetime.now().strftime('%s'))
        if r4.returncode == 0:
            for addr in data['AF4']:
                if addr['ttl'] < epoch:  # TTL is real (new query)
                    self.db.hmset(self.cfg['AF4_TABLE'] + "^" + addr['ip'].lower(),
                                  {'epoch': epoch, 'ttl': addr['ttl']})
                else:  # TTL is Unbound cache response (cache expiry epoch) - update timestamp only
                    self.db.hmset(self.cfg['AF4_TABLE'] + "^" + addr['ip'].lower(),
                                  {'epoch': epoch})
        if r6.returncode == 0:
            for addr in data['AF6']:
                if addr['ttl'] < epoch:
                    self.db.hmset(self.cfg['AF6_TABLE'] + "^" + addr['ip'].lower(),
                                  {'epoch': epoch, 'ttl': addr['ttl']})
                else:
                    self.db.hmset(self.cfg['AF6_TABLE'] + "^" + addr['ip'].lower(),
                                  {'epoch': epoch})
        if self.cfg['DEBUG']:
            etime = datetime.now()
            tntime = ntime - stime
            tptime = ptime - ntime
            trtime = etime - ptime
            ttime = etime - stime
            self.logger.info("PFUI_S: Receive Latency {} secs and {} microsecs".format(str(int(tntime.seconds)),
                                                                                     str(int(tntime.microseconds))))
            self.logger.info("PFUI_S: PF Update Latency {} secs and {} microsecs".format(str(int(tptime.seconds)),
                                                                                       str(int(tptime.microseconds))))
            self.logger.info("PFUI_S: Redis Update Latency {} secs and {} microsecs".format(str(int(trtime.seconds)),
                                                                                          str(int(trtime.microseconds))))
            self.logger.info("PFUI_S: Total Update Latency {} secs and {} microsecs".format(str(int(ttime.seconds)),
                                                                                          str(int(ttime.microseconds))))


if __name__ == '__main__':

    if len(sys.argv) != 2:
        print('Syntax: {} {{start|stop|kill|restart|check}}'.format(sys.argv[0]))
        exit(1)

    cmd = sys.argv[1].lower()
    service = PFUIService('pfui_server', pid_dir='/var/run')

    if cmd == 'start':
        if not service.is_running():
            service.start()
        if service.is_running():
            print("PFUI_Server started.")
            exit(0)
        else:
            exit(1)
    elif cmd == 'stop':
        if service.is_running():
            service.stop()
        if not service.is_running():
            print("PFUI_Server stopped.")
            exit(0)
        else:
            exit(1)
    elif cmd == 'kill':
        try:
            service.kill()
        except ValueError:
            print("PFUI_Server is not running.")
        if not service.is_running():
            exit(0)
        else:
            exit(1)
    elif cmd == 'restart' or cmd == 'reload':
        while service.is_running():
            print("PFUI_Server is stopping.")
            service.stop()
            sleep(1)
        service.start()
        if service.is_running():
            print("PFUI_Server started.")
            exit(0)
        else:
            exit(1)
    elif cmd == 'status' or cmd == 'check':
        if service.is_running():
            print("PFUI_Server is running.")
            exit(0)
        else:
            print("PFUI_Server is not running.")
            exit(1)
    else:
        sys.exit('Unknown command "%s".' % cmd)