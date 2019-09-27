#!/usr/bin/env python

import socket
from json import dumps
from yaml import safe_load
from datetime import datetime

TEST_MESSAGE1 = {'AF4': [{'ip': '198.51.100.1', 'ttl': 3600}],
                 'AF6': [{'ip': '2001:DB8:1:1::1', 'ttl': 3600}]}

TEST_MESSAGE2 = {'AF4': [{'ip': '198.51.100.1', 'ttl': 3600},
                         {'ip': '192.0.2.1', 'ttl': 100}],
                 'AF6': [{'ip': '2001:DB8:1:1::1', 'ttl': 3600}]}

TEST_MESSAGE3 = {'AF4': [{'ip': '192.0.2.1', 'ttl': 3600},
                         {'ip': '192.0.2.2', 'ttl': 100},
                         {'ip': '192.0.2.3', 'ttl': 100}],
                 'AF6': [{'ip': '2001:db8:1:1::1', 'ttl': 3600},
                         {'ip': '2001:DB8:1:2::1', 'ttl': 100}]}


def log_info(message):
    print(str(message))


def transmit(ip_dict):
    """ Test Transmit to PF Firewall running pfui_server listener. """

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 0)  # Buffer size Zero
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)  # Disable Nagle
    for fw in cfg['FIREWALLS']:
        if fw['HOST']:
            if not fw['PORT']:
                fw['PORT'] = cfg['DEFAULT_PORT']
            try:
                if cfg['DEBUG']:
                    print("PFUI: SENDING DATA: {} {}".format(str(type(ip_dict)), str(ip_dict)))
                    stime = datetime.now()
                s.connect((fw['HOST'], fw['PORT']))
                if cfg['DEBUG']:
                    ctime = datetime.now()
                s.send(dumps(ip_dict))
                if cfg['DEBUG']:
                    etime = datetime.now()
                    tctime = ctime - stime
                    tstime = etime - ctime
                    print("PFUI: Connect Latency {} secs and {} microsecs".format(str(int(tctime.seconds)),
                                                                                  str(int(tctime.microseconds))))
                    print("PFUI: Send Latency {} secs and {} microsecs".format(str(int(tstime.seconds)),
                                                                               str(int(tstime.microseconds))))
            except Exception as e:
                log_info("ERROR: Failed to send " + str(e))
            s.close()


try:
    cfg = safe_load(open('pfui_client.yml'))
except Exception as e:
    print("YAML Config File not found or cannot load: " + str(e))
    exit(1)

transmit(TEST_MESSAGE3)
