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

TEST_MESSAGE4 = {'AF4': [{'ip': '198.51.100.1', 'ttl': 3600}],
                 'AF6': []}

TEST_MESSAGE6 = {'AF4': [],
                 'AF6': [{'ip': '2001:DB8:1:1::1', 'ttl': 3600}]}


def log_info(message):
    print(str(message))


d = dict()

for i in range(100):
    key = i % 10
    if key in d:
        d[key] += 1
    else:
        d[key] = 1


def transmit(ip_dict):
    """ Transmits IP and TTL data structure to PF Firewalls running pfui_firewall. """

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)  # Disable Nagle
    #s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 0)  # Zero size Buffer (Send immediately) - Not supported MacOS
    print(cfg['SOCKET_TIMEOUT'])
    s.settimeout(cfg['SOCKET_TIMEOUT'])
    for fw in cfg['FIREWALLS']:
        if fw['HOST']:
            if 'PORT' not in fw:
                fw['PORT'] = cfg['DEFAULT_PORT']
            try:
                if cfg['LOGGING']:
                    print("PFUIDNS: Sending: {} {}".format(str(type(ip_dict)), str(ip_dict)))
                    start = datetime.now()
                try:
                    s.connect((fw['HOST'], fw['PORT']))
                    json = dumps(ip_dict)
                    s.send(dumps(json).encode())
                    s.send(b"EOT")  # Terminate stream and Provoke ACK
                    if cfg['BLOCKING']:
                        _ = s.recv(36)  # Wait for PF rules commit  # TODO Verify is ACK/NACK
                except socket.timeout:
                    print("PFUIDNS: Timeout sending to firewall!")  # TODO Need retries for 'blocking' mode
                except socket.error:
                    print("PFUIDNS: Socket Error!")
                except Exception as e:
                    print("PFUIDNS: Other Socket Exception! {}".format(str(e)))
                if cfg['LOGGING']:
                    end = datetime.now()
                    diff = end - start
                    log_info("PFUIDNS: Latency {} secs & {} microsecs..".format(str(int(diff.seconds)),
                                                                                str(int(diff.microseconds))))
            except Exception as e:
                print("PFUIDNS: Failed to send " + str(e))
            s.close()


try:
    cfg = safe_load(open('pfui_unbound.yml'))
except Exception as e:
    print("YAML Config File not found or cannot load: " + str(e))
    exit(1)

transmit(TEST_MESSAGE3)
