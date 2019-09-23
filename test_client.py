#!/usr/bin/env python

import socket
from yaml import safe_load
from json import dumps

TEST_MESSAGE = {'AF4': [{'ip': '204.79.197.212', 'ttl': 3600}, {'ip': '192.0.2.1', 'ttl': 100}], 'AF6': [{'ip': '2a00:77e0:1:2::1', 'ttl': 3600}]}
# TEST_MESSAGE = {'AF4': [{'ip': '204.79.197.212', 'ttl': 3600}], 'AF6': [{'ip': '2a00:77e0:1:2::1', 'ttl': 3600}]}
# {'AF4': [{"ip": ipv4_addr, "ttl": ip_ttl }], 'AF6': [{"ip": ipv6_addr, "ttl": ip_ttl }]}


def log_info(message):
    print(str(message))


def transmit(ip_dict):
    """ Test Transmit to PF Firewall running pfui_server listener. """

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, cfg['SOCKET_TIMEOUT'])
    for fw in cfg['FIREWALLS']:
        if fw['HOST']:
            if not fw['PORT']:
                fw['PORT'] = cfg['DEFAULT_PORT']
            try:
                if cfg['DEBUG']:
                    log_info("DEBUG: SENDING DATA: {} {}".format(str(type(ip_dict)), str(ip_dict)))
                s.connect((fw['HOST'], fw['PORT']))
                s.send(dumps(ip_dict))
            except Exception as e:
                log_info("ERROR: Failed to send " + str(e))
            s.close()


try:
    cfg = safe_load(open('pfui_client.yml'))
except Exception as e:
    print("YAML Config File not found or cannot load: " + str(e))
    exit(1)

transmit(TEST_MESSAGE)
