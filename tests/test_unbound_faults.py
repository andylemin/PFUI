#!/usr/bin/env python

# Failure Testing script

import socket
from time import time
from json import dumps
from yaml import safe_load

TEST_MESSAGE1 = ({'ip': '192.0.2.1', 'ttl': 3600},
                 {'ip': '192.0.2.2', 'ttl': 100},
                 {'ip': '192.0.2.3', 'ttl': 100})

TEST_MESSAGE2 = [{'ip': '192.0.2.1', 'ttl': 3600},
                 {'ip': '192.0.2.2', 'ttl': 100},
                 {'ip': '192.0.2.3', 'ttl': 100}]

TEST_MESSAGE3 = "{'ip': '192.0.2.1', 'ttl': 3600}, {'ip': '192.0.2.2', 'ttl': 100}, {'ip': '192.0.2.3', 'ttl': 100}"

TEST_MESSAGE4 = {'AF4': [{'ip': '192.0.2.1', 'ttl': 3600},
                         {'ip': '192.0.2', 'ttl': 100},
                         {'ip': '192.0.', 'ttl': 100}],
                 'AF6': [{'ip': '2001::1:1::1', 'ttl': 3600},
                         {'ip': '2001:DB8:1:2::1', 'ttl': 100},
                         {'ip': '1:DB8:1:3::53', 'ttl': 100}]}


def log_info(message):
    print(str(message))


def transmit(ip_dict):
    """ Transmits IP and TTL data structure to PF Firewalls running pfui_firewall. """

    if cfg['SOCKET_PROTO'] == "UDP":
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    elif cfg['SOCKET_PROTO'] == "TCP":
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)  # Disable Nagle
        s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 0)  # Zero size Buffer (Send immediately)
        s.settimeout(cfg['SOCKET_TIMEOUT'])

    for fw in cfg['FIREWALLS']:
        if fw['HOST']:
            if 'PORT' not in fw:
                fw['PORT'] = cfg['DEFAULT_PORT']
            try:
                if cfg['LOGGING']:
                    log_info("PFUIDNS: Sending : {} {}".format(type(ip_dict), ip_dict))
                    start = time()
                if cfg['SOCKET_PROTO'] == "UDP":
                    try:
                        s.sendto(dumps(ip_dict), (fw['HOST'], fw['PORT']))
                        if cfg['BLOCKING']:
                            _, _ = s.recvfrom(4096)
                    except Exception as e:
                        log_err("PFUIDNS: UDP Socket Error {}".format(e))
                elif cfg['SOCKET_PROTO'] == "TCP":
                    try:
                        s.connect((fw['HOST'], fw['PORT']))
                        s.send(dumps(ip_dict))
                        s.send(b"EOT")  # Terminate stream and Provoke ACK
                        if cfg['BLOCKING']:
                            _ = s.recv(36)  # Wait for PF rules commit  # TODO Verify is ACK/NACK
                    except socket.timeout:
                        log_err("PFUIDNS: Socket timeout to firewall!")  # TODO Need retries for 'blocking' mode
                    except socket.error:
                        log_err("PFUIDNS: Socket Error! Check pfui_firewall is running.")
                if cfg['LOGGING']:
                    end = time()
                    diff = (end - start)*(10**6)
                    log_info("PFUIDNS: DNS Answer Blocked {} microsecs".format(diff))
            except Exception as e:
                log_err("PFUIDNS: Failed to send " + str(e))
            s.close()


try:
    cfg = safe_load(open('pfui_unbound.yml'))
except Exception as e:
    print("YAML Config File not found or cannot load: " + str(e))
    exit(1)

transmit(TEST_MESSAGE1)
transmit(TEST_MESSAGE2)
transmit(TEST_MESSAGE3)
transmit(TEST_MESSAGE4)
