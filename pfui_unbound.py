# This is a Python library used by Unbound via SWIG
"""
PFUI-DNS Python Library for Unbound with SWIG (pfui_unbound)
Written using example python module scripts found in Unbound source.

inplace_cache_callback(), init(), init_standard(), deinit(), inform_super(), and operate() are SWIG interface functions
declared here and called by Unbound depending on EVENT type

:param qinfo: query_info struct
:param qstate: module qstate. None
:param rep: reply_info struct
:param rcode: return code for the query
:param edns: edns_data sent from client. List with EDNS options is accessible through edns.opt_list. Do not alter
:param opt_list_out: List with the EDNS options that will be sent as reply. It can be populated with EDNS options
:param region: region to allocate temporary data. Used when we want to append a new option to opt_list_out
:param qdata: ??
:param superqstate: ??
:param rr: DNS Resource Record
"""

import lz4.frame
from json import dumps
from sys import exit, getsizeof
from time import time
from yaml import safe_load

from socket import (
    AF_INET,
    AF_INET6,
    IPPROTO_TCP,
    SO_SNDBUF,
    SOCK_DGRAM,
    SOCK_STREAM,
    SOL_SOCKET,
    TCP_NODELAY,
    SO_REUSEADDR
)
from socket import error as ERROR
from socket import inet_ntop, ntohs, socket
from socket import timeout as TIMEOUT

CONFIG_LOCATION = "/var/unbound/etc/pfui_unbound.yml"


def data_to_hex(data, prefix=""):
    """PFUI: Converts RR binary data to display form. Function taken from Unbound source examples."""

    res = ""
    for i in range(int((len(data) + 15) / 16)):
        res += "%s0x%02X | " % (prefix, i * 16)
        d = [ord(x) for x in data[i * 16: i * 16 + 17]]
        for ch in d:
            res += "%02X " % ch
        for i in range(0, 17 - len(d)):
            res += "   "
        res += "| "
        for ch in d:
            if (ch < 32) or (ch > 127):
                res += ". "
            else:
                res += "%c " % ch
        res += "\n"
    return res


def logger(qstate):
    """PFUI: Logs Response. Requires Unbound to run in daemon mode (-dv)"""

    r = qstate.return_msg.rep
    q = qstate.return_msg.qinfo
    log_info("-" * 100)
    log_info(
        f"Query: {qstate.qinfo.qname_str}, "
        f"type: {qstate.qinfo.qtype_str} ({qstate.qinfo.qtype}), "
        f"class: {qstate.qinfo.qclass_str} ({qstate.qinfo.qclass})"
    )
    log_info("-" * 100)
    log_info(
        f"Return    reply :: flags: {r.flags}, QDcount: {r.qdcount}, Security:{r.security}, TTL={r.ttl}"
    )
    log_info(
        f"          qinfo :: qname: {q.qname_list} {q.qname_str}, qtype: {q.qtype_str}, qclass: {q.qclass_str}"
    )
    if r:
        log_info("RR:")
        for i in range(r.rrset_count):
            rr = r.rrsets[i]
            rk = rr.rk
            log_info(f"{i}:{rk.dname_list} {rk.dname_str} flags: {rk.flags}")
            log_info(
                f"type:{rk.type_str} ({ntohs(rk.type)}) "
                f"class: {rk.rrset_class_str} ({ntohs(rk.rrset_class)})"
            )
            d = rr.entry.data
            for j in range(d.count + d.rrsig_count):
                log_info("")
                log_info(f"   {j} : TTL= {d.rr_ttl[j]}")
                if j >= d.count:
                    log_info("rrsig")
                log_info("")
                log_info(f"HEX:  {data_to_hex(str(d.rr_data[j]))}")
                if rk.type_str == "A":
                    log_info(f"IPv4: {inet_ntop(AF_INET, d.rr_data[j][-4:])}")
                if rk.type_str == "AAAA":
                    log_info(f"IPv6: {inet_ntop(AF_INET6, d.rr_data[j][-16:])}")
    log_info("-" * 100)


def read_rr(rep=None, qname_str=""):
    """PFUI: Inspects RR response data, extracts IPs and TTLs, and returns PFUI Firewall data structure.
    Data Structure: {'AF4': [{"ip": ipv4_addr, "ttl": ip4_ttl }], 'AF6': [{"ip": ipv6_addr, "ttl": ip6_ttl }]}
    """

    if pfui_cfg["LOGGING"] and pfui_cfg["LOG_LEVEL"] == "DEBUG":
        log_info(f"rep: {rep}, qname_str: {qname_str}")

    # Extract all IPs and TTLs from all RR sets
    ipv4_resps, ipv6_resps = [], []
    if rep:
        for i in range(rep.rrset_count):
            rr = rep.rrsets[i]

            if rr.rk.type_str == "A":
                d = rr.entry.data
                # Last 4 bytes contain IPv4 address
                for rr_ip4, rr_ttl4 in [
                    (d.rr_data[j][-4:], int(d.rr_ttl[j]))
                    for j in range(d.count + d.rrsig_count)
                ]:
                    try:
                        ipv4_addr = inet_ntop(
                            AF_INET, rr_ip4
                        )  # IP bytes to display format
                        ipv4_resps.append(
                            {"ip": ipv4_addr, "ttl": int(rr_ttl4), "qname": qname_str}
                        )
                        if pfui_cfg["LOGGING"]:
                            log_info(
                                f"PFUIDNS: {qname_str} Found IPv4 address {ipv4_addr}"
                            )
                    except Exception as e:
                        log_err(
                            f"PFUIDNS: {qname_str} Invalid IPv4 address ({rr_ip4}, {rr_ttl4}). {e}"
                        )

            elif rr.rk.type_str == "AAAA":
                d = rr.entry.data
                # Last 16 bytes contain IPv6 address
                for rr_ip6, rr_ttl6 in [
                    (d.rr_data[j][-16:], int(d.rr_ttl[j]))
                    for j in range(d.count + d.rrsig_count)
                ]:
                    try:
                        ipv6_addr = inet_ntop(
                            AF_INET6, rr_ip6
                        )  # IP6 bytes to display format
                        ipv6_resps.append(
                            {"ip": ipv6_addr, "ttl": int(rr_ttl6), "qname": qname_str}
                        )
                        if pfui_cfg["LOGGING"]:
                            log_info(
                                f"PFUIDNS: {qname_str} Found IPv6 address {ipv6_addr}"
                            )
                    except Exception as e:
                        log_err(
                            f"PFUIDNS: {qname_str} Invalid IPv6 address ({rr_ip6}, {rr_ttl6}). {e}"
                        )

    if ipv4_resps or ipv6_resps:
        return {"AF4": ipv4_resps, "AF6": ipv6_resps}
    else:
        return False


def udp_transmit(soc, data, ip, port, retry=1):
    tries = 0
    while tries < retry:
        try:
            log_info(f"PFUIDNS: UDP Transmitting {len(data)} bytes")
            soc.sendto(data, (ip, port))
        except TIMEOUT:
            log_err(
                f"PFUIDNS: UDP socket timeout {ip}:{port}"
            )
        except Exception as e:
            log_err(f"PFUIDNS: UDP socket exception {ip}:{port}, '{e}'")
        msg = udp_receive(soc=soc, rcvbuf=40, retry=1)  # Wait pfui_firewall ack data
        if msg == b"ACKDATA":  # 40
            log_info(f"PFUIDNS: Received ACKDATA (transmit success): {msg}")
            return msg
        else:
            log_info(f"PFUIDNS: Received message not ACKDATA: {msg}")
        tries += 1
    log_info(f"PFUIDNS: timeout udp_transmit: buff {msg}")


def udp_receive(soc, rcvbuf=1400, retry=1):
    tries = 0
    while tries < retry:
        try:
            log_info(f"PFUIDNS: UDP waiting to recieve")
            msg, _ = soc.recvfrom(rcvbuf)
            if msg:
                return msg
        except TIMEOUT:
            log_err(
                "PFUIDNS: timeout udp_receive"
            )
        tries += 1
    log_info(f"PFUIDNS: Timeout udp receive - all retries")


def udp_transmit_close(data, ip, port, blocking):
    # setup udp socket
    soc = socket(AF_INET, SOCK_DGRAM)
    soc.setsockopt(SOL_SOCKET, SO_SNDBUF, 1400)
    soc.settimeout(pfui_cfg["SOCKET_TIMEOUT"])

    # transmit pf firewall data
    reply = udp_transmit(soc, data, ip, port, 40)

    # wait for pf firewall update
    if blocking:  # Wait for secondary ACKUPDATE
        msg = udp_receive(soc=soc, rcvbuf=42, retry=1)
        if msg == b"ACKUPDATE":
            log_info(
                "PFUIDNS: Recv pfui_firewall Update ACK"
            )
        else:
            log_info(f"PFUIDNS: Unexpected msg: {msg}")

    # close sender udp socket
    soc.close()


def tcp_transmit_close(data, ip, port, blocking):
    conn = socket(AF_INET, SOCK_STREAM)
    conn.settimeout(pfui_cfg["SOCKET_TIMEOUT"])
    conn.setsockopt(
        IPPROTO_TCP, TCP_NODELAY, True
    )  # Disable Nagle
    conn.setsockopt(
        SOL_SOCKET, SO_REUSEADDR, True
    )  # Fast Socket reuse
    conn.setsockopt(
        SOL_SOCKET, SO_SNDBUF, 0
    )  # Zero size Buffer (Zero buff, Send immediately?)
    # s.setsockopt(SOL_SOCKET, SO_SNDBUF, getsizeof(data))  # Exact send buff

    try:
        conn.connect((ip, port))
        conn.sendall(data + b"EOT")
    except TIMEOUT:
        log_err(
            "PFUIDNS: TCP Socket Timeout to firewall! Check pfui_firewall is running."
        )
    except ERROR:
        log_err(
            "PFUIDNS: TCP Socket Error! Check pfui_firewall is running."
        )
    except Exception as e:
        log_err(f"PFUIDNS: Unknown TCP Socket Exception! {e}")

    try:
        if blocking:
            _ = conn.recv(36)  # Wait for pfui_firewall to ACK(36)
            # TODO Verify ACK/NACK message
    except TIMEOUT:
        log_err(
            "PFUIDNS: Timeout waiting for pfui_firewall ACK."
        )
    except Exception as e:
        log_err(f"PFUIDNS: Unknown TCP Socket Exception while reading! {e}")
    finally:
        conn.close()


def transmit_all(pfui_dict, blocking=True):
    """PFUI: Transmits IP and TTL data to PF Firewalls running pfui_firewall."""

    if pfui_cfg["LOGGING"]:
        start = time()

    for fw in pfui_cfg["FIREWALLS"]:
        if fw["HOST"]:
            if "PORT" not in fw:
                fw["PORT"] = pfui_cfg["DEFAULT_PORT"]
            if pfui_cfg["LOGGING"]:
                log_info(f"PFUIDNS: Sending '{pfui_dict}' to {fw['HOST']}:{fw['PORT']}")

            # Encode JSON bytes, and (optional) Compress
            pfui_data = bytes(dumps(pfui_dict), "utf8")
            if pfui_cfg["COMPRESS"]:
                pfui_data = lz4.frame.compress(pfui_data)

            # TODO Update Multiple Firewalls in parallel (test Thread setup performance vs serial send)

            if pfui_cfg["SOCKET_PROTO"] == "UDP":
                udp_transmit_close(
                data=pfui_data,
                ip=fw["HOST"],
                port=fw["PORT"],
                blocking=blocking
            )
            elif pfui_cfg["SOCKET_PROTO"] == "TCP":
                tcp_transmit_close(
                data=pfui_data,
                ip=fw["HOST"],
                port=fw["PORT"],
                blocking=blocking
            )

    if pfui_cfg["LOGGING"]:
        log_info(f"PFUIDNS: Query Unblocked {(time() - start)*1000000} microsecs")


# Unbound functions (call points)
def inplace_cache_callback(
    qinfo, qstate, rep, rcode, edns, opt_list_out, region, **kwargs
):
    """pythonmod: Inplace callback function for cache responses."""
    if pfui_cfg["LOGGING"] and pfui_cfg["LOG_LEVEL"] == "DEBUG":
        log_info("pythonmod: cache_callback called - answering from cache.")

    if pfui_cfg["LOGGING"] and pfui_cfg["LOG_LEVEL"] == "DEBUG":
        log_info(
            f"Cache data - qinfo: {qinfo}, qstate: {qstate}, rep: {rep}, rcode: {rcode}, edns: {edns}, opt_list_out: {opt_list_out}, region: {region}"
        )

    if rep is not None:
        pfui_msg = read_rr(rep, qinfo.qname_str)
        if pfui_msg:
            transmit_all(pfui_msg, blocking=False)


def init(id, cfg):
    """
    Unbound Pythonmod Required
    pythonmod: Constructor
    id: module identifier (integer)
    cfg: Unbound config_file configuration structure
    """
    log_info(
        f"pythonmod: init, id {id}, cfg: {cfg}"
    )
    return True


def init_standard(id, env):
    """
    Unbound Pythonmod Required
    pythonmod: Register inplace_cache_callback() as the callback function for inspecting cache responses.
    (Iterator module not called for cache responses).
    id: module identifier (integer)
    env: module_env module environment
    """
    if pfui_cfg["LOGGING"] and pfui_cfg["LOG_LEVEL"] == "DEBUG":
        log_info(
            f"pythonmod: init_standard, id {id}, port: {env.cfg.port}, script: {env.cfg.python_script}"
        )

    if not register_inplace_cb_reply_cache(inplace_cache_callback, env, id):
        return False
    return True


def deinit(id):
    """
    Unbound Pythonmod Required
    pythonmod: Deconstructor
    id: module identifier (integer)
    """
    if pfui_cfg["LOGGING"] and pfui_cfg["LOG_LEVEL"] == "DEBUG":
        log_info(f"pythonmod: deinit, id {id}")
    return True


def inform_super(id, qstate, superqstate, qdata):
    """
    Unbound Pythonmod Required
    Inform super querystate about the results from this subquerystate.
    Is called when the querystate is finished.
    id: module identifier (integer)
    qstate: module_qstate Query state
    superqstate: pythonmod_qstate Mesh state
    qdata: query_info Query data
    """
    if pfui_cfg["LOGGING"] and pfui_cfg["LOG_LEVEL"] == "DEBUG":
        log_info(f"pythonmod: inform_super, id {id}, qstate {qstate}")
    return True


def operate(id, event, qstate, qdata):
    """
    Unbound Pythonmod Required
    pythonmod: Called when processing new (non-cached) queries. 'event' defines state-machine state.
    PFUI is only invoked after a domain has been successfully resolved by the Iterator
    and a valid RR exists (MODULE_EVENT_MODDONE).
    id: module identifier (integer)
    qstate: module_qstate Query state
    qdata: query_info Query data
    """

    if pfui_cfg["LOGGING"]:
        log_info(
            "pythonmod: operate, id: {}, event {}".format(
                str(id), str(strmodulevent(event))
            )
        )

    if event == MODULE_EVENT_MODDONE:
        if pfui_cfg["LOGGING"]:
            log_info(
                "pythonmod: MODULE_EVENT_MODDONE (Iterator finished, inspecting RR)"
            )
        pfui_msg = None
        if qstate.return_msg:
            if pfui_cfg["LOGGING"] and pfui_cfg["LOG_LEVEL"] == "DEBUG":
                if qstate.return_msg.qinfo:
                    logger(qstate)
            if qstate.return_msg.rep:
                pfui_msg = read_rr(qstate.return_msg.rep, qstate.qinfo.qname_str)
        if pfui_msg:
            transmit_all(pfui_msg, pfui_cfg["BLOCKING"])
        qstate.ext_state[id] = MODULE_FINISHED
        return True

    if event == MODULE_EVENT_NEW:
        if pfui_cfg["LOGGING"]:
            log_info("pythonmod: MODULE_EVENT_NEW")
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_PASS:
        if pfui_cfg["LOGGING"]:
            log_info("pythonmod: MODULE_EVENT_PASS")
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    log_err(
        f"pythonmod: MODULE_ERROR. Unknown EVENT; id {id}, event {event}, qstate {qstate}"
    )
    if qstate:
        logger(qstate)
    qstate.ext_state[id] = MODULE_ERROR
    return True


if __name__ == "__main__":
    try:
        pfui_cfg = safe_load(open(CONFIG_LOCATION))
        if "SOCKET_PROTO" not in pfui_cfg:
            pfui_cfg["SOCKET_PROTO"] = "TCP"
        if "BLOCKING" not in pfui_cfg:
            pfui_cfg["BLOCKING"] = True

    except Exception as e:
        log_err(
            f"PFUIDNS: Yaml Config File (pfui_unbound.yml) not found or cannot load: {e}"
        )
        exit(1)

    log_info("PFUIDNS: python module for Unbound loaded.")
