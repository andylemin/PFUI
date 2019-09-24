#!/usr/bin/env python3

"""
Written using example python module scripts found in Unbound source.

inplace_cache_callback(), init(), init_standard(), deinit(), inform_super(), and operate() are SWIG provided functions
declared here and called by Unbound depending on EVENT type..

:param qinfo: query_info struct;
:param qstate: module qstate. None;
:param rep: reply_info struct;
:param rcode: return code for the query;
:param edns: edns_data sent from client side. List with EDNS options is accessible through edns.opt_list. Do not alter;
:param opt_list_out: List with the EDNS options that will be sent as reply. It can be populated with EDNS options;
:param region: region to allocate temporary data. Used when we want to append a new option to opt_list_out.
:param qdata: ??
:param superqstate: ??
:param rr: DNS Resource Record
"""

import socket
from sys import exit
from time import time
from json import dumps
from yaml import safe_load


def dataHex(data, prefix=""):
    """ Converts binary string data to display form.
        Function taken from Unbound source examples. """

    res = ""
    for i in range(0, (len(data)+15)/16):
        res += "%s0x%02X | " % (prefix, i*16)
        d = map(lambda x: ord(x), data[i*16:i*16+17])
        for ch in d:
            res += "%02X " % ch
        for i in range(0, 17-len(d)):
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
    """ Logs Response. Requires Unbound to run in daemon mode (-dv) """

    r = qstate.return_msg.rep
    q = qstate.return_msg.qinfo
    print("-"*100)
    print("Query: {}, type: {} ({}), class: {} ({}) ".format(
            str(qstate.qinfo.qname_str), str(qstate.qinfo.qtype_str), str(qstate.qinfo.qtype),
            str(qstate.qinfo.qclass_str), str(qstate.qinfo.qclass)))
    print("-"*100)
    print("Return    reply :: flags: {}, QDcount: {}, Security:{}, TTL={}".format(str(r.flags), str(r.qdcount),
                                                                                  str(r.security), str(r.ttl)))
    print("          qinfo :: qname: {} {}, qtype: {}, qclass: {}".format(str(q.qname_list), str(q.qname_str),
                                                                          str(q.qtype_str), str(q.qclass_str)))
    if r:
        print("Reply:")
        for i in range(0, r.rrset_count):
            rr = r.rrsets[i]
            rk = rr.rk
            print(i, ":", rk.dname_list, rk.dname_str, "flags: {}".format(str(rk.flags)))
            print("type:{} ({}) class: {} ({})".format(str(rk.type_str), str(socket.ntohs(rk.type)),
                                                       str(rk.rrset_class_str), str(socket.ntohs(rk.rrset_class))))

            d = rr.entry.data
            for j in range(0, d.count+d.rrsig_count):
                print("")
                print("   {} : TTL= {}").format(str(j), str(d.rr_ttl[j]))
                if j >= d.count:
                    print("rrsig")
                print("")
                print("HEX:  {}".format(dataHex(d.rr_data[j])))
                if rk.type_str == 'A':
                    print("IPv4: {}".format(str(socket.inet_ntop(socket.AF_INET, d.rr_data[j][-4:]))))
                if rk.type_str == 'AAAA':
                    print("IPv6: {}".format(str(socket.inet_ntop(socket.AF_INET6, d.rr_data[j][-16:]))))
    print("-"*100)


def read_rr(qstate=None, rep=None):
    """ Inspects the RR Data, extracts IPs and TTLs, and populates data structure.
        Data Structure: {'AF4': [{"ip": ipv4_addr, "ttl": ip_ttl }], 'AF6': [{"ip": ipv6_addr, "ttl": ip_ttl }]} """

    ipv4, ipv6 = [], []
    try:
        r = qstate.return_msg.rep
    except:
        r = rep
    if r:
        for i in range(0, r.rrset_count):
            rr = r.rrsets[i]
            if cfg['DEBUG']:
                log_info("PFUI: r.rrsets[{}]: rr.rk.type_str {}".format(str(i), str(rr.rk.type_str)))
            if rr.rk.type_str == 'A':
                d = rr.entry.data
                for j in range(0, d.count+d.rrsig_count):
                    rr_ip = d.rr_data[j][-4:]  # Last four bytes contain the IPv4 address
                    try:
                        ip = socket.inet_ntop(socket.AF_INET, rr_ip)  # IP bytes to display format
                        ipv4.append({"ip": ip, "ttl": int(d.rr_ttl[j])})
                        if cfg['DEBUG']:
                            log_info("PFUI: Found IPv4 address {}".format(str(ipv4[-1])))
                    except:
                        log_err("PFUI: Invalid IPv4 address {}".format(str(ip)))
            elif rr.rk.type_str == 'AAAA':
                d = rr.entry.data
                for j in range(0, d.count+d.rrsig_count):
                    rr_ip = d.rr_data[j][-16:]  # TODO: Test and verify
                    try:
                        ip = socket.inet_ntop(socket.AF_INET6, rr_ip)
                        ipv6.append({"ip": ip, "ttl": int(d.rr_ttl[j])})
                        if cfg['DEBUG']:
                            log_info("PFUI: Found IPv6 address {}".format(str(ipv6[-1])))
                    except:
                        log_err("PFUI: Invalid IPv6 address {}".format(str(ip)))

        if ipv4 or ipv6:
            return {'AF4': ipv4, 'AF6': ipv6}
        else:
            return False


def transmit(ip_dict):
    """ Transmits IP and TTL data structure to PF Firewalls running pfui_server. """

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 0)        # Zero Buffer size (always send)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)  # Disable Nagle
    for fw in cfg['FIREWALLS']:
        if fw['HOST']:
            if not fw['PORT']:
                fw['PORT'] = cfg['DEFAULT_PORT']
            try:
                if cfg['DEBUG']:
                    log_info("PFUI: SENDING DATA: {} {}".format(str(type(ip_dict)), str(ip_dict)))
                    start = int(round(time() * 1000))
                s.connect((fw['HOST'], fw['PORT']))
                s.sendall(dumps(ip_dict))
                if cfg['DEBUG']:
                    end = int(round(time() * 1000))
                    log_info("PFUI: {} milliseconds".format(str(end - start)))
            except Exception as e:
                log_err("PFUI: Failed to send " + str(e))
            s.close()


def inplace_cache_callback(qinfo, qstate, rep, rcode, edns, opt_list_out, region, **kwargs):
    """ Inplace callback function for cache responses. """

    if cfg['DEBUG']:
        log_info("PFUI: pythonmod: cache_callback called while answering from cache.")
    if rep:
        struct = read_rr(rep=rep)
    if struct:
        transmit(struct)
    return True


def init(id, cfg):
    if cfg['DEBUG']:
        log_info("PFUI: pythonmod: init called, module id {} port: {} script: {}".format(str(id),
                                                                                          str(cfg.port),
                                                                                          str(cfg.python_script)))
    return True


def init_standard(id, env):
    """ Register inplace_cache_callback() as the callback function for inspecting cache responses.
        (Iterator is not called for cache responses). """

    if cfg['DEBUG']:
        log_info("PFUI: pythonmod: init_standard called, module id {} port: {} script: {}".format(str(id),
                                                                                          str(cfg.port),
                                                                                          str(cfg.python_script)))
    if not register_inplace_cb_reply_cache(inplace_cache_callback, env, id):
        return False
    return True


def deinit(id):
    if cfg['DEBUG']:
        log_info("PFUI: pythonmod: deinit called, module id {}".format(str(id)))
    return True


def inform_super(id, qstate, superqstate, qdata):
    if cfg['DEBUG']:
        log_info("PFUI: pythonmod: inform_super called, module is is {}. qstate is {}".format(str(id), str(qstate)))
    return True


def operate(id, event, qstate, qdata):
    """ When event == 'MODULE_EVENT_MODDONE' (Iterator finished) inspect RR response. """

    if cfg['DEBUG']:
        log_info("PFUI: pythonmod: operate called, id: {}, event:{}".format(str(id), str(strmodulevent(event))))

    if event == MODULE_EVENT_NEW:
        if cfg['DEBUG']:
            log_info("PFUI: pythonmod: MODULE_EVENT_NEW")
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if event == MODULE_EVENT_MODDONE:
        if cfg['DEBUG'] and qstate:
            log_info("PFUI: pythonmod: MODULE_EVENT_MODDONE (Iterator finished, inspecting response)")
            logger(qstate)
        if qstate.return_msg:
            struct = read_rr(qstate=qstate)
        if struct:
            transmit(struct)

        qstate.ext_state[id] = MODULE_FINISHED
        if cfg['DEBUG']:
            log_info("PFUI: pythonmod: MODULE_FINISHED")
        return True

    if event == MODULE_EVENT_PASS:
        if cfg['DEBUG']:
            log_info("PFUI: pythonmod: MODULE_EVENT_PASS")
        qstate.ext_state[id] = MODULE_WAIT_MODULE
        return True

    if cfg['DEBUG']:
        log_err("PFUI: pythonmod: MODULE_ERROR")
    qstate.ext_state[id] = MODULE_ERROR
    return True


if __name__ == '__main__':
    try:
        cfg = safe_load(open('pfui_client.yml'))
    except Exception as e:
        log_err("PFUI: YAML Config File pfui_client.yml not found or cannot load: " + str(e))
        exit(1)

    log_info("Unbound pythonmod: script loaded.")
