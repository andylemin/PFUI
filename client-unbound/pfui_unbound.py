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

import sys
from os.path import dirname
from sys import exit
from time import time
from yaml import safe_load

CONFIG_LOCATION = "/var/unbound/etc/pfui_unbound.yml"

# Unbound runs this file in the embedded interpreter's __main__ namespace, so the
# directory holding it is not on sys.path and __file__ cannot be relied on. The
# installer puts the shared pfui/ package beside this config, so derive it from
# there: one hardcoded location, same as CONFIG_LOCATION itself.
sys.path.insert(0, dirname(CONFIG_LOCATION))
from pfui_wire import encode_payload, frame  # noqa: E402

from socket import (
    AF_INET,
    AF_INET6,
    AF_UNIX,
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
                # Only the first d.count records hold addresses; the rest are
                # signatures. Reading their trailing bytes as an address printed
                # a fabricated one, the same defect read_rr was fixed for
                if j < d.count:
                    if rk.type_str == "A":
                        log_info(f"IPv4: {inet_ntop(AF_INET, d.rr_data[j][-4:])}")
                    if rk.type_str == "AAAA":
                        log_info(f"IPv6: {inet_ntop(AF_INET6, d.rr_data[j][-16:])}")
    log_info("-" * 100)


def read_rr(rep=None, qname_str="", from_cache=False):
    """PFUI: Inspects RR response data, extracts IPs and TTLs, and returns PFUI Firewall data structure.
    Data Structure: {'kind': 'rr'|'cache', 'qname': qname_str,
                     'AF4': [{"ip": ipv4_addr, "ttl": ip4_ttl}],
                     'AF6': [{"ip": ipv6_addr, "ttl": ip6_ttl}]}
    qname is per message, not per record: every record in one reply shares the
    query name, so repeating it once per address was pure duplication.
    On the cache path Unbound reports rr_ttl as an absolute expiry timestamp, on
    the reply path as a relative TTL. 'kind' records which, so the firewall does
    not have to guess from the magnitude.
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
                # d.count addresses, then d.rrsig_count signatures. Reading the
                # signatures as addresses would whitelist arbitrary bytes.
                for rr_ip4, rr_ttl4 in [
                    (d.rr_data[j][-4:], int(d.rr_ttl[j]))
                    for j in range(d.count)
                ]:
                    try:
                        ipv4_addr = inet_ntop(
                            AF_INET, rr_ip4
                        )  # IP bytes to display format
                        ipv4_resps.append({"ip": ipv4_addr, "ttl": int(rr_ttl4)})
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
                    for j in range(d.count)
                ]:
                    try:
                        ipv6_addr = inet_ntop(
                            AF_INET6, rr_ip6
                        )  # IP6 bytes to display format
                        ipv6_resps.append({"ip": ipv6_addr, "ttl": int(rr_ttl6)})
                        if pfui_cfg["LOGGING"]:
                            log_info(
                                f"PFUIDNS: {qname_str} Found IPv6 address {ipv6_addr}"
                            )
                    except Exception as e:
                        log_err(
                            f"PFUIDNS: {qname_str} Invalid IPv6 address ({rr_ip6}, {rr_ttl6}). {e}"
                        )

    if ipv4_resps or ipv6_resps:
        return {
            "kind": "cache" if from_cache else "rr",
            "qname": qname_str,
            "AF4": ipv4_resps,
            "AF6": ipv6_resps,
        }
    else:
        return False


def udp_transmit(soc, data, ip, port, retry=1):
    tries = 0
    msg = None  # retry may be 0, and the summary below reads this
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
    # ACK wait is deliberately shorter than SOCKET_TIMEOUT: with 40 retries at
    # 3s each a down firewall blocked the resolver for ~2 minutes per query
    soc.settimeout(float(pfui_cfg["UDP_ACK_TIMEOUT"]))

    # transmit pf firewall data
    reply = udp_transmit(soc, data, ip, port, int(pfui_cfg["UDP_RETRY"]))
    breaker_record(f"{ip}:{port}", ok=(reply == b"ACKDATA"))

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


# Per-firewall circuit breaker state: {target: [consecutive_failures, open_until]}
# Keyed on the target's label rather than an (ip, port) pair, so a local socket
# path is as much a distinct destination as an address and port are
_breakers = {}


def breaker_open(target):
    """True while this firewall is in its cool-off window.

    A closed breaker keeps its failure count. Clearing it on every check, which is
    what this did, reset the count once per query and so held it at 1 forever: with
    any BREAKER_FAILURES above 1 the breaker could never trip, and every query kept
    paying the full timeout for a firewall that was plainly down. Only an elapsed
    cool-off clears the count, which is the one case that means "probe again".
    """
    state = _breakers.get(target)
    if not state:
        return False
    if not state[1]:  # Closed and counting failures
        return False
    if state[1] > time():
        return True
    state[0], state[1] = 0, 0  # Cool-off elapsed, probe again
    return False


def breaker_record(target, ok):
    """Count consecutive failures and open the breaker once the threshold trips."""
    state = _breakers.setdefault(target, [0, 0])
    if ok:
        state[0], state[1] = 0, 0
        return
    state[0] += 1
    if state[0] >= int(pfui_cfg["BREAKER_FAILURES"]):
        state[1] = time() + float(pfui_cfg["BREAKER_COOLOFF"])
        log_err(
            f"PFUIDNS: {target} unreachable {state[0]}x, skipping it for "
            f"{pfui_cfg['BREAKER_COOLOFF']}s (PF still denies the traffic)"
        )


def stream_transmit_close(data, family, address, target, blocking):
    """Send one framed message over a stream socket and wait for the ACK.

    Shared by the TCP and the local-socket paths: both carry the same
    length-prefixed frame and get the same reply, so only the socket family, the
    address and the latency controls differ.
    """
    conn = socket(family, SOCK_STREAM)
    conn.settimeout(pfui_cfg["SOCKET_TIMEOUT"])
    if family == AF_INET:
        conn.setsockopt(
            IPPROTO_TCP, TCP_NODELAY, True
        )  # Disable Nagle
        conn.setsockopt(
            SOL_SOCKET, SO_REUSEADDR, True
        )  # Fast Socket reuse
        # No SO_SNDBUF here: setting it to 0 does not mean "send immediately", the
        # kernel clamps it to its minimum, and a small send buffer only adds syscalls
        # and blocking on large messages. TCP_NODELAY above is the latency control.
    # A local socket needs neither: there is no Nagle to disable and no
    # TIME_WAIT to reuse, which is most of why it is faster than loopback TCP.

    sent = False
    try:
        conn.connect(address)
        conn.sendall(frame(data))
        sent = True
    except TIMEOUT:
        breaker_record(target, ok=False)
        log_err(
            f"PFUIDNS: Socket Timeout to firewall {target}! Check pfui_firewall is running."
        )
    except ERROR as e:
        breaker_record(target, ok=False)
        log_err(
            f"PFUIDNS: Socket Error to firewall {target} ({e})! Check pfui_firewall "
            f"is running, and that this user may write the socket if it is local."
        )
    except Exception as e:
        breaker_record(target, ok=False)
        log_err(f"PFUIDNS: Unknown Socket Exception to {target}! {e}")

    # The breaker counts a successful acknowledgement, not a successful send. A
    # firewall that completes the handshake and then never replies looked healthy
    # to the old accounting, so the breaker never opened and every subsequent
    # query paid SOCKET_TIMEOUT in full, forever. A refusal counts as a failure
    # too: the firewall is reachable but is not whitelisting anything, and PF
    # keeps denying the traffic either way.
    try:
        if blocking and sent:  # Nothing to acknowledge if the send failed
            reply = conn.recv(36)  # Wait for pfui_firewall to ACK
            breaker_record(target, ok=(reply == b"ACKUPDATE"))
            if reply != b"ACKUPDATE":
                # The firewall replies with a reason when it refuses a message,
                # e.g. a version skew that leaves the wire format mismatched
                log_err(
                    f"PFUIDNS: {target} did not confirm the update: {reply!r}"
                )
        elif sent:
            # Non-blocking: delivery is the only thing observable from here
            breaker_record(target, ok=True)
    except TIMEOUT:
        breaker_record(target, ok=False)
        log_err(
            f"PFUIDNS: Timeout waiting for pfui_firewall ACK from {target}."
        )
    except Exception as e:
        breaker_record(target, ok=False)
        log_err(f"PFUIDNS: Unknown Socket Exception while reading {target}! {e}")
    finally:
        conn.close()


def tcp_transmit_close(data, ip, port, blocking):
    stream_transmit_close(
        data=data,
        family=AF_INET,
        address=(ip, int(port)),
        target=f"{ip}:{port}",
        blocking=blocking,
    )


def unix_transmit_close(data, path, blocking):
    """Send to a PFUI_Firewall on this same host over its local socket.

    There is no PF rule guarding this transport, because there is no packet: the
    permissions on the socket are the whole access control, so a connect() that
    fails with EACCES means this resolver's user is not in the firewall's
    SOCKET_UNIX_GROUP.
    """
    stream_transmit_close(
        data=data,
        family=AF_UNIX,
        address=path,
        target=path,
        blocking=blocking,
    )


def firewall_target(fw):
    """How to reach one FIREWALLS entry, or None if it names no firewall.

    Returns (kind, target, address). 'target' is the label the circuit breaker and
    the logs key on, so it must identify one destination uniquely.

    An entry carries either SOCKET, for a PFUI_Firewall on this same host, or
    HOST, for one reached over the network with SOCKET_PROTO. Per entry rather
    than per resolver, because a CARP node runs both at once: the local firewall
    over its socket, and the peer over TCP.
    """
    path = fw.get("SOCKET")
    if path:
        return "UNIX", str(path), str(path)
    host = fw.get("HOST")
    if not host:
        return None
    # 'or' rather than a get() default: a 'PORT:' left empty in the yml parses as
    # None, which is not the same as absent
    port = int(fw.get("PORT") or pfui_cfg["DEFAULT_PORT"])
    return pfui_cfg["SOCKET_PROTO"], f"{host}:{port}", (host, port)


def transmit_all(pfui_dict, blocking=True):
    """PFUI: Transmits IP and TTL data to PF Firewalls running pfui_firewall."""

    if pfui_cfg["LOGGING"]:
        start = time()

    # Encoded once for all firewalls, and only if there is one to send to: the
    # bytes are identical per destination, and this runs on the blocking DNS path
    # where a second lz4 pass per firewall was pure duplicated work
    pfui_data = None

    for fw in pfui_cfg["FIREWALLS"]:
        destination = firewall_target(fw)
        if destination is None:
            continue
        kind, target, address = destination

        if breaker_open(target):
            log_info(f"PFUIDNS: Skipping {target}, circuit breaker open")
            continue
        if pfui_cfg["LOGGING"]:
            log_info(f"PFUIDNS: Sending '{pfui_dict}' to {target}")

        # JSON, optionally lz4 compressed. Both stream transports add a length
        # prefix below; only UDP sends the payload alone
        if pfui_data is None:
            pfui_data = encode_payload(pfui_dict, compress=pfui_cfg["COMPRESS"])

        # TODO Update Multiple Firewalls in parallel (test Thread setup performance vs serial send)
        # Serial today: with BLOCKING each firewall's full round trip is added
        # to the query. The circuit breaker keeps an unreachable one from
        # contributing its timeout, but a healthy CARP pair still doubles the
        # block time.

        if kind == "UNIX":
            unix_transmit_close(data=pfui_data, path=address, blocking=blocking)
        elif kind == "UDP":
            udp_transmit_close(
                data=pfui_data,
                ip=address[0],
                port=address[1],
                blocking=blocking,
            )
        elif kind == "TCP":
            tcp_transmit_close(
                data=pfui_data,
                ip=address[0],
                port=address[1],
                blocking=blocking,
            )
        else:
            # Unreachable: the config load validates this. Kept so a proto
            # that reaches here is loud, rather than silently whitelisting
            # nothing while the resolver looks perfectly healthy
            log_err(
                f"PFUIDNS: SOCKET_PROTO '{pfui_cfg['SOCKET_PROTO']}' is not TCP "
                f"or UDP; {target} was not told about {pfui_dict}"
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
        pfui_msg = read_rr(rep, qinfo.qname_str, from_cache=True)
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


# pythonmod injects these into this module's globals. strmodulevent() is not
# used to name an event: its binding rejects anything outside 'enum module_ev'
# with an OverflowError, and a log line must not be able to fail.
EVENT_NAMES = (
    "MODULE_EVENT_NEW",
    "MODULE_EVENT_PASS",
    "MODULE_EVENT_REPLY",
    "MODULE_EVENT_NOREPLY",
    "MODULE_EVENT_CAPSFAIL",
    "MODULE_EVENT_MODDONE",
    "MODULE_EVENT_ERROR",
)


def event_name(event):
    """Name for a pythonmod event value, or the value itself if unrecognised."""
    for name in EVENT_NAMES:
        if globals().get(name) == event:
            return name
    return f"event {event!r}"


def describe_exception(exc):
    """One-line type, message and call site for an exception.

    Built from the traceback object by hand because pythonmod's own reporter
    cannot always import io to format one.
    """
    where = []
    tb = exc.__traceback__
    while tb:
        code = tb.tb_frame.f_code
        where.append(f"{code.co_name}:{tb.tb_lineno}")
        tb = tb.tb_next
    return f"{type(exc).__name__}: {exc} at {' -> '.join(where) or 'unknown'}"


def operate(id, event, qstate, qdata):
    """
    Unbound Pythonmod Required
    pythonmod: Called when processing new (non-cached) queries. 'event' defines state-machine state.
    PFUI is only invoked after a domain has been successfully resolved by the Iterator
    and a valid RR exists (MODULE_EVENT_MODDONE).
    id: module identifier (integer)
    qstate: module_qstate Query state
    qdata: query_info Query data

    Nothing is allowed to raise out of here: an exception reaching pythonmod
    fails the query, so a PFUI fault would take DNS resolution with it.
    """
    try:
        return _operate(id, event, qstate, qdata)
    except Exception as exc:
        log_err(f"PFUIDNS: {describe_exception(exc)}")
        try:
            qstate.ext_state[id] = MODULE_WAIT_MODULE
        except Exception:
            pass
        return True


def _operate(id, event, qstate, qdata):

    if pfui_cfg["LOGGING"]:
        log_info(f"pythonmod: operate, id: {id}, {event_name(event)}")

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
        try:
            logger(qstate)  # Best effort: derefs qstate.return_msg, which may be None
        except Exception as e:
            log_err(f"pythonmod: could not log qstate: {e}")
        qstate.ext_state[id] = MODULE_ERROR
    return True


# Every key this module reads, with the value assumed when the yml omits it.
# Partial defaults meant a config predating an option raised KeyError from inside
# a query - after Unbound had already loaded the module and before ext_state was
# set - so the resolver failed per lookup rather than at start.
CONFIG_DEFAULTS = {
    "LOGGING": True,
    "LOG_LEVEL": "ERROR",
    "COMPRESS": True,
    "SOCKET_PROTO": "TCP",
    "SOCKET_TIMEOUT": 3,
    "BLOCKING": True,
    "UDP_RETRY": 3,
    "UDP_ACK_TIMEOUT": 0.5,
    "BREAKER_FAILURES": 3,
    "BREAKER_COOLOFF": 30,
    "DEFAULT_PORT": 10001,
    "FIREWALLS": [],  # Nothing to send to; warned about below rather than guessed
}


def load_config(location=CONFIG_LOCATION):
    """Read the yml, apply the defaults, and reject a config that cannot work.

    Raises ValueError on a SOCKET_PROTO the transmit path does not implement,
    which would otherwise leave the resolver answering normally while telling no
    firewall anything.
    """
    cfg = safe_load(open(location)) or {}
    for key, value in CONFIG_DEFAULTS.items():
        cfg.setdefault(key, value)
    cfg["SOCKET_PROTO"] = str(cfg["SOCKET_PROTO"]).strip().upper()
    if cfg["SOCKET_PROTO"] not in ("TCP", "UDP"):
        raise ValueError(
            f"SOCKET_PROTO must be TCP or UDP, not '{cfg['SOCKET_PROTO']}'"
        )

    # SOCKET_PROTO governs the network entries only. A SOCKET entry is always a
    # local stream socket carrying the same frames, so UDP does not apply to it.
    for index, fw in enumerate(cfg["FIREWALLS"] or []):
        if not isinstance(fw, dict):
            raise ValueError(f"FIREWALLS[{index}] is not a mapping: {fw!r}")
        socket_path, host = fw.get("SOCKET"), fw.get("HOST")
        if socket_path and host:
            raise ValueError(
                f"FIREWALLS[{index}] sets both SOCKET ({socket_path}) and HOST "
                f"({host}); one firewall is reached one way or the other"
            )
        if socket_path and not str(socket_path).startswith("/"):
            raise ValueError(
                f"FIREWALLS[{index}] SOCKET must be an absolute path, "
                f"not '{socket_path}'"
            )
        # An entry with neither is skipped by firewall_target rather than
        # rejected: a commented-out placeholder left with an empty HOST has
        # always been tolerated, and refusing to load would break configs that
        # work today. It is worth saying out loud, though
        if not socket_path and not host:
            log_err(
                f"PFUIDNS: FIREWALLS[{index}] names neither SOCKET nor HOST "
                f"({fw}); it will be skipped"
            )
    return cfg


if __name__ == "__main__":
    try:
        pfui_cfg = load_config()
    except Exception as e:
        log_err(
            f"PFUIDNS: Yaml Config File (pfui_unbound.yml) not found or cannot load: {e}"
        )
        exit(1)

    if not pfui_cfg["FIREWALLS"]:
        log_err(
            "PFUIDNS: No FIREWALLS configured; resolved addresses will not be "
            f"whitelisted anywhere. Add them to {CONFIG_LOCATION}"
        )

    log_info("PFUIDNS: python module for Unbound loaded.")
