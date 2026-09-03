"""Contract tests for the Unbound python module.

pfui_unbound.py is a plugin: Unbound imports it into the embedded interpreter's
__main__ namespace, injects log_info/log_err and the MODULE_* constants, and
calls init/init_standard/deinit/inform_super/operate/inplace_cache_callback
itself. Nothing in PFUI calls them, so nothing in PFUI would notice if one were
renamed, lost a parameter, or stopped existing - which is what these tests are
for.

They import the file as an ordinary module, so the __main__ block does not run
and pfui_cfg is never set. That is deliberate: it proves module-level code needs
neither Unbound's injected symbols nor its config to load.
"""

import importlib.util
import inspect
import shutil
import socket
import sys
import tempfile
import time
from pathlib import Path
from threading import Event, Thread

import pytest
import yaml

COMPONENT = Path(__file__).resolve().parent.parent

# Unbound's pythonmod injects these; supply stubs so call-time lookups resolve
INJECTED = {
    "log_info": lambda *a, **k: None,
    "log_err": lambda *a, **k: None,
    "MODULE_EVENT_NEW": 0,
    "MODULE_EVENT_PASS": 1,
    "MODULE_EVENT_MODDONE": 4,
    "MODULE_FINISHED": 2,
    "MODULE_ERROR": 4,
    "MODULE_WAIT_MODULE": 1,
    "strmodulevent": lambda e: str(e),
}


@pytest.fixture(scope="module")
def plugin():
    sys.path.insert(0, str(COMPONENT))
    spec = importlib.util.spec_from_file_location(
        "pfui_unbound_plugin", COMPONENT / "pfui_unbound.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    for name, value in INJECTED.items():
        setattr(mod, name, value)
    return mod


def test_module_loads_without_unbound_or_config(plugin):
    """Module-level code must not need the config or Unbound's injected symbols:
    a failure here means the resolver cannot load the plugin at all."""
    assert plugin.CONFIG_LOCATION.endswith("pfui_unbound.yml")


def test_module_loads_without_dunder_file():
    """Unbound executes the script rather than importing it, so __file__ may not
    be defined in the namespace it runs in. importlib always sets __file__, so
    the fixture above cannot catch a dependency on it; exec the source in a bare
    namespace instead.
    """
    source = (COMPONENT / "pfui_unbound.py").read_text()
    sys.path.insert(0, str(COMPONENT))
    namespace = {"__name__": "pfui_unbound_no_file"}  # deliberately no __file__
    exec(compile(source, "pfui_unbound.py", "exec"), namespace)
    assert callable(namespace["operate"])
    assert callable(namespace["read_rr"])


@pytest.mark.parametrize(
    "name,params",
    [
        ("init", ["id", "cfg"]),
        ("init_standard", ["id", "env"]),
        ("deinit", ["id"]),
        ("inform_super", ["id", "qstate", "superqstate", "qdata"]),
        ("operate", ["id", "event", "qstate", "qdata"]),
    ],
)
def test_required_entry_points_keep_their_signatures(plugin, name, params):
    """Unbound calls these positionally; a renamed or dropped parameter breaks
    the resolver at load or first query."""
    fn = getattr(plugin, name, None)
    assert callable(fn), f"pythonmod entry point {name}() is missing"
    assert list(inspect.signature(fn).parameters) == params


def test_inplace_cache_callback_signature(plugin):
    """Registered with register_inplace_cb_reply_cache, which passes these by
    keyword, plus **kwargs for forward compatibility."""
    fn = plugin.inplace_cache_callback
    params = inspect.signature(fn).parameters
    for expected in (
        "qinfo",
        "qstate",
        "rep",
        "rcode",
        "edns",
        "opt_list_out",
        "region",
    ):
        assert expected in params, f"inplace_cache_callback lost {expected}"
    assert any(p.kind is p.VAR_KEYWORD for p in params.values())


def test_init_functions_return_true(plugin):
    """pythonmod treats a false return from init/init_standard as failure."""
    plugin.pfui_cfg = {"LOGGING": False, "LOG_LEVEL": "ERROR"}
    assert plugin.init(0, None) is True
    assert plugin.deinit(0) is True
    assert plugin.inform_super(0, None, None, None) is True


def test_read_rr_labels_the_source(plugin):
    """The firewall branches on this label instead of guessing from the TTL
    magnitude, so the two call sites must disagree about it."""
    plugin.pfui_cfg = {"LOGGING": False, "LOG_LEVEL": "ERROR"}
    assert plugin.read_rr(rep=None) is False  # no records, nothing to send

    class FakeData:
        count = 1
        rrsig_count = 0
        rr_ttl = [3600]
        rr_data = [b"\x00\x04" + bytes([8, 8, 8, 8])]

    class FakeKey:
        type_str = "A"

    class FakeRRset:
        rk = FakeKey()

        class entry:
            data = FakeData()

    class FakeRep:
        rrset_count = 1
        rrsets = [FakeRRset()]

    from_reply = plugin.read_rr(FakeRep(), "example.com.", from_cache=False)
    from_cache = plugin.read_rr(FakeRep(), "example.com.", from_cache=True)
    assert from_reply["kind"] == "rr"
    assert from_cache["kind"] == "cache"
    assert from_reply["AF4"] == [{"ip": "8.8.8.8", "ttl": 3600}]
    # qname appears once for the whole message, not once per address
    assert from_reply["qname"] == "example.com."


def test_operate_finishes_on_moddone_without_a_reply(plugin):
    """MODULE_EVENT_MODDONE with no return_msg must still finish the module."""
    plugin.pfui_cfg = {"LOGGING": False, "LOG_LEVEL": "ERROR", "BLOCKING": True}

    class QState:
        return_msg = None
        ext_state = {}

    qstate = QState()
    assert plugin.operate(0, plugin.MODULE_EVENT_MODDONE, qstate, None) is True
    assert qstate.ext_state[0] == plugin.MODULE_FINISHED

def test_rrsig_rdata_is_not_read_as_an_address(plugin):
    """An rrset carries d.count addresses followed by d.rrsig_count signatures.
    Reading the signatures as addresses whitelisted their trailing bytes, which
    an attacker controls, so every signed answer leaked one arbitrary IP."""
    plugin.pfui_cfg = {"LOGGING": False, "LOG_LEVEL": "ERROR"}

    class FakeData:
        count = 1  # one A record
        rrsig_count = 1  # plus its signature
        rr_ttl = [3600, 3600]
        rr_data = [
            b"\x00\x04" + bytes([8, 8, 8, 8]),  # the address
            b"\x00\x88" + bytes(0x84) + bytes([136, 137, 138, 139]),  # signature
        ]

    class FakeKey:
        type_str = "A"

    class FakeRRset:
        rk = FakeKey()

        class entry:
            data = FakeData()

    class FakeRep:
        rrset_count = 1
        rrsets = [FakeRRset()]

    msg = plugin.read_rr(FakeRep(), "signed.example.com.")
    addresses = [r["ip"] for r in msg["AF4"]]
    assert addresses == ["8.8.8.8"], f"signature bytes leaked as {addresses}"


def test_rrsig_only_rrset_yields_nothing(plugin):
    """A signature with no address alongside it must produce no records."""
    plugin.pfui_cfg = {"LOGGING": False, "LOG_LEVEL": "ERROR"}

    class FakeData:
        count = 0
        rrsig_count = 1
        rr_ttl = [3600]
        rr_data = [b"\x00\x88" + bytes([1, 2, 3, 4])]

    class FakeKey:
        type_str = "A"

    class FakeRRset:
        rk = FakeKey()

        class entry:
            data = FakeData()

    class FakeRep:
        rrset_count = 1
        rrsets = [FakeRRset()]

    assert plugin.read_rr(FakeRep(), "sig-only.example.com.") is False


def test_zero_udp_retry_does_not_raise(plugin):
    """UDP_RETRY: 0 skips the loop entirely; the summary log must still work."""
    plugin.pfui_cfg = {"LOGGING": False, "LOG_LEVEL": "ERROR"}

    class Soc:
        def sendto(self, *a):
            raise AssertionError("must not transmit when retry is 0")

    assert plugin.udp_transmit(Soc(), b"x", "127.0.0.1", 10001, retry=0) is None


def test_shipped_config_needs_no_defaults(plugin):
    """Every key load_config defaults must also be a key the shipped yml sets or
    deliberately omits, so the example config and the code cannot drift."""
    shipped = yaml.safe_load((COMPONENT / "pfui_unbound.yml").read_text())
    cfg = plugin.load_config(COMPONENT / "pfui_unbound.yml")
    for key in plugin.CONFIG_DEFAULTS:
        assert key in cfg
    assert cfg["FIREWALLS"] == shipped["FIREWALLS"]


def test_every_key_read_at_runtime_has_a_default(plugin, tmp_path):
    """A config predating an option must load. Each of these keys is read on the
    query path, where a KeyError surfaces per lookup rather than at start."""
    minimal = tmp_path / "pfui_unbound.yml"
    minimal.write_text("--- # Yaml\nFIREWALLS:\n  - HOST: 127.0.0.1\n")
    cfg = plugin.load_config(minimal)
    for key in (
        "LOGGING",
        "LOG_LEVEL",
        "COMPRESS",
        "SOCKET_PROTO",
        "SOCKET_TIMEOUT",
        "BLOCKING",
        "UDP_RETRY",
        "UDP_ACK_TIMEOUT",
        "BREAKER_FAILURES",
        "BREAKER_COOLOFF",
        "DEFAULT_PORT",
    ):
        assert key in cfg, f"{key} is read at runtime but has no default"


def test_empty_config_file_loads(plugin, tmp_path):
    """safe_load returns None for an empty document, which used to be indexed."""
    empty = tmp_path / "pfui_unbound.yml"
    empty.write_text("")
    assert plugin.load_config(empty)["FIREWALLS"] == []


def test_socket_proto_is_normalised_and_validated(plugin, tmp_path):
    """The transmit path matches on the exact string, so an unrecognised value
    would send nothing at all while the resolver looked healthy."""
    cfg = tmp_path / "pfui_unbound.yml"
    cfg.write_text("--- # Yaml\nSOCKET_PROTO: ' tcp '\n")
    assert plugin.load_config(cfg)["SOCKET_PROTO"] == "TCP"

    cfg.write_text("--- # Yaml\nSOCKET_PROTO: SCTP\n")
    with pytest.raises(ValueError):
        plugin.load_config(cfg)


def test_moddone_completes_with_a_config_that_omits_optional_keys(plugin, tmp_path):
    """The failure this guards: a missing key raised KeyError inside operate(),
    before ext_state was set, so Unbound never learned the module had finished."""
    minimal = tmp_path / "pfui_unbound.yml"
    minimal.write_text("--- # Yaml\nFIREWALLS: []\n")
    plugin.pfui_cfg = plugin.load_config(minimal)

    class QState:
        return_msg = None
        ext_state = {}

    qstate = QState()
    assert plugin.operate(0, plugin.MODULE_EVENT_MODDONE, qstate, None) is True
    assert qstate.ext_state[0] == plugin.MODULE_FINISHED


def test_logger_does_not_print_signature_bytes_as_an_address(plugin):
    """The debug dump had the same defect read_rr was fixed for: it read every
    record's trailing bytes as an address, so a signed answer printed an IPv4
    line that no nameserver ever sent."""
    printed = []
    plugin.pfui_cfg = {"LOGGING": True, "LOG_LEVEL": "DEBUG"}
    plugin.log_info = lambda msg="": printed.append(str(msg))

    class FakeData:
        count = 1
        rrsig_count = 1
        rr_ttl = [3600, 3600]
        rr_data = [
            b"\x00\x04" + bytes([8, 8, 8, 8]),
            b"\x00\x88" + bytes([136, 137, 138, 139]),  # signature rdata
        ]

    class FakeKey:
        dname_list, dname_str, flags = [], "signed.example.com.", 0
        type_str, rrset_class_str = "A", "IN"
        type = rrset_class = 1

    class FakeRRset:
        rk = FakeKey()

        class entry:
            data = FakeData()

    class FakeRep:
        flags = qdcount = security = ttl = 0
        rrset_count = 1
        rrsets = [FakeRRset()]
        qinfo = FakeKey()

    class QInfo:
        qname_str, qtype_str, qclass_str = "signed.example.com.", "A", "IN"
        qname_list = []
        qtype = qclass = 1

    class QState:
        qinfo = QInfo()

        class return_msg:
            rep = FakeRep()
            qinfo = QInfo()

    try:
        plugin.logger(QState())
    finally:
        plugin.log_info = INJECTED["log_info"]

    addresses = [line for line in printed if line.startswith("IPv4:")]
    assert addresses == ["IPv4: 8.8.8.8"], f"signature bytes printed as {addresses}"


class AckServer:
    """Loopback stand-in for PFUI_Firewall. `reply=None` accepts the connection
    and then says nothing, which is the case that used to look like success."""

    def __init__(self, reply=b"ACKUPDATE", connections=4):
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.reply = reply
        self.received = []
        self._held = []
        self._thread = Thread(target=self._serve, args=(connections,), daemon=True)
        self._thread.start()

    def _serve(self, connections):
        for _ in range(connections):
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.received.append(conn.recv(65536))
            if self.reply is None:
                self._held.append(conn)  # Never reply, never close
            else:
                conn.sendall(self.reply)
                conn.close()

    def close(self):
        self.listener.close()
        for conn in self._held:
            conn.close()


@pytest.fixture
def breaker_cfg(plugin):
    plugin.pfui_cfg = {
        "LOGGING": False,
        "LOG_LEVEL": "ERROR",
        "COMPRESS": False,
        "SOCKET_PROTO": "TCP",
        "SOCKET_TIMEOUT": 0.25,
        "BLOCKING": True,
        "BREAKER_FAILURES": 2,
        "BREAKER_COOLOFF": 30,
        "DEFAULT_PORT": 10001,
        "FIREWALLS": [],
    }
    plugin._breakers.clear()
    yield plugin.pfui_cfg
    plugin._breakers.clear()


def queries(plugin, count):
    """Drive `count` whole queries through transmit_all.

    Deliberately not calling the transmit functions directly: transmit_all
    consults the breaker before each attempt, and it was that consultation which
    used to reset the failure count, so a test that skips it cannot see the
    breaker fail to trip.
    """
    for _ in range(count):
        plugin.transmit_all({"kind": "rr", "qname": "a.", "AF4": [], "AF6": []})


def test_breaker_opens_when_the_firewall_never_acknowledges(plugin, breaker_cfg):
    """Recording success at sendall meant a firewall that accepted the connection
    and never replied looked healthy forever, so the breaker never opened and
    every query paid SOCKET_TIMEOUT in full."""
    server = AckServer(reply=None, connections=4)
    breaker_cfg["FIREWALLS"] = [{"HOST": "127.0.0.1", "PORT": server.port}]
    try:
        queries(plugin, 2)  # BREAKER_FAILURES
        assert plugin.breaker_open(f"127.0.0.1:{server.port}")
    finally:
        server.close()


def test_breaker_counts_across_queries_rather_than_resetting(plugin, breaker_cfg):
    """The count has to survive the breaker being consulted. While it did not, a
    threshold above 1 could never be reached and the breaker was inert."""
    server = AckServer(reply=None, connections=4)
    breaker_cfg["BREAKER_FAILURES"] = 3
    breaker_cfg["FIREWALLS"] = [{"HOST": "127.0.0.1", "PORT": server.port}]
    key = f"127.0.0.1:{server.port}"
    try:
        queries(plugin, 1)
        assert plugin._breakers[key][0] == 1
        assert not plugin.breaker_open(key)
        queries(plugin, 1)
        assert plugin._breakers[key][0] == 2, "the failure count was reset"
        assert not plugin.breaker_open(key)
        queries(plugin, 1)
        assert plugin.breaker_open(key), "three failures did not trip a threshold of 3"
    finally:
        server.close()


def test_a_tripped_breaker_stops_further_attempts(plugin, breaker_cfg):
    """The point of the breaker: an unreachable firewall stops costing the
    resolver a timeout per query."""
    server = AckServer(reply=None, connections=8)
    breaker_cfg["FIREWALLS"] = [{"HOST": "127.0.0.1", "PORT": server.port}]
    try:
        queries(plugin, 2)  # Trips it
        connected = len(server.received)
        queries(plugin, 3)  # Must all be skipped
        assert len(server.received) == connected, "kept connecting once tripped"
    finally:
        server.close()


def test_breaker_reopens_for_a_probe_once_the_cooloff_elapses(plugin, breaker_cfg):
    server = AckServer(reply=None, connections=8)
    breaker_cfg["BREAKER_COOLOFF"] = 0.5
    breaker_cfg["FIREWALLS"] = [{"HOST": "127.0.0.1", "PORT": server.port}]
    key = f"127.0.0.1:{server.port}"
    try:
        queries(plugin, 2)
        assert plugin.breaker_open(key)
        time.sleep(0.75)
        assert not plugin.breaker_open(key), "never probed again after the cool-off"
        assert plugin._breakers[key][0] == 0, "the count was not cleared for the probe"
    finally:
        server.close()


def test_breaker_stays_closed_when_the_firewall_acknowledges(plugin, breaker_cfg):
    server = AckServer(reply=b"ACKUPDATE", connections=4)
    breaker_cfg["FIREWALLS"] = [{"HOST": "127.0.0.1", "PORT": server.port}]
    try:
        queries(plugin, 3)
        assert not plugin.breaker_open(f"127.0.0.1:{server.port}")
        assert len(server.received) == 3
    finally:
        server.close()


def test_breaker_opens_on_a_refusal(plugin, breaker_cfg):
    """A reachable firewall that refuses every message is not doing its job, and
    PF denies the traffic either way."""
    server = AckServer(reply=b"Missing kind", connections=4)
    breaker_cfg["FIREWALLS"] = [{"HOST": "127.0.0.1", "PORT": server.port}]
    try:
        queries(plugin, 2)
        assert plugin.breaker_open(f"127.0.0.1:{server.port}")
    finally:
        server.close()


def test_payload_is_encoded_once_for_all_firewalls(plugin, breaker_cfg):
    """encode_payload ran per firewall inside the loop, so a CARP pair paid for
    two lz4 passes over identical bytes on the blocking DNS path."""
    calls = []
    real_encode = plugin.encode_payload
    plugin.encode_payload = lambda msg, compress=True: (
        calls.append(msg) or real_encode(msg, compress=compress)
    )
    sent = []
    real_tcp = plugin.tcp_transmit_close  # Restored, not deleted: a del here would
    # remove the module's own function and break every later test
    plugin.tcp_transmit_close = lambda data, ip, port, blocking: sent.append((ip, port))
    breaker_cfg["FIREWALLS"] = [
        {"HOST": "127.0.0.1", "PORT": 10001},
        {"HOST": "127.0.0.2", "PORT": 10001},
    ]
    try:
        plugin.transmit_all({"kind": "rr", "qname": "a.", "AF4": [], "AF6": []})
    finally:
        plugin.encode_payload = real_encode
        plugin.tcp_transmit_close = real_tcp

    assert len(sent) == 2, "both firewalls must still be told"
    assert len(calls) == 1, f"payload encoded {len(calls)} times for 2 firewalls"


def test_nothing_is_encoded_when_there_is_no_firewall_to_send_to(plugin, breaker_cfg):
    calls = []
    real_encode = plugin.encode_payload
    plugin.encode_payload = lambda msg, compress=True: (
        calls.append(msg) or real_encode(msg, compress=compress)
    )
    try:
        plugin.transmit_all({"kind": "rr", "qname": "a.", "AF4": [], "AF6": []})
    finally:
        plugin.encode_payload = real_encode
    assert calls == []


class UnixAckServer(AckServer):
    """The same stand-in bound to a local socket instead of loopback TCP."""

    def __init__(self, path, reply=b"ACKUPDATE", connections=4):
        self.path = str(path)
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(self.path)
        self.listener.listen(8)
        self.listener.settimeout(0.5)
        self.port = None
        self.reply = reply
        self.received = []
        self._held = []
        self.stop = Event()
        self._thread = Thread(target=self._serve, args=(connections,), daemon=True)
        self._thread.start()


@pytest.fixture
def short_tmp():
    """Scratch directory with a path short enough for sockaddr_un.sun_path.

    pytest's tmp_path is far too long, especially on macOS where it lives under
    /private/var/folders/...
    """
    path = Path(tempfile.mkdtemp(prefix="pfui-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def test_a_socket_entry_is_reached_over_a_local_socket(plugin, breaker_cfg, short_tmp):
    """A resolver on the firewall itself: no port, no address, no PF rule."""
    path = short_tmp / "pfui_firewall.sock"
    server = UnixAckServer(path, connections=2)
    breaker_cfg["FIREWALLS"] = [{"SOCKET": str(path)}]
    try:
        plugin.transmit_all({"kind": "rr", "qname": "a.", "AF4": [], "AF6": []})
        time.sleep(0.5)
        assert server.received, "nothing arrived on the local socket"
        assert not plugin.breaker_open(str(path))
    finally:
        server.close()


def test_a_local_and_a_remote_firewall_are_both_told(plugin, breaker_cfg, short_tmp):
    """The CARP case the per-entry transport exists for: this node's own firewall
    over its socket, the peer over TCP, from one resolver and one config."""
    path = short_tmp / "pfui_firewall.sock"
    local = UnixAckServer(path, connections=2)
    remote = AckServer(connections=2)
    breaker_cfg["FIREWALLS"] = [
        {"SOCKET": str(path)},
        {"HOST": "127.0.0.1", "PORT": remote.port},
    ]
    calls = []
    real_encode = plugin.encode_payload
    plugin.encode_payload = lambda msg, compress=True: (
        calls.append(msg) or real_encode(msg, compress=compress)
    )
    try:
        plugin.transmit_all({"kind": "rr", "qname": "a.", "AF4": [], "AF6": []})
        time.sleep(0.5)
        assert local.received, "the local firewall was not told"
        assert remote.received, "the remote firewall was not told"
        assert local.received[0] == remote.received[0], "the two got different bytes"
        assert len(calls) == 1, "the payload was encoded per transport"
    finally:
        plugin.encode_payload = real_encode
        local.close()
        remote.close()


def test_the_breaker_tracks_a_local_and_a_remote_firewall_separately(
    plugin, breaker_cfg, short_tmp
):
    """One key per destination: a dead socket must not shut off a healthy peer."""
    path = short_tmp / "absent.sock"  # Nothing bound: every connect fails
    remote = AckServer(connections=4)
    breaker_cfg["FIREWALLS"] = [
        {"SOCKET": str(path)},
        {"HOST": "127.0.0.1", "PORT": remote.port},
    ]
    try:
        for _ in range(2):  # BREAKER_FAILURES
            plugin.transmit_all({"kind": "rr", "qname": "a.", "AF4": [], "AF6": []})
        time.sleep(0.5)
        assert plugin.breaker_open(str(path)), "the dead socket did not trip"
        assert not plugin.breaker_open(f"127.0.0.1:{remote.port}")
        assert len(remote.received) == 2, "the healthy firewall lost a message"
    finally:
        remote.close()


def test_a_socket_entry_ignores_socket_proto(plugin, breaker_cfg, short_tmp):
    """SOCKET_PROTO describes the network transport. A local socket is always a
    stream carrying the same frames, so UDP must not send a bare datagram at it."""
    path = short_tmp / "pfui_firewall.sock"
    server = UnixAckServer(path, connections=2)
    breaker_cfg["SOCKET_PROTO"] = "UDP"
    breaker_cfg["FIREWALLS"] = [{"SOCKET": str(path)}]
    try:
        plugin.transmit_all({"kind": "rr", "qname": "a.", "AF4": [], "AF6": []})
        time.sleep(0.5)
        assert server.received, "nothing arrived on the local socket"
        # Length-prefixed, as the stream framing requires
        assert len(server.received[0]) > 4
    finally:
        server.close()


def test_firewall_target_reads_each_entry_shape(plugin, breaker_cfg):
    breaker_cfg["SOCKET_PROTO"] = "TCP"
    assert plugin.firewall_target({"SOCKET": "/var/run/pfui/f.sock"}) == (
        "UNIX",
        "/var/run/pfui/f.sock",
        "/var/run/pfui/f.sock",
    )
    assert plugin.firewall_target({"HOST": "10.0.0.1", "PORT": 10002}) == (
        "TCP",
        "10.0.0.1:10002",
        ("10.0.0.1", 10002),
    )
    # An entry with no PORT falls back to DEFAULT_PORT, and one left empty in the
    # yml parses as None rather than being absent
    assert plugin.firewall_target({"HOST": "10.0.0.1"})[2] == ("10.0.0.1", 10001)
    assert plugin.firewall_target({"HOST": "10.0.0.1", "PORT": None})[2] == (
        "10.0.0.1",
        10001,
    )
    # A placeholder entry names no firewall and is skipped, as it always was
    assert plugin.firewall_target({"HOST": None}) is None
    assert plugin.firewall_target({}) is None


def test_an_entry_setting_both_socket_and_host_is_refused(plugin, tmp_path):
    """Unambiguous misconfiguration: it cannot be a leftover placeholder."""
    cfg = tmp_path / "pfui_unbound.yml"
    cfg.write_text(
        "--- # Yaml\nFIREWALLS:\n"
        "  - SOCKET: /var/run/pfui/pfui_firewall.sock\n    HOST: 10.0.0.1\n"
    )
    with pytest.raises(ValueError):
        plugin.load_config(cfg)


def test_a_relative_socket_path_is_refused(plugin, tmp_path):
    cfg = tmp_path / "pfui_unbound.yml"
    cfg.write_text("--- # Yaml\nFIREWALLS:\n  - SOCKET: pfui_firewall.sock\n")
    with pytest.raises(ValueError):
        plugin.load_config(cfg)


def test_a_placeholder_entry_still_loads(plugin, tmp_path):
    """Refusing here would break configs that work today, where an entry with an
    empty HOST is left in place as a comment."""
    cfg = tmp_path / "pfui_unbound.yml"
    cfg.write_text("--- # Yaml\nFIREWALLS:\n  - HOST:\n    PORT:\n")
    assert plugin.load_config(cfg)["FIREWALLS"] == [{"HOST": None, "PORT": None}]


def test_a_mixed_config_loads(plugin, tmp_path):
    cfg = tmp_path / "pfui_unbound.yml"
    cfg.write_text(
        "--- # Yaml\nFIREWALLS:\n"
        "  - SOCKET: /var/run/pfui/pfui_firewall.sock\n"
        "  - HOST: 10.10.1.253\n    PORT: 10001\n"
    )
    assert len(plugin.load_config(cfg)["FIREWALLS"]) == 2


def test_unknown_event_sets_module_error_even_if_logging_fails(plugin):
    """The debug dump derefs qstate.return_msg; a failure there must not stop
    the module from reporting MODULE_ERROR back to Unbound."""
    plugin.pfui_cfg = {"LOGGING": False, "LOG_LEVEL": "ERROR"}

    class QState:
        return_msg = None  # logger() will raise on this
        ext_state = {}

    qstate = QState()
    assert plugin.operate(0, 999, qstate, None) is True
    assert qstate.ext_state[0] == plugin.MODULE_ERROR


# Faults found reviewing the callback and transmit paths. Each of these failed
# before its fix, and each is reachable from a config an operator can write.


def test_a_commented_out_firewall_list_loads_as_a_list(plugin, tmp_path):
    """FIREWALLS: with every entry commented out parses as None, which
    setdefault cannot replace, and transmit_all then iterates None."""
    cfg = tmp_path / "pfui_unbound.yml"
    cfg.write_text("LOGGING: False\nFIREWALLS:\n#  - HOST: 10.0.0.1\n")
    assert plugin.load_config(cfg)["FIREWALLS"] == []


def test_transmit_all_survives_an_empty_firewall_list(plugin, tmp_path):
    cfg = tmp_path / "pfui_unbound.yml"
    cfg.write_text("LOGGING: False\nFIREWALLS:\n")
    plugin.pfui_cfg = plugin.load_config(cfg)
    plugin.transmit_all(
        {"kind": "rr", "qname": "x.", "AF4": [{"ip": "8.8.8.8", "ttl": 60}], "AF6": []},
        False,
    )


@pytest.mark.parametrize(
    "line",
    ["SOCKET_TIMEOUT: '3'", "UDP_RETRY: '3'", "BREAKER_FAILURES: '3'",
     "UDP_ACK_TIMEOUT: '0.5'"],
)
def test_quoted_numbers_are_coerced_at_load(plugin, tmp_path, line):
    """A quoted number reached the socket calls as a string and raised there."""
    cfg = tmp_path / "pfui_unbound.yml"
    cfg.write_text(f"FIREWALLS:\n  - HOST: 10.0.0.1\n{line}\n")
    key = line.split(":")[0]
    assert isinstance(plugin.load_config(cfg)[key], (int, float))


@pytest.mark.parametrize("value", ["1O001", "", "abc"])
def test_an_unusable_port_is_refused_at_load(plugin, tmp_path, value):
    """int(PORT) runs on the send path, where the failure looks like a resolver
    fault rather than the configuration error it is."""
    cfg = tmp_path / "pfui_unbound.yml"
    cfg.write_text(f"FIREWALLS:\n  - HOST: 10.0.0.1\n    PORT: '{value}'\n")
    with pytest.raises(ValueError, match="PORT"):
        plugin.load_config(cfg)


def test_an_emptied_numeric_key_is_refused_at_load(plugin, tmp_path):
    cfg = tmp_path / "pfui_unbound.yml"
    cfg.write_text("FIREWALLS:\n  - HOST: 10.0.0.1\nBREAKER_FAILURES:\n")
    with pytest.raises(ValueError, match="BREAKER_FAILURES"):
        plugin.load_config(cfg)


def test_a_non_blocking_send_records_no_success(plugin):
    """A firewall that accepts and never answers is a failure the blocking path
    counts. A cache report to the same firewall succeeds at the socket, and
    recording that a success cleared the count, so the breaker never opened
    however long the firewall stayed silent."""
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()
    plugin.pfui_cfg = dict(plugin.CONFIG_DEFAULTS, SOCKET_TIMEOUT=0.2,
                           BREAKER_FAILURES=3, BREAKER_COOLOFF=30)
    plugin._breakers.clear()
    recorded = []
    original = plugin.breaker_record

    def spy(target, ok):
        recorded.append(ok)
        original(target, ok)

    plugin.breaker_record = spy
    try:
        # Accepted but never answered, exactly what a saturated firewall does
        plugin.tcp_transmit_close(b"x", host, port, blocking=False)
        assert True not in recorded, f"a non-blocking send recorded {recorded}"

        for _ in range(3):
            plugin.tcp_transmit_close(b"x", host, port, blocking=True)
        assert plugin.breaker_open(f"{host}:{port}")
    finally:
        plugin.breaker_record = original
        listener.close()


def test_the_cache_callback_reports_a_result_and_never_raises(plugin, monkeypatch):
    """Its return value is read as a boolean, and a raise discards the cache hit."""
    monkeypatch.setattr(plugin, "read_rr",
                        lambda *a, **k: {"kind": "cache", "qname": "x.",
                                         "AF4": [], "AF6": []})
    monkeypatch.setattr(plugin, "transmit_all",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    qinfo = type("Q", (), {"qname_str": "x."})()
    assert plugin.inplace_cache_callback(
        qinfo, None, object(), 0, None, None, None
    ) is True


def test_a_fault_at_moddone_finishes_the_query(plugin, monkeypatch):
    """MODULE_WAIT_MODULE tells the mesh to advance to the next module, which
    re-enters one that has already run and loops the query."""
    monkeypatch.setattr(plugin, "read_rr",
                        lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    qstate = type("S", (), {
        "return_msg": type("R", (), {"rep": object(), "qinfo": object()})(),
        "qinfo": type("Q", (), {"qname_str": "x."})(),
        "ext_state": {},
    })()
    assert plugin.operate(0, plugin.MODULE_EVENT_MODDONE, qstate, None) is True
    assert qstate.ext_state[0] == plugin.MODULE_FINISHED


def test_logger_tolerates_a_reply_without_records(plugin):
    """The 'if r:' guard sat five lines after the dereference it guarded."""
    qstate = type("S", (), {
        "return_msg": type("R", (), {"rep": None, "qinfo": object()})(),
        "qinfo": type("Q", (), {"qname_str": "x.", "qtype_str": "A", "qtype": 1,
                                "qclass_str": "IN", "qclass": 1})(),
    })()
    plugin.logger(qstate)


def test_an_acknowledgement_split_in_transit_is_still_read(plugin):
    """One recv() took whatever the first segment held, so a reply delivered in
    two pieces compared unequal to ACKUPDATE and was charged as a refusal."""
    import threading
    import time as _time

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    host, port = listener.getsockname()

    def serve():
        conn, _ = listener.accept()
        conn.recv(1024)
        conn.send(b"ACK")          # deliberately split
        _time.sleep(0.05)
        conn.send(b"UPDATE")
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    plugin.pfui_cfg = dict(plugin.CONFIG_DEFAULTS, SOCKET_TIMEOUT=2,
                           BREAKER_FAILURES=3, BREAKER_COOLOFF=30)
    plugin._breakers.clear()
    try:
        plugin.tcp_transmit_close(b"x", host, port, blocking=True)
        # A confirmed update leaves no failure counted against the firewall
        assert plugin._breakers[f"{host}:{port}"][0] == 0
    finally:
        listener.close()


@pytest.mark.parametrize(
    "compress,expected", [(True, "compressed"), (False, "uncompressed")]
)
def test_a_decode_refusal_names_the_direction_of_the_mismatch(plugin, compress,
                                                              expected):
    """A COMPRESS mismatch is the one fault not signalled on the wire, so it can
    only reach the operator as a refusal. The resolver knows what it sent, which
    fixes the direction from this end alone."""
    plugin.pfui_cfg = dict(plugin.CONFIG_DEFAULTS, COMPRESS=compress)
    detail = plugin.refusal_detail(b"Failed to decode")
    assert "Failed to decode" in detail
    assert f"sent {expected} data" in detail
    assert "the other way" in detail


def test_a_refusal_is_logged_with_what_it_means(plugin):
    plugin.pfui_cfg = dict(plugin.CONFIG_DEFAULTS)
    assert "different release" in plugin.refusal_detail(b"Missing kind")
    # An unknown reply is still reported, just without advice
    assert plugin.refusal_detail(b"something new") == repr(b"something new")


def test_every_hint_names_a_documented_refusal(plugin):
    """The reply strings are fixed by the protocol; a hint for one that does not
    exist would be advice nobody ever sees."""
    protocol = (COMPONENT.parent / "protocol" / "PROTOCOL.md").read_text()
    for reply in plugin.REFUSAL_HINTS:
        assert f"`{reply.decode()}`" in protocol, reply
