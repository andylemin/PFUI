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
import sys
from pathlib import Path

import pytest

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
