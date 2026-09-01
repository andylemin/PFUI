"""Configuration rules for the daemon.

Every key the daemon reads must either have a default or stop the daemon. The
two that matter most are the socket keys: an unset SOCKET_LISTEN used to publish
an unauthenticated whitelist-injection port on every interface, and an
unrecognised SOCKET_PROTO used to match neither listener branch, fall through to
the shutdown path, and exit 0 as though the daemon had served.
"""

from pathlib import Path

import pytest
import yaml

from test_file_store import fw  # reuses the daemon-import shim

COMPONENT = Path(__file__).resolve().parent.parent


def write(tmp_path, mapping):
    path = tmp_path / "pfui_firewall.yml"
    path.write_text(yaml.safe_dump(mapping))
    return str(path)


def complete():
    """The minimum a working deployment sets."""
    return {
        "SOCKET_LISTEN": "10.10.1.254",
        "AF4_TABLE": "pfui_ipv4_domains",
        "AF4_FILE": "/var/spool/pfui/pfui_ipv4_domains",
        "AF6_TABLE": "pfui_ipv6_domains",
        "AF6_FILE": "/var/spool/pfui/pfui_ipv6_domains",
    }


def tables_only():
    """A config with the PF tables but no listener of either kind."""
    cfg = complete()
    del cfg["SOCKET_LISTEN"]
    return cfg


def test_shipped_config_loads():
    """The example config must satisfy its own daemon."""
    cfg = fw.load_config(str(COMPONENT / "pfui_firewall.yml"))
    assert cfg["SOCKET_PROTO"] == "TCP"
    assert cfg["SOCKET_LISTEN"]


def test_every_key_read_at_runtime_has_a_default(tmp_path):
    cfg = fw.load_config(write(tmp_path, complete()))
    for key in fw.CONFIG_DEFAULTS:
        assert key in cfg, f"{key} is read at runtime but has no default"


@pytest.mark.parametrize("key", sorted(fw.CONFIG_REQUIRED))
def test_required_keys_are_refused_when_missing(tmp_path, key):
    """Including SOCKET_LISTEN: the table and file keys always hard-exited when
    absent, but the listen address silently became 0.0.0.0."""
    cfg = complete()
    del cfg[key]
    with pytest.raises(ValueError) as raised:
        fw.load_config(write(tmp_path, cfg))
    assert key in str(raised.value)


def test_no_listener_of_either_kind_is_refused(tmp_path):
    """A daemon with nothing listening would start, serve nothing and look fine."""
    with pytest.raises(ValueError) as raised:
        fw.load_config(write(tmp_path, tables_only()))
    assert "no listener" in str(raised.value)


def test_listen_address_is_never_defaulted_to_all_interfaces(tmp_path):
    """The invariant that outlives SOCKET_LISTEN becoming optional: a config that
    does not name an address must not end up bound to every interface."""
    cfg = tables_only()
    cfg["SOCKET_UNIX"] = "/var/run/pfui/pfui_firewall.sock"
    loaded = fw.load_config(write(tmp_path, cfg))
    assert not loaded.get("SOCKET_LISTEN")
    assert "SOCKET_LISTEN" not in fw.CONFIG_DEFAULTS


def test_local_socket_alone_is_a_complete_configuration(tmp_path):
    """A resolver on the firewall itself needs no network listener at all."""
    cfg = tables_only()
    cfg["SOCKET_UNIX"] = "/var/run/pfui/pfui_firewall.sock"
    loaded = fw.load_config(write(tmp_path, cfg))
    assert loaded["SOCKET_UNIX"] == "/var/run/pfui/pfui_firewall.sock"


def test_network_listener_alone_is_still_a_complete_configuration(tmp_path):
    loaded = fw.load_config(write(tmp_path, complete()))
    assert loaded["SOCKET_UNIX"] == ""  # Disabled unless asked for


def test_both_listeners_together_are_accepted(tmp_path):
    """A CARP node serves its own resolver locally and its peer's over TCP."""
    cfg = complete()
    cfg["SOCKET_UNIX"] = "/var/run/pfui/pfui_firewall.sock"
    loaded = fw.load_config(write(tmp_path, cfg))
    assert loaded["SOCKET_LISTEN"] and loaded["SOCKET_UNIX"]


@pytest.mark.parametrize("path", ["pfui.sock", "var/run/pfui.sock", "./pfui.sock"])
def test_relative_socket_path_is_refused(tmp_path, path):
    """It would be resolved against whatever directory rc.subr started us in."""
    cfg = tables_only()
    cfg["SOCKET_UNIX"] = path
    with pytest.raises(ValueError):
        fw.load_config(write(tmp_path, cfg))


def test_socket_group_defaults_to_the_shared_pfui_group(tmp_path):
    cfg = tables_only()
    cfg["SOCKET_UNIX"] = "/var/run/pfui/pfui_firewall.sock"
    assert fw.load_config(write(tmp_path, cfg))["SOCKET_UNIX_GROUP"] == "_pfui"


def test_udp_gate_does_not_apply_to_a_local_socket_only_daemon(tmp_path):
    """SOCKET_PROTO describes the network listener. With no SOCKET_LISTEN there is
    no datagram socket to be spoofed, so a stale SOCKET_PROTO: UDP must not block
    a local-socket deployment from starting."""
    cfg = tables_only()
    cfg["SOCKET_UNIX"] = "/var/run/pfui/pfui_firewall.sock"
    cfg["SOCKET_PROTO"] = "UDP"
    loaded = fw.load_config(write(tmp_path, cfg))
    assert loaded["SOCKET_PROTO"] == "UDP" and not loaded.get("SOCKET_LISTEN")


@pytest.mark.parametrize("value,expected", [(" tcp ", "TCP"), ("udp", "UDP")])
def test_socket_proto_is_normalised(tmp_path, value, expected):
    """Normalising is what keeps 'udp' behind the ALLOW_INSECURE_UDP gate, which
    also matches on the exact string."""
    cfg = complete()
    cfg["SOCKET_PROTO"] = value
    assert fw.load_config(write(tmp_path, cfg))["SOCKET_PROTO"] == expected


@pytest.mark.parametrize("value", ["SCTP", "tcp6", "", "both", 4])
def test_unsupported_socket_proto_is_refused(tmp_path, value):
    cfg = complete()
    cfg["SOCKET_PROTO"] = value
    with pytest.raises(ValueError):
        fw.load_config(write(tmp_path, cfg))


def test_empty_config_file_is_refused(tmp_path):
    """safe_load returns None for an empty document; the required keys still
    have to be reported rather than the daemon crashing on a None subscript."""
    path = tmp_path / "pfui_firewall.yml"
    path.write_text("")
    with pytest.raises(ValueError):
        fw.load_config(str(path))
