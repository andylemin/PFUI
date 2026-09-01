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


def test_missing_listen_address_is_not_defaulted_to_all_interfaces(tmp_path):
    cfg = complete()
    del cfg["SOCKET_LISTEN"]
    with pytest.raises(ValueError):
        fw.load_config(write(tmp_path, cfg))


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
