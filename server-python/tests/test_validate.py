"""Ingress validation tests: S7/S11 (sentinels and non-global answers) and
B10 (IPv6 canonicalisation)."""

import pytest

from pfui.validate import extract, routable


@pytest.mark.parametrize(
    "addr",
    [
        "0.0.0.0",  # blocklist sentinel
        "::",
        "0:0:0:0:0:0:0:0",  # same sentinel, non-canonical spelling
        "0::0",
        "10.0.0.1",  # RFC1918
        "192.168.1.1",
        "172.16.0.1",
        "100.64.0.1",  # CGNAT
        "169.254.1.1",  # link-local
        "127.0.0.1",  # loopback
        "224.0.0.1",  # multicast, which ipaddress reports as global
        "ff02::1",
        "::1",
        "fe80::1",
        "fc00::1",  # ULA
        "::ffff:10.0.0.1",  # IPv4-mapped private
        "::ffff:8.8.8.8",  # IPv4-mapped global still belongs in no v6 table
        "not-an-ip",
        "",
        None,
        "8.8.8.8/32",
    ],
)
def test_non_routable_rejected(addr):
    assert routable(addr) is None


@pytest.mark.parametrize(
    "addr,canon",
    [
        ("8.8.8.8", "8.8.8.8"),
        ("1.1.1.1", "1.1.1.1"),
        ("2001:4860:4860::8888", "2001:4860:4860::8888"),
        ("2001:4860:4860:0000:0000:0000:0000:8888", "2001:4860:4860::8888"),
        ("2001:4860:4860::8888".upper(), "2001:4860:4860::8888"),
    ],
)
def test_routable_returns_canonical_form(addr, canon):
    assert routable(addr) == canon


def test_version_mismatch_rejected():
    assert routable("8.8.8.8", version=6) is None
    assert routable("2001:4860:4860::8888", version=4) is None


def test_extract_filters_and_canonicalises():
    records = [
        {"ip": "8.8.8.8", "ttl": 3600},
        {"ip": "0.0.0.0", "ttl": 3600},
        {"ip": "10.0.0.1", "ttl": 3600},
        {"ip": "8.8.4.4", "ttl": "300"},
    ]
    assert extract(records, version=4) == [("8.8.8.8", 3600), ("8.8.4.4", 300)]


def test_extract_keeps_zero_ttl():
    """A ttl of 0 means do-not-cache, not absent; dropping it blocks egress."""
    assert extract([{"ip": "8.8.8.8", "ttl": 0}], version=4) == [("8.8.8.8", 0)]


def test_extract_tolerates_missing_and_malformed_records():
    records = [
        None,
        "garbage",
        {"ttl": 3600},
        {"ip": "8.8.8.8"},
        {"ip": "8.8.8.8", "ttl": "abc"},
        {"ip": "8.8.8.8", "ttl": 60},
    ]
    assert extract(records, version=4) == [("8.8.8.8", 60)]


def test_extract_handles_none_input():
    assert extract(None, version=4) == []
