"""Integration tests that speak the real PFUI wire format to a running
PFUI_Firewall.

Skipped unless PFUI_FW_HOST is set, because they need a live daemon and they
mutate its PF tables:

    PFUI_FW_HOST=10.10.1.254 PFUI_FW_PORT=10001 pytest tests/test_unbound.py

The previous version of this file sent json.dumps() output (a str, so TypeError
on Py3), called an undefined log_err, and did not match the wire format at all.
"""

import os
import socket

import pytest

from pfui_wire import encode

HOST = os.environ.get("PFUI_FW_HOST")
PORT = int(os.environ.get("PFUI_FW_PORT", 10001))
COMPRESS = os.environ.get("PFUI_FW_COMPRESS", "1") == "1"
TIMEOUT = float(os.environ.get("PFUI_FW_TIMEOUT", 3))

pytestmark = pytest.mark.skipif(
    not HOST, reason="set PFUI_FW_HOST to run against a live PFUI_Firewall"
)


def send(msg, expect_reply=True):
    """Send one framed message, returning the daemon's reply bytes."""
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(TIMEOUT)
    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
    try:
        conn.connect((HOST, PORT))
        conn.sendall(encode(msg, compress=COMPRESS))
        if not expect_reply:
            return b""
        return conn.recv(64)
    finally:
        conn.close()


def test_single_ipv4_answer_is_acknowledged():
    reply = send({"AF4": [{"ip": "1.1.1.1", "ttl": 3600, "qname": "test."}],
                  "AF6": [], "kind": "rr"})
    assert reply == b"ACKUPDATE"


def test_dual_stack_answer_is_acknowledged():
    reply = send(
        {
            "AF4": [{"ip": "1.1.1.1", "ttl": 3600, "qname": "test."}],
            "AF6": [{"ip": "2606:4700:4700::1111", "ttl": 3600, "qname": "test."}],
            "kind": "rr",
        }
    )
    assert reply == b"ACKUPDATE"


def test_cache_kind_answer_is_acknowledged():
    """A cache-derived message carries an absolute expiry, not a relative TTL."""
    import time

    reply = send(
        {
            "AF4": [{"ip": "1.0.0.1", "ttl": int(time.time()) + 3600, "qname": "test."}],
            "AF6": [],
            "kind": "cache",
        }
    )
    assert reply == b"ACKUPDATE"


def test_large_answer_survives_reassembly():
    """The defect that motivated length-prefix framing: a message larger than
    2 x SOCKET_BUFFER used to lose its leading bytes and be dropped."""
    msg = {
        "AF4": [
            {"ip": f"1.1.{i // 254}.{i % 254 + 1}", "ttl": 3600, "qname": "big."}
            for i in range(500)
        ],
        "AF6": [],
        "kind": "rr",
    }
    assert send(msg) == b"ACKUPDATE"
