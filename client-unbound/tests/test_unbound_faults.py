"""Fault injection against a running PFUI_Firewall: every case here must be
rejected without whitelisting anything and without killing the daemon.

Skipped unless PFUI_FW_HOST is set:

    PFUI_FW_HOST=10.10.1.254 pytest tests/test_unbound_faults.py
"""

import os
import socket

import lz4.frame
import pytest

from pfui_wire import HEADER, MAX_MESSAGE, encode

HOST = os.environ.get("PFUI_FW_HOST")
PORT = int(os.environ.get("PFUI_FW_PORT", 10001))
COMPRESS = os.environ.get("PFUI_FW_COMPRESS", "1") == "1"
TIMEOUT = float(os.environ.get("PFUI_FW_TIMEOUT", 3))

pytestmark = pytest.mark.skipif(
    not HOST, reason="set PFUI_FW_HOST to run against a live PFUI_Firewall"
)


def send_raw(blob):
    """Send arbitrary bytes; returns the reply, or b"" if the peer hung up."""
    conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn.settimeout(TIMEOUT)
    try:
        conn.connect((HOST, PORT))
        conn.sendall(blob)
        try:
            return conn.recv(64)
        except socket.timeout:
            return b""
    finally:
        conn.close()


def assert_rejected(reply):
    assert reply != b"ACKUPDATE", "hostile input was accepted"


def test_message_without_kind_is_rejected():
    """Pre-kind senders are refused rather than guessed at."""
    assert_rejected(
        send_raw(encode({"AF4": [{"ip": "1.1.1.1", "ttl": 3600}], "AF6": []},
                        compress=COMPRESS))
    )


def test_sentinel_addresses_are_not_whitelisted():
    for ip in ("0.0.0.0", "::", "0:0:0:0:0:0:0:0"):
        key = "AF4" if "." in ip else "AF6"
        msg = {"AF4": [], "AF6": [], "kind": "rr"}
        msg[key] = [{"ip": ip, "ttl": 3600, "qname": "sentinel."}]
        assert_rejected(send_raw(encode(msg, compress=COMPRESS)))


def test_internal_addresses_are_not_whitelisted():
    """A DNS answer pointing inside the network must not authorise egress."""
    for ip in ("10.0.0.1", "192.168.1.1", "127.0.0.1", "100.64.0.1"):
        msg = {"AF4": [{"ip": ip, "ttl": 3600, "qname": "rebind."}], "AF6": [],
               "kind": "rr"}
        assert_rejected(send_raw(encode(msg, compress=COMPRESS)))


def test_oversize_declared_length_is_refused():
    """The prefix is validated before any payload byte is buffered."""
    assert_rejected(send_raw(HEADER.pack(MAX_MESSAGE + 1) + b"x" * 16))


def test_zero_declared_length_is_refused():
    assert_rejected(send_raw(HEADER.pack(0)))


def test_truncated_payload_is_refused():
    blob = encode({"AF4": [{"ip": "1.1.1.1", "ttl": 3600}], "AF6": [], "kind": "rr"},
                  compress=COMPRESS)
    assert_rejected(send_raw(blob[: len(blob) // 2]))


def test_garbage_payload_is_refused():
    payload = b"\xde\xad\xbe\xef" * 8
    assert_rejected(send_raw(HEADER.pack(len(payload)) + payload))


def test_decompression_bomb_is_refused():
    """A few KB on the wire that would expand to far past the ceiling."""
    if not COMPRESS:
        pytest.skip("daemon is not running with COMPRESS enabled")
    bomb = lz4.frame.compress(b"\0" * (MAX_MESSAGE * 8))
    assert_rejected(send_raw(HEADER.pack(len(bomb)) + bomb))


def test_daemon_still_serves_after_every_fault():
    """The whole point: none of the above may have taken the daemon down."""
    good = encode(
        {"AF4": [{"ip": "1.1.1.1", "ttl": 3600, "qname": "recover."}], "AF6": [],
         "kind": "rr"},
        compress=COMPRESS,
    )
    assert send_raw(good) == b"ACKUPDATE"


def test_connection_opened_and_closed_without_data():
    """An empty connection must be dropped, not leak a worker slot."""
    for _ in range(5):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.settimeout(TIMEOUT)
        conn.connect((HOST, PORT))
        conn.close()
    good = encode(
        {"AF4": [{"ip": "1.1.1.1", "ttl": 60, "qname": "empty."}], "AF6": [],
         "kind": "rr"},
        compress=COMPRESS,
    )
    assert send_raw(good) == b"ACKUPDATE"
