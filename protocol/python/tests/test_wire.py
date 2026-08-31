"""Wire-format regression tests: B1 (framing) and S5 (bounded decompression)."""

import lz4.frame
import pytest

from pfui_wire import (
    HEADER,
    MAX_MESSAGE,
    WireError,
    decode_stream,
    decompress_bounded,
    encode,
    encode_payload,
    frame,
)


def test_large_message_roundtrip():
    """B1: a message far larger than SOCKET_BUFFER must survive reassembly."""
    msg = {
        "AF4": [
            {"ip": f"198.51.100.{i % 254 + 1}", "ttl": 3600, "qname": "x"}
            for i in range(500)
        ],
        "AF6": [],
        "kind": "rr",
    }
    blob = encode(msg, compress=True)
    assert len(blob) > 1024  # would have been truncated by the old 2-chunk join
    assert decode_stream(blob, chunk=512) == msg


def test_payload_containing_sentinel_bytes():
    """B1: b"EOT" inside the payload must not terminate the frame."""
    msg = {"AF4": [{"ip": "203.0.113.7", "ttl": 3600, "qname": "EOT"}], "AF6": [],
           "kind": "rr"}
    assert decode_stream(encode(msg, compress=True), chunk=1) == msg


def test_uncompressed_roundtrip():
    msg = {"AF4": [], "AF6": [{"ip": "2001:db8::1", "ttl": 300}], "kind": "cache"}
    assert decode_stream(encode(msg, compress=False), compress=False) == msg


def test_closed_connection_returns_none():
    assert decode_stream(b"", compress=False) is None


def test_truncated_payload_raises():
    blob = encode({"AF4": [], "AF6": [], "kind": "rr"}, compress=False)
    with pytest.raises(WireError):
        decode_stream(blob[:-1], compress=False)


def test_oversize_declared_length_rejected():
    """The prefix is checked before any payload byte is buffered."""
    with pytest.raises(WireError):
        decode_stream(HEADER.pack(MAX_MESSAGE + 1) + b"x", compress=False)


def test_zero_declared_length_rejected():
    with pytest.raises(WireError):
        decode_stream(HEADER.pack(0), compress=False)


def test_decompression_bomb_refused():
    """S5: expansion stops at the ceiling instead of being allocated in full."""
    bomb = lz4.frame.compress(b"\0" * (MAX_MESSAGE * 4))
    assert len(bomb) < MAX_MESSAGE  # small on the wire, huge when expanded
    with pytest.raises(WireError):
        decompress_bounded(bomb)


def test_payload_at_ceiling_still_decodes():
    payload = encode_payload({"AF4": [], "AF6": [], "kind": "rr"}, compress=True)
    assert decode_stream(frame(payload)) == {"AF4": [], "AF6": [], "kind": "rr"}
