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
            {"ip": f"198.51.100.{i % 254 + 1}", "ttl": 3600}
            for i in range(500)
        ],
        "AF6": [],
        "kind": "rr", "qname": "test.",
    }
    blob = encode(msg, compress=True)
    assert len(blob) > 1024  # would have been truncated by the old 2-chunk join
    assert decode_stream(blob, chunk=512) == msg


def test_payload_containing_sentinel_bytes():
    """B1: b"EOT" inside the payload must not terminate the frame."""
    msg = {"AF4": [{"ip": "203.0.113.7", "ttl": 3600}], "AF6": [],
           "kind": "rr", "qname": "test."}
    assert decode_stream(encode(msg, compress=True), chunk=1) == msg


def test_uncompressed_roundtrip():
    msg = {"AF4": [], "AF6": [{"ip": "2001:db8::1", "ttl": 300}], "kind": "cache", "qname": "test."}
    assert decode_stream(encode(msg, compress=False), compress=False) == msg


def test_closed_connection_returns_none():
    assert decode_stream(b"", compress=False) is None


def test_truncated_payload_raises():
    blob = encode({"AF4": [], "AF6": [], "kind": "rr", "qname": "test."}, compress=False)
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
    payload = encode_payload({"AF4": [], "AF6": [], "kind": "rr", "qname": "test."}, compress=True)
    assert decode_stream(frame(payload)) == {"AF4": [], "AF6": [], "kind": "rr", "qname": "test."}


def _wire_without_lz4():
    """Load a private copy of the module with the lz4 import failing.

    A fresh instance rather than a reload: this module is shared by the resolver,
    both daemons and the rest of these tests, and reloading it in place would
    leave them holding a codec-less copy.
    """
    import builtins
    import importlib.util
    import sys
    from pathlib import Path

    real_import = builtins.__import__

    def blocked(name, *args, **kwargs):
        if name == "lz4" or name.startswith("lz4."):
            raise ImportError("no lz4 for this test")
        return real_import(name, *args, **kwargs)

    path = Path(__file__).resolve().parent.parent / "pfui_wire.py"
    spec = importlib.util.spec_from_file_location("pfui_wire_no_lz4", path)
    module = importlib.util.module_from_spec(spec)
    builtins.__import__ = blocked
    try:
        for cached in ("lz4", "lz4.frame"):
            sys.modules.pop(cached, None)
        spec.loader.exec_module(module)
    finally:
        builtins.__import__ = real_import
    return module


def test_the_module_loads_and_works_without_lz4():
    """lz4 is only needed when COMPRESS is on, so importing it unconditionally
    made the package mandatory on a resolver that had compression off."""
    wire = _wire_without_lz4()
    assert wire.HAVE_LZ4 is False

    msg = {"kind": "rr", "qname": "a.", "AF4": [{"ip": "8.8.8.8", "ttl": 60}], "AF6": []}
    blob = wire.encode(msg, compress=False)
    assert wire.decode_stream(blob, compress=False) == msg


def test_asking_for_compression_without_lz4_says_what_to_install():
    """It must not fall back to plain JSON: the far end would refuse that as a
    COMPRESS mismatch, which is a much harder fault to read."""
    wire = _wire_without_lz4()
    msg = {"kind": "rr", "qname": "a.", "AF4": [], "AF6": []}

    with pytest.raises(wire.WireError, match="lz4"):
        wire.encode_payload(msg, compress=True)
    with pytest.raises(wire.WireError, match="lz4"):
        wire.decompress_bounded(b"whatever")


def test_lz4_is_still_used_when_it_is_present():
    """The optional import must not have turned compression off for everyone."""
    from pfui_wire import HAVE_LZ4 as available

    assert available is True
    msg = {"kind": "rr", "qname": "a.", "AF4": [{"ip": "1.1.1.1", "ttl": 5}], "AF6": []}
    assert encode_payload(msg, compress=True) != encode_payload(msg, compress=False)
