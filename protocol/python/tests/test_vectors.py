"""Conformance tests against the shared vectors in ../../vectors/.

The same framing.tsv is read by server-c's test suite, so a divergence between
the two implementations fails here or there rather than in production.
"""

import json
from pathlib import Path

import pytest

from pfui_wire import MAX_MESSAGE, WireError, decode_stream, encode

VECTORS = Path(__file__).resolve().parents[3] / "protocol" / "vectors"


def framing_rows():
    rows = []
    for line in (VECTORS / "framing.tsv").read_text().splitlines():
        if not line or line.startswith("#"):
            continue
        name, frame_hex, expect, payload_hex = line.split("\t")
        # "-" means empty or not applicable; the format has no empty fields, so
        # that a whitespace-splitting reader cannot silently shift columns
        blob = b"" if frame_hex == "-" else bytes.fromhex(frame_hex)
        rows.append((name, blob, expect, payload_hex))
    return rows


def message_vectors():
    return json.loads((VECTORS / "messages.json").read_text())["vectors"]


@pytest.mark.parametrize(
    "name,blob,expect,payload_hex", framing_rows(), ids=lambda v: v if isinstance(v, str) else ""
)
def test_framing_vector(name, blob, expect, payload_hex):
    if expect == "ok":
        # This layer is about bytes, not JSON: check the declared length and the
        # payload the framing yields
        assert int.from_bytes(blob[:4], "big") == len(blob) - 4
        assert blob[4:].hex() == payload_hex
    elif expect == "short":
        # No complete header arrived, so there is no message; not an error
        assert decode_stream(blob, compress=False) is None
    else:
        with pytest.raises(WireError):
            decode_stream(blob, compress=False)


@pytest.mark.parametrize("vector", message_vectors(), ids=lambda v: v["name"])
def test_message_vector(vector):
    msg = vector["message"]
    if vector.get("byte_exact"):
        assert encode(msg, compress=vector["compress"]).hex() == vector["frame_hex"]
    blob = encode(msg, compress=vector["compress"])
    assert decode_stream(blob, compress=vector["compress"]) == msg


def test_vectors_agree_on_max_message():
    assert json.loads((VECTORS / "messages.json").read_text())["max_message"] == MAX_MESSAGE
