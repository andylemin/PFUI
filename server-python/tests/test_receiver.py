"""What the daemon replies to a message it will not act on.

PROTOCOL.md makes each refusal a distinct short reason, because the reason is the
only diagnostic a client gets. Two of them were unreachable: the frame layer
collapsed a bad length and a truncated payload into one "Bad frame", and the
shape check ran after the 'kind' check, so a payload that was not a message
object at all was reported as a version skew and the branch meant for it was
dead code.
"""

import pytest

from pfui_wire import HEADER, MAX_MESSAGE, encode, encode_payload
from test_file_store import fw

COMPRESS = False


class Recorder:
    def __init__(self):
        self.lines = []

    def info(self, msg, *a, **k):
        self.lines.append(str(msg))

    def error(self, msg, *a, **k):
        self.lines.append(str(msg))

    def exception(self, msg, *a, **k):
        self.lines.append(str(msg))


class FakeConn:
    """One accepted TCP connection, fed from a byte string."""

    def __init__(self, blob):
        self.blob = blob
        self.sent = b""
        self.closed = False

    def recv(self, n):
        chunk, self.blob = self.blob[:n], self.blob[n:]
        return chunk

    def sendall(self, data):
        self.sent += data

    def close(self):
        self.closed = True


class Daemon:
    """Enough of PFUI_Firewall to run receiver_thread with nothing installed."""

    receiver_thread = fw.PFUI_Firewall.receiver_thread

    def __init__(self):
        self.logger = Recorder()
        self.soc = None
        self.db = None  # db_push is recorded, not performed
        self.stats = False
        self.cfg = {
            "LOGGING": False,
            "COMPRESS": COMPRESS,
            "SOCKET_BUFFER": 1024,
            "AF4_TABLE": "pfui_ipv4_domains",
            "AF6_TABLE": "pfui_ipv6_domains",
            "AF4_FILE": "/nonexistent/af4",
            "AF6_FILE": "/nonexistent/af6",
        }


@pytest.fixture
def daemon(monkeypatch):
    """Records the PF, Redis and file writes instead of performing them."""
    performed = {"table": [], "db": [], "file": []}
    monkeypatch.setattr(fw, "table_push", lambda **kw: performed["table"].append(kw))
    monkeypatch.setattr(fw, "db_push", lambda **kw: performed["db"].append(kw))
    monkeypatch.setattr(fw, "file_push", lambda **kw: performed["file"].append(kw))
    d = Daemon()
    d.performed = performed
    return d


def deliver(daemon, blob):
    """Push raw bytes at the TCP receive path; returns what the daemon replied."""
    conn = FakeConn(blob)
    daemon.receiver_thread(proto="TCP", conn=conn, ip="10.10.1.1", port=54321)
    assert conn.closed, "the connection was left open"
    return conn.sent


def test_a_valid_message_is_acknowledged(daemon):
    msg = {"kind": "rr", "qname": "a.", "AF4": [{"ip": "8.8.8.8", "ttl": 60}], "AF6": []}
    assert deliver(daemon, encode(msg, compress=COMPRESS)) == b"ACKUPDATE"
    assert [kw["ip_list"] for kw in daemon.performed["table"]] == [["8.8.8.8"]]
    assert daemon.performed["db"] and daemon.performed["file"]


def test_zero_declared_length_is_refused_as_a_bad_length(daemon):
    assert deliver(daemon, HEADER.pack(0)) == b"Bad length"


def test_oversize_declared_length_is_refused_as_a_bad_length(daemon):
    """Refused from the prefix alone, before any payload byte is buffered."""
    assert deliver(daemon, HEADER.pack(MAX_MESSAGE + 1) + b"x" * 16) == b"Bad length"


def test_short_payload_is_refused_as_truncated(daemon):
    """A sender that declared bytes it did not send is a different fault from a
    bad prefix, and gets its own reason."""
    assert deliver(daemon, HEADER.pack(64) + b"x" * 8) == b"Truncated"


def test_peer_that_closes_before_a_header_gets_the_empty_payload_reason(daemon):
    assert deliver(daemon, b"") == b"Empty payload"


def test_garbage_payload_is_refused_as_undecodable(daemon):
    payload = b"\xde\xad\xbe\xef" * 8
    assert deliver(daemon, HEADER.pack(len(payload)) + payload) == b"Failed to decode"


@pytest.mark.parametrize("payload", ["[]", '"a string"', "42", "null"])
def test_payload_that_is_not_a_message_object_is_an_invalid_datatype(daemon, payload):
    """Reported as the wrong shape, not as a missing 'kind': a list has no kind
    to be missing, and blaming a version skew sent the operator the wrong way."""
    blob = encode_payload(payload_as_json(payload), compress=COMPRESS)
    reply = deliver(daemon, HEADER.pack(len(blob)) + blob)
    assert reply == b"Invalid datatype"
    assert daemon.performed["table"] == []


def payload_as_json(text):
    import json

    return json.loads(text)


def test_message_without_kind_is_refused(daemon):
    msg = {"qname": "a.", "AF4": [{"ip": "8.8.8.8", "ttl": 60}], "AF6": []}
    assert deliver(daemon, encode(msg, compress=COMPRESS)) == b"Missing kind"


def test_message_with_an_unrecognised_kind_is_refused(daemon):
    msg = {"kind": "guess", "AF4": [{"ip": "8.8.8.8", "ttl": 60}], "AF6": []}
    assert deliver(daemon, encode(msg, compress=COMPRESS)) == b"Missing kind"


def test_well_formed_message_with_no_records_is_refused(daemon):
    msg = {"kind": "rr", "qname": "a.", "AF4": [], "AF6": []}
    assert deliver(daemon, encode(msg, compress=COMPRESS)) == b"No records"


def test_message_whose_only_records_are_non_global_is_refused(daemon):
    """Nothing survives validation, so there is nothing to act on."""
    msg = {
        "kind": "rr",
        "qname": "a.",
        "AF4": [{"ip": "10.0.0.1", "ttl": 60}, {"ip": "0.0.0.0", "ttl": 60}],
        "AF6": [{"ip": "::1", "ttl": 60}],
    }
    assert deliver(daemon, encode(msg, compress=COMPRESS)) == b"No records"
    assert daemon.performed["table"] == []


def test_every_refusal_reason_is_documented():
    """The reasons are a protocol surface, so PROTOCOL.md has to list each one."""
    from pathlib import Path

    spec = (
        Path(__file__).resolve().parents[2] / "protocol" / "PROTOCOL.md"
    ).read_text()
    for reason in (
        "Missing kind",
        "Bad frame",
        "Bad length",
        "Truncated",
        "Failed to decode",
        "Invalid datatype",
        "No records",
        "Empty payload",
        "Socket timeout",
    ):
        assert f"`{reason}`" in spec, f"{reason} is sent but not documented"
