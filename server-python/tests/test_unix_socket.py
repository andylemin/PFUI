"""The local (AF_UNIX) listener for a resolver on the firewall itself.

There is no packet on this transport, so the pf.conf source restriction that
guards the network listener does not apply and the socket's own permissions are
the entire access control on who may inject PF whitelist entries. Everything here
is about that: the socket is never wider than SOCKET_UNIX_GROUP, it is never
briefly wider on the way to being bound, and anything that cannot be made that
narrow stops the daemon instead of serving.
"""

import grp
import os
import shutil
import socket
import stat
import tempfile
import threading
from pathlib import Path

import pytest

from pfui_wire import encode
from test_file_store import fw

MODE = fw.UNIX_SOCKET_MODE


def resolvable_own_group():
    """Name of a group this process is really in, so chown() is permitted.

    Every gid the process holds is tried, not just the primary one: on a host
    joined to a directory service the primary gid often has no entry in the local
    group database, which is a property of the test host and not of PFUI.
    """
    for gid in [os.getgid()] + list(os.getgroups()):
        try:
            return grp.getgrgid(gid).gr_name
        except (KeyError, OverflowError):
            continue
    return None


OWN_GROUP = resolvable_own_group()

pytestmark = pytest.mark.skipif(
    OWN_GROUP is None,
    reason="no gid held by this process resolves to a local group name",
)


def own_group():
    return OWN_GROUP


class Recorder:
    def __init__(self):
        self.lines = []

    def info(self, msg, *a, **k):
        self.lines.append(str(msg))

    error = exception = info


class Daemon:
    """Enough of PFUI_Firewall to bind and serve a local socket."""

    _bind_unix = fw.PFUI_Firewall._bind_unix
    _reclaim_unix_socket = fw.PFUI_Firewall._reclaim_unix_socket
    _grant_unix_socket = fw.PFUI_Firewall._grant_unix_socket
    _remove_unix_socket = fw.PFUI_Firewall._remove_unix_socket
    _prepare_conn = fw.PFUI_Firewall._prepare_conn
    receiver_thread = fw.PFUI_Firewall.receiver_thread

    def __init__(self, path, group=None):
        self.unix = None
        self.soc = None
        self.db = None
        self.stats = False
        self.logger = Recorder()
        self.cfg = {
            "LOGGING": False,
            "COMPRESS": False,
            "SOCKET_UNIX": str(path),
            "SOCKET_UNIX_GROUP": group or own_group(),
            "SOCKET_TIMEOUT": 3,
            "SOCKET_BACKLOG": 8,
            "SOCKET_BUFFER": 1024,
            "AF4_TABLE": "pfui_ipv4_domains",
            "AF6_TABLE": "pfui_ipv6_domains",
            "AF4_FILE": "/nonexistent/af4",
            "AF6_FILE": "/nonexistent/af6",
        }


@pytest.fixture
def short_tmp():
    """A short-pathed scratch directory.

    pytest's tmp_path is far too long for sockaddr_un.sun_path, especially on
    macOS where it sits under /private/var/folders/..., so socket tests cannot
    use it. See UNIX_PATH_MAX and the config rule that reports the limit.
    """
    path = Path(tempfile.mkdtemp(prefix="pfui-", dir="/tmp"))
    try:
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


@pytest.fixture
def sock_path(short_tmp):
    return short_tmp / "pfui_firewall.sock"


def mode_of(path):
    return stat.S_IMODE(os.stat(path).st_mode)


def test_socket_is_bound_with_the_intended_mode_and_group(sock_path):
    daemon = Daemon(sock_path)
    listener = daemon._bind_unix(str(sock_path))
    try:
        assert stat.S_ISSOCK(os.stat(sock_path).st_mode)
        assert oct(mode_of(sock_path)) == oct(MODE)
        assert grp.getgrgid(os.stat(sock_path).st_gid).gr_name == own_group()
    finally:
        listener.close()


def test_socket_is_not_readable_or_writable_by_others(sock_path):
    """The whole point: only SOCKET_UNIX_GROUP may inject whitelist entries."""
    daemon = Daemon(sock_path)
    listener = daemon._bind_unix(str(sock_path))
    try:
        mode = mode_of(sock_path)
        assert not mode & stat.S_IRWXO, f"world bits set: {oct(mode)}"
    finally:
        listener.close()


def test_umask_means_the_socket_is_never_wider_than_intended(sock_path, monkeypatch):
    """bind() creates the node with the process umask, so the narrowing cannot be
    left to a chmod afterwards: between the two the socket would be connectable by
    anyone. Observed by failing the chmod and checking what bind alone produced."""
    daemon = Daemon(sock_path)
    seen = {}
    real_chmod = os.chmod

    def record_then_chmod(path, mode, *a, **k):
        seen.setdefault("before_chmod", mode_of(path))
        return real_chmod(path, mode, *a, **k)

    monkeypatch.setattr(fw.os, "chmod", record_then_chmod)
    listener = daemon._bind_unix(str(sock_path))
    try:
        assert not seen["before_chmod"] & stat.S_IRWXO
        assert not seen["before_chmod"] & stat.S_IRWXG
    finally:
        listener.close()


def test_a_stale_socket_from_an_unclean_stop_is_reclaimed(sock_path):
    """bind() fails with EADDRINUSE on a leftover node, so a crash must not need
    a hand-cleanup before the service will start again."""
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(sock_path))
    stale.close()  # Node remains, nothing listening
    assert os.path.exists(sock_path)

    daemon = Daemon(sock_path)
    listener = daemon._bind_unix(str(sock_path))
    try:
        assert oct(mode_of(sock_path)) == oct(MODE)
    finally:
        listener.close()


def test_a_live_daemons_socket_is_not_stolen(sock_path):
    """Unlinking a listening daemon's socket would leave it running and
    unreachable, which is worse than refusing to start."""
    incumbent = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    incumbent.bind(str(sock_path))
    incumbent.listen(4)
    try:
        with pytest.raises(SystemExit):
            Daemon(sock_path)._bind_unix(str(sock_path))
        assert stat.S_ISSOCK(os.stat(sock_path).st_mode), "the live socket was removed"
    finally:
        incumbent.close()


def test_a_missing_group_stops_the_daemon(sock_path):
    """Rather than serving on a socket whose group is whatever we happened to
    inherit, which is how a local socket silently becomes too open."""
    daemon = Daemon(sock_path, group="_no_such_group_exists")
    with pytest.raises(SystemExit):
        daemon._bind_unix(str(sock_path))


def test_a_missing_group_leaves_no_socket_behind(sock_path):
    """A socket left bound by a refused start would be reclaimed by the next one
    and, worse, might be connectable in the meantime."""
    daemon = Daemon(sock_path, group="_no_such_group_exists")
    with pytest.raises(SystemExit):
        daemon._bind_unix(str(sock_path))
    assert not os.path.exists(sock_path)


def test_a_world_writable_parent_directory_is_refused(short_tmp):
    """Whatever the socket's own mode, anyone could replace it there and be handed
    the resolver's messages."""
    loose = short_tmp / "loose"
    loose.mkdir()
    os.chmod(loose, 0o777)
    daemon = Daemon(loose / "pfui.sock")
    with pytest.raises(SystemExit):
        daemon._bind_unix(str(loose / "pfui.sock"))


def test_a_sticky_world_writable_parent_is_allowed(short_tmp):
    """/tmp semantics: the sticky bit stops one user unlinking another's node."""
    sticky = short_tmp / "sticky"
    sticky.mkdir()
    os.chmod(sticky, 0o1777)
    daemon = Daemon(sticky / "pfui.sock")
    listener = daemon._bind_unix(str(sticky / "pfui.sock"))
    listener.close()


def test_a_missing_parent_directory_stops_the_daemon(short_tmp):
    daemon = Daemon(short_tmp / "absent" / "pfui.sock")
    with pytest.raises(SystemExit):
        daemon._bind_unix(str(short_tmp / "absent" / "pfui.sock"))


def test_shutdown_removes_the_socket(sock_path):
    daemon = Daemon(sock_path)
    daemon.unix = daemon._bind_unix(str(sock_path))
    daemon._remove_unix_socket()
    assert not os.path.exists(sock_path)


def test_removing_the_socket_is_safe_when_none_was_bound(sock_path):
    """Called on the failure path when SOCKET_UNIX is set but nothing bound."""
    daemon = Daemon(sock_path)
    daemon._remove_unix_socket()  # Must not raise
    assert not os.path.exists(sock_path)


def test_prepare_conn_sets_a_timeout_without_touching_nagle(sock_path):
    """TCP_NODELAY is not a thing on a local socket, and setting it there raises
    rather than being ignored, so a spurious exception would be logged for every
    single connection."""
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        daemon = Daemon(sock_path)
        daemon._prepare_conn(left)
        assert left.gettimeout() == 3.0
        assert daemon.logger.lines == [], f"logged: {daemon.logger.lines}"
    finally:
        left.close()
        right.close()


def test_a_message_over_the_local_socket_is_acknowledged(sock_path, monkeypatch):
    """End to end on the stream path: the same framing and the same reply as TCP,
    with the socket path standing in for the peer address accept() cannot give."""
    performed = []
    monkeypatch.setattr(fw, "table_push", lambda **kw: performed.append(kw["ip_list"]))
    monkeypatch.setattr(fw, "db_push", lambda **kw: None)
    monkeypatch.setattr(fw, "file_push", lambda **kw: None)

    daemon = Daemon(sock_path)
    listener = daemon._bind_unix(str(sock_path))
    message = {
        "kind": "rr",
        "qname": "local.example.com.",
        "AF4": [{"ip": "8.8.8.8", "ttl": 60}],
        "AF6": [],
    }
    replies = []

    def client():
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(5)
        try:
            conn.connect(str(sock_path))
            conn.sendall(encode(message, compress=False))
            replies.append(conn.recv(64))
        finally:
            conn.close()

    thread = threading.Thread(target=client)
    thread.start()
    try:
        served, _ = listener.accept()
        daemon._prepare_conn(served)
        daemon.receiver_thread(proto="UNIX", conn=served, peer=str(sock_path))
        thread.join(10)
    finally:
        listener.close()

    assert replies == [b"ACKUPDATE"]
    assert performed == [["8.8.8.8"]]


def test_a_peer_that_leaves_before_the_ack_is_tolerated(sock_path, monkeypatch):
    """A cache report is sent with blocking=False, so the resolver has closed by
    the time the acknowledgement is written. Loopback TCP absorbs that write into
    a buffer nobody reads; a local socket reports EPIPE immediately, so the
    tolerance in disconnect() is load-bearing on this transport and not on TCP.
    The whitelisting must still have happened.
    """
    performed = []
    monkeypatch.setattr(fw, "table_push", lambda **kw: performed.append(kw["ip_list"]))
    monkeypatch.setattr(fw, "db_push", lambda **kw: None)
    monkeypatch.setattr(fw, "file_push", lambda **kw: None)

    daemon = Daemon(sock_path)
    listener = daemon._bind_unix(str(sock_path))
    message = {
        "kind": "cache",
        "qname": "cached.example.com.",
        "AF4": [{"ip": "8.8.8.8", "ttl": 2000000000}],
        "AF6": [],
    }

    def client():
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(5)
        conn.connect(str(sock_path))
        conn.sendall(encode(message, compress=False))
        conn.close()  # Away before the ACK, as the non-blocking path does

    thread = threading.Thread(target=client)
    thread.start()
    try:
        served, _ = listener.accept()
        daemon._prepare_conn(served)
        thread.join(10)
        # Must not raise out of the worker, and must still install the address
        daemon.receiver_thread(proto="UNIX", conn=served, peer=str(sock_path))
    finally:
        listener.close()

    assert performed == [["8.8.8.8"]]


def test_a_refusal_over_the_local_socket_names_the_socket(sock_path, monkeypatch):
    """A local sender has no address to be logged, so the diagnostics have to fall
    back to the socket path rather than printing None:None."""
    monkeypatch.setattr(fw, "table_push", lambda **kw: None)
    monkeypatch.setattr(fw, "db_push", lambda **kw: None)
    monkeypatch.setattr(fw, "file_push", lambda **kw: None)

    daemon = Daemon(sock_path)
    listener = daemon._bind_unix(str(sock_path))
    replies = []

    def client():
        conn = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        conn.settimeout(5)
        try:
            conn.connect(str(sock_path))
            # No 'kind': a version-skewed sender
            conn.sendall(encode({"AF4": [{"ip": "8.8.8.8", "ttl": 60}]}, compress=False))
            replies.append(conn.recv(64))
        finally:
            conn.close()

    thread = threading.Thread(target=client)
    thread.start()
    try:
        served, _ = listener.accept()
        daemon._prepare_conn(served)
        daemon.receiver_thread(proto="UNIX", conn=served, peer=str(sock_path))
        thread.join(10)
    finally:
        listener.close()

    assert replies == [b"Missing kind"]
    assert any(str(sock_path) in line for line in daemon.logger.lines)
    assert not any("None:None" in line for line in daemon.logger.lines)
