"""Per-connection socket options on accepted sockets.

accept() does not carry over the listener's timeout: Python returns the new
socket in blocking mode with timeout None. Without an explicit timeout a peer
that connects and stalls holds a receiver slot forever, and the socket_timeout
branch in the read path is unreachable.
"""

import socket
import threading

import pytest

from test_file_store import fw  # reuses the daemon-import shim


class Cfg(dict):
    pass


class Daemon:
    """Minimal stand-in exposing just what _prepare_conn touches."""

    def __init__(self, timeout=3):
        self.cfg = {"SOCKET_TIMEOUT": timeout}

        class Log:
            def exception(self, *a, **k):
                pass

        self.logger = Log()

    _prepare_conn = fw.PFUI_Firewall._prepare_conn


@pytest.fixture
def accepted():
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(3)  # what the daemon does, to poll for SIGTERM
    port = listener.getsockname()[1]
    client = socket.create_connection(("127.0.0.1", port))
    conn, _ = listener.accept()
    yield conn
    for s in (conn, client, listener):
        s.close()


def test_accept_really_does_lose_the_timeout(accepted):
    """The premise of this suite; if this ever changes, the fix is redundant."""
    assert accepted.gettimeout() is None


def test_prepare_conn_sets_a_recv_timeout(accepted):
    Daemon(timeout=3)._prepare_conn(accepted)
    assert accepted.gettimeout() == 3.0


def test_prepare_conn_disables_nagle(accepted):
    """Set explicitly rather than relying on inheritance from the listener,
    which is not guaranteed across platforms."""
    accepted.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 0)
    Daemon()._prepare_conn(accepted)
    # Any non-zero value means the option is on. The kernel is free to report
    # its own flag bits rather than the 1 that was set: Darwin returns 4, so
    # asserting equality made this suite red everywhere but Linux
    assert accepted.getsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY) != 0


def test_stalled_peer_hits_the_timeout_instead_of_blocking(accepted):
    """The behaviour that matters: a peer that sends nothing must not pin the
    worker. Without the timeout this recv would never return."""
    Daemon(timeout=0.25)._prepare_conn(accepted)
    with pytest.raises(socket.timeout):
        accepted.recv(4)


def test_timeout_survives_into_a_thread(accepted):
    """receiver_thread runs in the pool, so the timeout must be a property of
    the socket rather than of the accepting thread."""
    Daemon(timeout=0.25)._prepare_conn(accepted)
    result = []

    def read():
        try:
            accepted.recv(4)
            result.append("returned")
        except socket.timeout:
            result.append("timeout")

    t = threading.Thread(target=read)
    t.start()
    t.join(5)
    assert not t.is_alive(), "recv blocked past the timeout inside a thread"
    assert result == ["timeout"]
