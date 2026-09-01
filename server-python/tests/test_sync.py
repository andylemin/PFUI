"""ScanSync's diff against the live PF table.

The sync deletes what is in the table but not in Redis, so it can only ever run
on a complete read. A failing `pfctl -T show` produces no output, which used to
be indistinguishable from an empty table: the diff then found nothing to expire
and tried to re-add every live IP, so a broken pfctl left the table unmanaged
with nothing in the log saying so.
"""

import subprocess

import pytest

from test_file_store import Log, fw


class Recorder(Log):
    def __init__(self):
        self.exceptions = []
        self.errors = []

    def exception(self, msg, *a, **k):
        self.exceptions.append(str(msg))

    def error(self, msg, *a, **k):
        self.errors.append(str(msg))


class FakeRedis:
    def __init__(self, ips):
        self.ips = ips

    def scan_iter(self, match, count=None):
        table = match.split("^")[0]
        return [f"{table}^{ip}".encode() for ip in self.ips]


class Completed:
    """subprocess.CompletedProcess stand-in, so no pfctl is needed."""

    def __init__(self, returncode, stdout=b"", stderr=b""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


@pytest.fixture
def syncer(monkeypatch):
    """A ScanSync wired to fakes, with the PF mutations recorded not performed."""
    pushed, popped = [], []
    monkeypatch.setattr(fw, "table_push", lambda **kw: pushed.append(kw["ip_list"]))
    monkeypatch.setattr(fw, "table_pop", lambda **kw: popped.append(kw["ip_list"]))

    def make(db_ips, pfctl_result):
        monkeypatch.setattr(
            fw.subprocess, "run", lambda *a, **k: pfctl_result
        )
        sync = fw.ScanSync.__new__(fw.ScanSync)  # No thread, no Redis connection
        sync.logger = Recorder()
        sync.cfg = {"LOGGING": False, "REDIS_DB": 9, "SCAN_PERIOD": 300}
        sync.db = FakeRedis(db_ips)
        sync.af = 2
        sync.table = "pfui_ipv4_domains"
        sync.file = "/nonexistent"
        return sync, pushed, popped

    return make


def test_expired_table_entry_is_removed(syncer):
    sync, pushed, popped = syncer(
        db_ips=["1.1.1.1"], pfctl_result=Completed(0, b"  1.1.1.1\n  8.8.8.8\n")
    )
    sync.sync_pf_table()
    assert popped == [["8.8.8.8"]]  # In the table, no Redis record
    assert pushed == []


def test_missing_table_entry_is_added(syncer):
    sync, pushed, popped = syncer(
        db_ips=["1.1.1.1", "8.8.8.8"], pfctl_result=Completed(0, b"  1.1.1.1\n")
    )
    sync.sync_pf_table()
    assert pushed == [["8.8.8.8"]]
    assert popped == []


def test_a_failing_pfctl_does_not_look_like_an_empty_table(syncer):
    """The defect: a non-zero exit with no output meant every Redis IP looked
    missing from the table, and every table entry looked unmanageable."""
    sync, pushed, popped = syncer(
        db_ips=["1.1.1.1"],
        pfctl_result=Completed(1, b"", b"pfctl: Table does not exist.\n"),
    )
    sync.sync_pf_table()
    assert pushed == [], "pushed to the table on the strength of a failed read"
    assert popped == [], "deleted from the table on the strength of a failed read"


def test_a_failing_pfctl_is_logged(syncer):
    sync, _, _ = syncer(
        db_ips=["1.1.1.1"],
        pfctl_result=Completed(77, b"", b"pfctl: /dev/pf: Permission denied.\n"),
    )
    sync.sync_pf_table()
    assert sync.logger.exceptions, "a failed table read was silent"


def test_a_genuinely_empty_table_still_gets_its_entries_added(syncer):
    """The other side of the same coin: exit 0 with no output is an empty table
    and must be repopulated."""
    sync, pushed, popped = syncer(db_ips=["1.1.1.1"], pfctl_result=Completed(0, b""))
    sync.sync_pf_table()
    assert pushed == [["1.1.1.1"]]
    assert popped == []


def test_pfctl_that_cannot_be_executed_is_survived(syncer, monkeypatch):
    """OSError from run(), Eg a pfctl that is not installed."""
    sync, pushed, popped = syncer(db_ips=["1.1.1.1"], pfctl_result=Completed(0))
    monkeypatch.setattr(
        fw.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError())
    )
    sync.sync_pf_table()
    assert pushed == [] and popped == []
    assert sync.logger.exceptions


def test_a_sync_cycle_failure_does_not_end_the_thread(syncer):
    """One transient fault must not stop expiry for the table forever."""
    sync, _, _ = syncer(db_ips=["1.1.1.1"], pfctl_result=Completed(1, b"", b"boom"))
    sync.stop_event = fw.Event()
    sync.scan_redis_db = lambda: None
    sync.sync_pf_file = lambda: None
    calls = []
    real = sync.sync_pf_table

    def counted():
        calls.append(1)
        if len(calls) >= 2:
            sync.stop_event.set()
        real()

    sync.sync_pf_table = counted
    sync.cfg["SCAN_PERIOD"] = 1
    sync.run()
    assert len(calls) >= 2, "the loop stopped after the first failing cycle"
