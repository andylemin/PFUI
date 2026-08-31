"""Persist-file regression tests: B3 (temp collision), B4 (locking, return
contract) and B5 (atomicity)."""

import importlib.util
import os
import sys
from pathlib import Path
from threading import Thread

import pytest

COMPONENT = Path(__file__).resolve().parent.parent


def _load_daemon():
    """Import pfui_firewall without its OpenBSD-only runtime deps."""
    sys.path.insert(0, str(COMPONENT))
    for missing in ("redis", "service"):
        if missing not in sys.modules:
            module = type(sys)(missing)
            if missing == "redis":
                module.StrictRedis = object
            else:
                module.Service = object
                module.find_syslog = lambda: None
            sys.modules[missing] = module
    spec = importlib.util.spec_from_file_location(
        "pfui_firewall", COMPONENT / "pfui_firewall.py"
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


fw = _load_daemon()


class Log:
    def info(self, *a, **k):
        pass

    def exception(self, *a, **k):
        pass

    def error(self, *a, **k):
        pass


@pytest.fixture
def persist(tmp_path):
    f = tmp_path / "pfui_ipv4_domains"
    f.write_text("")
    return str(f)


def lines(path):
    return [l for l in Path(path).read_text().splitlines() if l]


def test_push_returns_true_and_appends(persist):
    assert fw.file_push(Log(), False, persist, ["1.1.1.1", "8.8.8.8"]) is True
    assert lines(persist) == ["1.1.1.1", "8.8.8.8"]


def test_pop_returns_true_on_success(persist):
    """B4: file_pop returned None on success, unlike its siblings."""
    fw.file_push(Log(), False, persist, ["1.1.1.1", "8.8.8.8"])
    assert fw.file_pop(Log(), False, persist, ["1.1.1.1"]) is True
    assert lines(persist) == ["8.8.8.8"]


def test_pop_dedupes_remaining_entries(persist):
    fw.file_push(Log(), False, persist, ["1.1.1.1", "1.1.1.1", "8.8.8.8"])
    fw.file_pop(Log(), False, persist, ["9.9.9.9"])
    assert lines(persist) == ["1.1.1.1", "8.8.8.8"]


def test_pop_preserves_file_mode(persist):
    """mkstemp creates 0600; the replacement must keep the installed mode."""
    os.chmod(persist, 0o640)
    fw.file_pop(Log(), False, persist, ["1.1.1.1"])
    assert oct(os.stat(persist).st_mode & 0o777) == oct(0o640)


def test_pop_leaves_no_temp_files(persist):
    """B3: two pops within the same second must not collide, and nothing
    should be left behind."""
    fw.file_push(Log(), False, persist, ["1.1.1.1", "8.8.8.8", "9.9.9.9"])
    fw.file_pop(Log(), False, persist, ["1.1.1.1"])
    fw.file_pop(Log(), False, persist, ["8.8.8.8"])
    leftovers = [p.name for p in Path(persist).parent.iterdir() if ".tmp" in p.name]
    assert leftovers == []
    assert lines(persist) == ["9.9.9.9"]


def test_concurrent_push_loses_nothing(persist):
    """B5: read/decide/append was not atomic, so concurrent appends could be
    lost. Every IP must survive."""
    ips = [f"10.0.{i // 254}.{i % 254 + 1}" for i in range(400)]
    threads = [
        Thread(target=fw.file_push, args=(Log(), False, persist, ips[i::8]))
        for i in range(8)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(set(lines(persist))) == sorted(ips)


def test_concurrent_push_and_pop_keeps_file_parseable(persist):
    """A pop rewriting the file must never interleave with an append."""
    fw.file_push(Log(), False, persist, [f"10.1.0.{i + 1}" for i in range(50)])
    adds = [f"10.2.0.{i + 1}" for i in range(50)]
    threads = [
        Thread(target=fw.file_push, args=(Log(), False, persist, adds)),
        Thread(target=fw.file_pop, args=(Log(), False, persist, ["10.1.0.1"])),
        Thread(target=fw.file_push, args=(Log(), False, persist, adds)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    for line in lines(persist):
        assert line.count(".") == 3, f"corrupt line {line!r}"


def test_push_failure_returns_false(tmp_path):
    assert fw.file_push(Log(), False, str(tmp_path / "no" / "such"), ["1.1.1.1"]) is False
