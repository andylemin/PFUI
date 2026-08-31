"""Expiry regression tests: B2 (cache entries survive) and B9 (kind is authoritative)."""

import pytest

from pfui.store import expired_keys, is_expired

NOW = 1675846179
MULT = 4


class FakePipeline:
    """Minimal stand-in for redis-py's pipeline: queues hgetall, returns hashes."""

    def __init__(self, store, raiser=None):
        self.store = store
        self.raiser = raiser
        self.queued = []

    def hgetall(self, key):
        self.queued.append(key)

    def execute(self, raise_on_error=True):
        out = []
        for key in self.queued:
            if self.raiser and key in self.raiser:
                out.append(self.raiser[key])
            else:
                out.append(self.store.get(key, {}))
        self.queued = []
        return out


class FakeRedis:
    def __init__(self, store, raiser=None):
        self.store = store
        self.raiser = raiser or {}

    def scan_iter(self, match, count=None):
        prefix = match.rstrip("*")
        return [k for k in self.store if k.decode().startswith(prefix)]

    def pipeline(self):
        return FakePipeline(self.store, self.raiser)


def key(table, ip):
    return f"{table}^{ip}".encode()


def test_cache_entry_not_expired_before_expires():
    """B2: an IP seen only via the cache callback must survive the next scan."""
    db = FakeRedis({
        key("t", "1.1.1.1"): {
            b"epoch": str(NOW).encode(),
            b"kind": b"cache",
            b"expires": str(NOW + 3600).encode(),
        }
    })
    assert expired_keys(db, "t", now=NOW, multiplier=MULT) == []


def test_cache_entry_expired_after_expires():
    db = FakeRedis({
        key("t", "1.1.1.1"): {
            b"epoch": str(NOW - 7200).encode(),
            b"kind": b"cache",
            b"expires": str(NOW - 1).encode(),
        }
    })
    assert expired_keys(db, "t", now=NOW, multiplier=MULT) == ["1.1.1.1"]


def test_rr_entry_uses_ttl_times_multiplier():
    fresh = {b"epoch": str(NOW - 3600).encode(), b"kind": b"rr", b"ttl": b"3600"}
    stale = {b"epoch": str(NOW - 20000).encode(), b"kind": b"rr", b"ttl": b"3600"}
    assert not is_expired(fresh, NOW, MULT)  # 3600 * 4 not yet elapsed
    assert is_expired(stale, NOW, MULT)


def test_long_ttl_rr_is_not_treated_as_a_timestamp():
    """B9: a genuine week-long TTL must not be read as an absolute expiry."""
    meta = {b"epoch": str(NOW).encode(), b"kind": b"rr", b"ttl": b"604800"}
    assert not is_expired(meta, NOW, MULT)


def test_merged_hash_prefers_kind_over_field_presence():
    """B9: hmset merges, so both fields can be present; kind decides."""
    meta = {
        b"epoch": str(NOW).encode(),
        b"kind": b"rr",
        b"ttl": b"3600",
        b"expires": str(NOW - 99999).encode(),  # stale leftover from cache path
    }
    assert not is_expired(meta, NOW, MULT)


def test_legacy_key_without_kind_is_purged():
    meta = {b"epoch": str(NOW).encode(), b"ttl": b"3600"}
    assert is_expired(meta, NOW, MULT)


def test_malformed_metadata_is_purged():
    db = FakeRedis({key("t", "1.1.1.1"): {b"kind": b"rr", b"ttl": b"not-a-number"}})
    assert expired_keys(db, "t", now=NOW, multiplier=MULT) == ["1.1.1.1"]


def test_one_unreadable_key_does_not_void_the_batch():
    """A WRONGTYPE key is skipped, and the rest of the batch is still judged."""
    bad, good = key("t", "9.9.9.9"), key("t", "8.8.8.8")
    db = FakeRedis(
        {
            bad: {},
            good: {
                b"epoch": str(NOW - 20000).encode(),
                b"kind": b"rr",
                b"ttl": b"3600",
            },
        },
        raiser={bad: Exception("WRONGTYPE")},
    )
    assert expired_keys(db, "t", now=NOW, multiplier=MULT) == ["8.8.8.8"]


def test_connection_error_propagates_to_caller():
    """scan_redis_db must be able to catch this and retry next SCAN_PERIOD."""

    class Broken(FakeRedis):
        def pipeline(self):
            raise ConnectionError("redis down")

    db = Broken({key("t", "1.1.1.1"): {b"kind": b"rr", b"ttl": b"3600"}})
    with pytest.raises(ConnectionError):
        expired_keys(db, "t", now=NOW, multiplier=MULT)
