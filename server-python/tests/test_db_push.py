"""What db_push records for one answer.

The TTL is the whole expiry decision, so what is stored has to be what the sender
said. An undocumented one-hour floor used to be applied to every RR TTL, which
contradicted the expiry rule in PROTOCOL.md and, with the shipped
TTL_MULTIPLIER: 4, turned a 60 second answer into four hours of authorised
egress. It also raised the ttl of 0 that means do-not-cache, the one value
validate.extract goes out of its way to preserve.
"""

import pytest

from pfui.store import is_expired
from test_file_store import Log, fw

CFG = {"SCAN_PERIOD": 300, "TTL_MULTIPLIER": 4}


class FakePipeline:
    """Records the commands the daemon queues, without a Redis."""

    def __init__(self):
        self.hmset_calls = {}
        self.hdel_calls = []
        self.expire_calls = {}
        self.executed = False

    def hmset(self, key, mapping):
        self.hmset_calls.setdefault(key, {}).update(mapping)

    def hdel(self, key, field):
        self.hdel_calls.append((key, field))

    def expire(self, key, seconds):
        self.expire_calls[key] = seconds

    def execute(self):
        self.executed = True


class FakeRedis:
    def __init__(self):
        self.pipe = FakePipeline()

    def pipeline(self):
        return self.pipe


def push(data, kind, cfg=CFG):
    db = FakeRedis()
    assert fw.db_push(Log(), False, db, "t", data, kind, "example.com.", cfg) is True
    assert db.pipe.executed
    return db.pipe


@pytest.mark.parametrize("ttl", [0, 1, 30, 60, 3599, 3600, 604800])
def test_rr_ttl_is_stored_exactly_as_sent(ttl):
    pipe = push([("8.8.8.8", ttl)], "rr")
    assert pipe.hmset_calls["t^8.8.8.8"]["ttl"] == ttl


def test_short_ttl_is_not_raised_to_an_hour():
    """A 60 second answer must expire on its own TTL, not on a hidden floor."""
    pipe = push([("8.8.8.8", 60)], "rr")
    meta = pipe.hmset_calls["t^8.8.8.8"]
    assert meta["ttl"] == 60
    assert meta["kind"] == "rr"
    # The recorded window is the sender's TTL times the multiplier, plus one
    # scan period of slack for the sweep that retires it
    assert pipe.expire_calls["t^8.8.8.8"] == 60 * 4 + 300


def test_do_not_cache_answer_keeps_its_zero_ttl():
    """ttl 0 is valid and means do-not-cache, so the entry must expire at the
    next scan rather than be held for an hour times the multiplier."""
    pipe = push([("8.8.8.8", 0)], "rr")
    assert pipe.hmset_calls["t^8.8.8.8"]["ttl"] == 0
    assert is_expired(
        {b"kind": b"rr", b"epoch": b"1000", b"ttl": b"0"}, now=1000, multiplier=4
    )


def test_zero_ttl_key_is_not_deleted_by_its_own_backstop():
    """Redis treats EXPIRE 0 as delete-now, which would drop the record before
    the scan that should retire it ever ran."""
    pipe = push([("8.8.8.8", 0)], "rr")
    assert pipe.expire_calls["t^8.8.8.8"] > 0


def test_backstop_is_never_non_positive_even_with_a_zero_scan_period():
    pipe = push([("8.8.8.8", 0)], "rr", cfg={"SCAN_PERIOD": 0, "TTL_MULTIPLIER": 1})
    assert pipe.expire_calls["t^8.8.8.8"] >= 1


def test_cache_entry_stores_the_absolute_expiry_and_drops_the_ttl_field():
    """hmset merges, so the field the other kind uses has to go."""
    pipe = push([("8.8.8.8", 1675846179 + 3600)], "cache")
    meta = pipe.hmset_calls["t^8.8.8.8"]
    assert meta["kind"] == "cache"
    assert meta["expires"] == 1675846179 + 3600
    assert ("t^8.8.8.8", "ttl") in pipe.hdel_calls


def test_rr_entry_drops_the_expires_field():
    pipe = push([("8.8.8.8", 3600)], "rr")
    assert ("t^8.8.8.8", "expires") in pipe.hdel_calls


def test_already_expired_cache_entry_still_gets_a_positive_backstop():
    pipe = push([("8.8.8.8", 1)], "cache")  # epoch 1 is long past
    assert pipe.expire_calls["t^8.8.8.8"] > 0


def test_qname_is_recorded_per_key():
    pipe = push([("8.8.8.8", 60), ("1.1.1.1", 60)], "rr")
    for key in ("t^8.8.8.8", "t^1.1.1.1"):
        assert pipe.hmset_calls[key]["qname"] == "example.com."


def test_redis_failure_returns_false():
    class Broken:
        def pipeline(self):
            raise ConnectionError("redis down")

    assert (
        fw.db_push(Log(), False, Broken(), "t", [("8.8.8.8", 60)], "rr", "a.", CFG)
        is False
    )
