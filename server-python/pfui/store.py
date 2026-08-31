"""Expiry decision for PFUI's Redis keys.

Each key carries an explicit `kind`; the expiry rule branches on that and never
on which fields are present. `hmset` merges, so a key written by the RR path and
later refreshed by the cache path can hold both `ttl` and `expires`, and a rule
that checked field presence could judge a fresh record against a stale expiry.
"""

KIND_RR = b"rr"
KIND_CACHE = b"cache"


def is_expired(meta: dict, now: int, multiplier: int) -> bool:
    """True when one IP's Redis hash has expired."""
    kind = meta.get(b"kind")
    if kind == KIND_CACHE:  # absolute Unbound cache-expiry timestamp
        return int(meta[b"expires"]) <= now
    if kind == KIND_RR:  # relative RR TTL
        epoch = int(meta.get(b"epoch", now))
        return epoch + (int(meta[b"ttl"]) * int(multiplier)) <= now
    return True  # written before `kind` existed, or malformed


def expired_keys(db, table: str, now: int, multiplier: int, batch: int = 500) -> list:
    """IPs of every expired key in `table`, read in batches of `batch`.

    Reads are pipelined with raise_on_error=False so one WRONGTYPE key cannot
    void a whole batch. Connection-level errors propagate to the caller.
    """
    expired = []
    keys = list(db.scan_iter(match=f"{table}^*", count=batch))
    for i in range(0, len(keys), batch):
        chunk = keys[i : i + batch]
        pipe = db.pipeline()
        for key in chunk:
            pipe.hgetall(key)
        for key, meta in zip(chunk, pipe.execute(raise_on_error=False)):
            if isinstance(meta, Exception) or not meta:
                continue
            try:
                stale = is_expired(meta, now, multiplier)
            except (KeyError, ValueError, TypeError):
                stale = True  # unreadable metadata cannot authorise egress
            if stale:
                expired.append(key.decode("utf-8").split("^", 1)[1])
    return expired
