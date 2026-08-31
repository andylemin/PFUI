
#### Check to see if PF tables on the PFUI_Firewall server are growing
`pfctl -t pfui_ipv4_domains -T [add|show|delete]`

#### Check if the redis database on the PFUI_Firewall server is growing and holding resolved IP entries (keys)
Use SCAN, not KEYS: KEYS is O(N) and blocks the whole Redis server, on a firewall.
```
fw1# redis-cli -n 9 --scan --pattern 'pfui_ipv4_domains^*' | head
pfui_ipv4_domains^204.79.197.212
pfui_ipv4_domains^67.199.248.13
pfui_ipv4_domains^1.1.1.1
```

#### Check the metadata (values) for an example IP entry
Every entry carries a `kind`, which says how to read its expiry. `kind: rr` means
`ttl` is a relative DNS TTL and the entry expires at `epoch + ttl * TTL_MULTIPLIER`.
`kind: cache` means the answer came from Unbound's cache callback and `expires` is
an absolute timestamp. Exactly one of `ttl` or `expires` is present; an entry with
neither, or with no `kind`, is treated as malformed and purged on the next scan.
```
127.0.0.1:6379> hgetall "pfui_ipv4_domains^1.1.1.1"
1) "epoch"
2) "1675846179"
3) "kind"
4) "rr"
5) "ttl"
6) "3600"
7) "qname"
8) "one.one.one.one."
```

#### Check the PF persist files
These live in a daemon-owned directory, and are written by the daemon user only.
```
fw1# ls -l /var/spool/pfui/
fw1# tail /var/spool/pfui/pfui_ipv4_domains
```
Duplicate lines here are expected between scans: the per-query path appends
without reading the file, and the periodic sync rewrite de-duplicates it.

#### Check the service is actually running, and as the right user
`rcctl check pfui_firewall` reflects the daemon's own exit status, and the daemon
must not be running as root.
```
fw1# rcctl check pfui_firewall
fw1# ps -axo user,command | grep pfui_firewall
```

#### Watch the per-query latency breakdown
Set both `LOGGING: True` and `LOG_LEVEL: DEBUG` in `/etc/pfui_firewall.yml`. One
structured line is emitted per update; either setting alone produces no timings.
