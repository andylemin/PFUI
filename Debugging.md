
#### Check to see if PF tables on the PFUI_Firewall server are growing
`pfctl -t pfui_ipv4_domains -T [add|show|delete]`

#### Check if the redis database on the PFUI_Firewall server is growing and holding resolved IP entries (keys)
```
fw1# redis-cli
127.0.0.1:6379> KEYS *
1) "pfui_ipv4_domains^204.79.197.212"
2) "pfui_ipv4_domains^67.199.248.13"
3) "pfui_ipv4_domains^1.1.1.1"
```

#### Check the metadata (values) for an example IP entry
```
127.0.0.1:6379> hgetall "pfui_ipv4_domains^1.1.1.1"
1) "epoch"
2) "1675846179"
3) "ttl"
4) "3600"
5) "expires"
6) "1675846753"
```

