"""Address validation for PFUI ingress.

Whatever survives here is authorised for egress, so this is a whitelist: only
globally routable unicast addresses pass, in canonical form.
"""

from ipaddress import ip_address


def routable(address, version=None):
    """Canonical text form of a globally routable unicast address, else None.

    Rejects blocklist sentinels (0.0.0.0, ::, and every other spelling of them)
    along with private, loopback, link-local, CGNAT, ULA, IPv4-mapped and
    multicast answers: a DNS answer pointing inside the network must not
    authorise egress. Multicast needs its own test because ipaddress reports
    224.0.0.0/4 and ff00::/8 as global.

    Canonicalising here also stops Redis keys and `pfctl -T show` output from
    diverging on IPv6 spelling, which made sync_pf_table delete and re-add the
    same address forever.
    """
    try:
        addr = ip_address(address)
    except (ValueError, TypeError):
        return None
    if version is not None and addr.version != version:
        return None
    if addr.is_multicast or not addr.is_global:
        return None
    if getattr(addr, "ipv4_mapped", None) is not None:
        return None
    return str(addr)


def extract(records, version):
    """(ip, ttl) tuples for every routable record of `version`.

    A ttl of 0 is valid ("do not cache") and must not be discarded, so the test
    is against None rather than truthiness.
    """
    out = []
    for rr in records or []:
        if not isinstance(rr, dict):
            continue
        ip = routable(rr.get("ip"), version=version)
        if ip is None or rr.get("ttl") is None:
            continue
        try:
            ttl = int(rr["ttl"])
        except (ValueError, TypeError):
            continue
        out.append((ip, ttl))
    return out
