//! Address validation for PFUI ingress. Whatever survives here is authorised
//! for egress, so this is a whitelist: only globally routable unicast
//! addresses pass, in canonical form.
//!
//! The reject tables are the normative list (RFC 6890 and the IANA
//! special-purpose registries) rather than a stdlib `is_global()`, which is
//! nightly-only. Parity with `server-python` is one-directional: everything
//! it rejects is rejected here, and rejecting more only refuses extra egress.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum IpVersion {
    V4,
    V6,
}

struct Prefix4 {
    net: u32,
    len: u32,
}

struct Prefix6 {
    net: u128,
    len: u32,
}

const fn p4(a: u8, b: u8, c: u8, d: u8, len: u32) -> Prefix4 {
    Prefix4 {
        net: u32::from_be_bytes([a, b, c, d]),
        len,
    }
}

const fn p6(s: [u16; 8], len: u32) -> Prefix6 {
    let mut net: u128 = 0;
    let mut i = 0;
    while i < 8 {
        net = (net << 16) | s[i] as u128;
        i += 1;
    }
    Prefix6 { net, len }
}

const V4_REJECT: &[Prefix4] = &[
    p4(0, 0, 0, 0, 8),       // "this network", incl. the 0.0.0.0 sentinel
    p4(10, 0, 0, 0, 8),      // RFC 1918
    p4(100, 64, 0, 0, 10),   // CGNAT
    p4(127, 0, 0, 0, 8),     // loopback
    p4(169, 254, 0, 0, 16),  // link-local
    p4(172, 16, 0, 0, 12),   // RFC 1918
    p4(192, 0, 0, 0, 24),    // IETF protocol assignments (whole /24)
    p4(192, 0, 2, 0, 24),    // documentation
    p4(192, 88, 99, 0, 24),  // 6to4 relay anycast, deprecated
    p4(192, 168, 0, 0, 16),  // RFC 1918
    p4(198, 18, 0, 0, 15),   // benchmarking
    p4(198, 51, 100, 0, 24), // documentation
    p4(203, 0, 113, 0, 24),  // documentation
    p4(224, 0, 0, 0, 4),     // multicast
    p4(240, 0, 0, 0, 4),     // reserved, incl. broadcast
];

const V6_REJECT: &[Prefix6] = &[
    p6([0, 0, 0, 0, 0, 0, 0, 0], 96),      // ::, ::1 and v4-compatible
    p6([0, 0, 0, 0, 0, 0xffff, 0, 0], 96), // v4-mapped, even when the mapped address is global
    p6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96), // NAT64 well-known prefix
    p6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48), // NAT64 local-use
    p6([0x100, 0, 0, 0, 0, 0, 0, 0], 64),  // discard-only
    p6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23), // IETF protocol assignments (whole /23)
    p6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32), // documentation
    p6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16), // 6to4
    p6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20), // documentation
    p6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),  // ULA
    p6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10), // link-local
    p6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10), // site-local, deprecated
    p6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8),  // multicast
];

fn rejected_v4(ip: Ipv4Addr) -> bool {
    let x = u32::from(ip);
    V4_REJECT.iter().any(|p| (x ^ p.net) >> (32 - p.len) == 0)
}

fn rejected_v6(ip: Ipv6Addr) -> bool {
    let x = u128::from(ip);
    V6_REJECT.iter().any(|p| (x ^ p.net) >> (128 - p.len) == 0)
}

/// Canonical text form of a globally routable unicast address, else None.
///
/// Canonicalisation is load-bearing: Redis keys, PF pushes and table reads
/// must agree on IPv6 spelling, or the sync loop deletes and re-adds the same
/// address forever.
pub fn routable(address: &str, version: Option<IpVersion>) -> Option<String> {
    let addr: IpAddr = address.parse().ok()?;
    let addr_version = match addr {
        IpAddr::V4(_) => IpVersion::V4,
        IpAddr::V6(_) => IpVersion::V6,
    };
    if let Some(v) = version {
        if v != addr_version {
            return None;
        }
    }
    let ok = match addr {
        IpAddr::V4(ip) => !rejected_v4(ip),
        IpAddr::V6(ip) => !rejected_v6(ip),
    };
    // Rust's IpAddr Display is RFC 5952 (lowercase, :: compression), matching
    // Python's str(ip_address(...))
    ok.then(|| addr.to_string())
}

/// (ip, ttl) pairs for every routable record of `version`.
///
/// A ttl of 0 means do-not-cache and must survive, so the test is for absence
/// rather than truthiness. Coercion matches the reference implementation:
/// integers as-is, floats truncated, numeric strings parsed, booleans as 0/1.
pub fn extract(records: Option<&serde_json::Value>, version: IpVersion) -> Vec<(String, i64)> {
    let mut out = Vec::new();
    let Some(arr) = records.and_then(|v| v.as_array()) else {
        return out;
    };
    for rr in arr {
        let Some(obj) = rr.as_object() else { continue };
        let Some(ip) = obj
            .get("ip")
            .and_then(|v| v.as_str())
            .and_then(|s| routable(s, Some(version)))
        else {
            continue;
        };
        let Some(ttl) = obj.get("ttl").and_then(coerce_ttl) else {
            continue;
        };
        out.push((ip, ttl));
    }
    out
}

fn coerce_ttl(v: &serde_json::Value) -> Option<i64> {
    match v {
        serde_json::Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        serde_json::Value::String(s) => s.parse().ok(),
        serde_json::Value::Bool(b) => Some(*b as i64),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Every address the reference implementation rejects
    const PYTHON_REJECTS: &[&str] = &[
        "0.0.0.0", // blocklist sentinel
        "::",
        "0:0:0:0:0:0:0:0", // same sentinel, non-canonical spelling
        "0::0",
        "10.0.0.1", // RFC 1918
        "192.168.1.1",
        "172.16.0.1",
        "100.64.0.1",  // CGNAT
        "169.254.1.1", // link-local
        "127.0.0.1",   // loopback
        "224.0.0.1",   // multicast
        "ff02::1",
        "::1",
        "fe80::1",
        "fc00::1",         // ULA
        "::ffff:10.0.0.1", // v4-mapped private
        "::ffff:8.8.8.8",  // v4-mapped global still belongs in no v6 table
        "not-an-ip",
        "",
        "8.8.8.8/32",
    ];

    #[test]
    fn python_reject_cases() {
        for addr in PYTHON_REJECTS {
            assert_eq!(routable(addr, None), None, "{addr}");
        }
    }

    // One reject inside and one accept just outside every table row, so a
    // dropped or mistyped prefix fails
    const ROW_PAIRS_REJECT: &[&str] = &[
        "0.1.2.3",
        "10.255.255.255",
        "100.127.255.255",
        "127.255.255.255",
        "169.254.0.1",
        "172.31.255.255",
        "192.0.0.9", // CPython carve-out, deliberately rejected here
        "192.0.2.1",
        "192.88.99.1",
        "192.168.255.255",
        "198.19.255.255",
        "198.51.100.1",
        "203.0.113.1",
        "239.255.255.255",
        "240.0.0.1",
        "255.255.255.255",
        "::2", // inside ::/96
        "::ffff:1.2.3.4",
        "64:ff9b::8.8.8.8",
        "64:ff9b:1::1",
        "100::1",
        "2001::1",     // Teredo, inside 2001::/23
        "2001:1::1",   // CPython carve-out, deliberately rejected here
        "2001:1ff::1", // last /32 inside 2001::/23
        "2001:20::1",  // ORCHIDv2 carve-out, deliberately rejected here
        "2001:db8::1",
        "2002::1",
        "3fff::1",
        "fdff::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
    ];

    const ROW_PAIRS_ACCEPT: &[&str] = &[
        "1.0.0.1",
        "11.0.0.0",
        "100.128.0.0",
        "128.0.0.1",
        "169.255.0.0",
        "172.32.0.0",
        "192.0.1.1",
        "192.0.3.1",
        "192.88.100.1",
        "192.169.0.1",
        "198.20.0.1",
        "198.51.101.1",
        "203.0.114.1",
        "223.255.255.255",
        "8.8.8.8",
        "1::1",         // just outside ::/96
        "64:ff9b:2::1", // outside both NAT64 rows
        "100:0:0:1::1", // outside 100::/64
        "2001:200::1",  // first /23 above the IETF block
        "2001:db9::1",
        "2003::1",
        "3fff:1000::1", // outside 3fff::/20
        "fe00::1",      // below fe80::/10, outside fc00::/7
        "2001:4860:4860::8888",
        "2606:4700:4700::1111",
    ];

    #[test]
    fn every_table_row_has_a_reject_inside_and_accept_outside() {
        for addr in ROW_PAIRS_REJECT {
            assert_eq!(routable(addr, None), None, "{addr} must be rejected");
        }
        for addr in ROW_PAIRS_ACCEPT {
            assert!(routable(addr, None).is_some(), "{addr} must be accepted");
        }
    }

    #[test]
    fn routable_returns_canonical_form() {
        for (addr, canon) in [
            ("8.8.8.8", "8.8.8.8"),
            ("1.1.1.1", "1.1.1.1"),
            ("2001:4860:4860::8888", "2001:4860:4860::8888"),
            (
                "2001:4860:4860:0000:0000:0000:0000:8888",
                "2001:4860:4860::8888",
            ),
            (
                "2001:4860:4860::8888".to_uppercase().as_str(),
                "2001:4860:4860::8888",
            ),
        ] {
            assert_eq!(routable(addr, None).as_deref(), Some(canon));
        }
    }

    #[test]
    fn version_mismatch_rejected() {
        assert_eq!(routable("8.8.8.8", Some(IpVersion::V6)), None);
        assert_eq!(routable("2001:4860:4860::8888", Some(IpVersion::V4)), None);
    }

    #[test]
    fn extract_filters_and_canonicalises() {
        let records = json!([
            {"ip": "8.8.8.8", "ttl": 3600},
            {"ip": "0.0.0.0", "ttl": 3600},
            {"ip": "10.0.0.1", "ttl": 3600},
            {"ip": "8.8.4.4", "ttl": "300"},
        ]);
        assert_eq!(
            extract(Some(&records), IpVersion::V4),
            vec![("8.8.8.8".into(), 3600), ("8.8.4.4".into(), 300)]
        );
    }

    #[test]
    fn extract_keeps_zero_ttl() {
        // A ttl of 0 means do-not-cache, not absent; dropping it blocks egress
        let records = json!([{"ip": "8.8.8.8", "ttl": 0}]);
        assert_eq!(
            extract(Some(&records), IpVersion::V4),
            vec![("8.8.8.8".into(), 0)]
        );
    }

    #[test]
    fn extract_tolerates_missing_and_malformed_records() {
        let records = json!([
            null,
            "garbage",
            {"ttl": 3600},
            {"ip": "8.8.8.8"},
            {"ip": "8.8.8.8", "ttl": "abc"},
            {"ip": "8.8.8.8", "ttl": null},
            {"ip": "8.8.8.8", "ttl": 60},
        ]);
        assert_eq!(
            extract(Some(&records), IpVersion::V4),
            vec![("8.8.8.8".into(), 60)]
        );
    }

    #[test]
    fn extract_handles_absent_and_non_array_input() {
        assert!(extract(None, IpVersion::V4).is_empty());
        assert!(extract(Some(&json!("nope")), IpVersion::V4).is_empty());
        assert!(extract(Some(&json!({})), IpVersion::V4).is_empty());
    }

    #[test]
    fn extract_coerces_ttl_like_pythons_int() {
        let records = json!([
            {"ip": "8.8.8.8", "ttl": 3.9},   // int(3.9) == 3
            {"ip": "1.1.1.1", "ttl": true},  // int(True) == 1
            {"ip": "9.9.9.9", "ttl": -5},    // stored as sent, no floor
        ]);
        assert_eq!(
            extract(Some(&records), IpVersion::V4),
            vec![
                ("8.8.8.8".into(), 3),
                ("1.1.1.1".into(), 1),
                ("9.9.9.9".into(), -5)
            ]
        );
    }
}
