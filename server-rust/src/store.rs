//! Redis expiry store. The key schema is shared with the Python daemon and is
//! therefore frozen: key `{table}^{ip}`, hash fields `epoch`, `ttl` or
//! `expires` as decimal strings, `kind` as the literal rr|cache, and `qname`.
//!
//! The functions are generic over `Db`, the set of Redis commands used, so
//! tests can inject a recorder.

use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Rr,
    Cache,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Rr => "rr",
            Kind::Cache => "cache",
        }
    }
}

/// Connection faults propagate so a scan cycle can skip and retry; a fault on
/// one key must not void a batch.
#[derive(Debug)]
pub struct DbError {
    pub connection: bool,
    pub msg: String,
}

impl fmt::Display for DbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum DbCmd {
    HSet {
        key: String,
        fields: Vec<(&'static str, String)>,
    },
    HDel {
        key: String,
        field: &'static str,
    },
    Expire {
        key: String,
        seconds: i64,
    },
    Del {
        key: String,
    },
}

pub trait Db {
    /// Run one pipeline of write commands atomically (MULTI/EXEC).
    fn run_atomic(&mut self, cmds: &[DbCmd]) -> Result<(), DbError>;
    /// Every key matching `pattern`, SCANned in COUNT-sized slices.
    fn scan_keys(&mut self, pattern: &str, count: usize) -> Result<Vec<String>, DbError>;
    /// HGETALL each key. A per-key fault yields None for that key; connection
    /// faults fail the call.
    fn hgetall_batch(
        &mut self,
        keys: &[String],
    ) -> Result<Vec<Option<HashMap<String, String>>>, DbError>;
}

/// Backstop lifetime only; the scan loop owns expiry. Floored at 1 because
/// Redis reads EXPIRE 0 as delete-now, which would discard a ttl-0 record
/// before its own scan saw it.
fn key_lifetime(window: i64, scan_period: u64) -> i64 {
    (window.saturating_add(scan_period as i64)).max(1)
}

/// Store IPs and metadata. The TTL is recorded exactly as sent, with no floor:
/// a ttl of 0 means do-not-cache, and TTL_MULTIPLIER is the only knob for
/// holding entries longer. The losing field is deleted because hash writes
/// merge, and a key holding both `ttl` and `expires` would be ambiguous.
#[allow(clippy::too_many_arguments)]
pub fn db_push(
    db: &mut impl Db,
    table: &str,
    data: &[(String, i64)],
    kind: Kind,
    qname: &str,
    now: i64,
    scan_period: u64,
    ttl_multiplier: u32,
) -> Result<(), DbError> {
    let mut cmds = Vec::new();
    for (ip, rr_ttl) in data {
        let key = format!("{table}^{ip}");
        match kind {
            Kind::Cache => {
                cmds.push(DbCmd::HSet {
                    key: key.clone(),
                    fields: vec![
                        ("epoch", now.to_string()),
                        ("kind", "cache".to_string()),
                        ("expires", rr_ttl.to_string()),
                        ("qname", qname.to_string()),
                    ],
                });
                cmds.push(DbCmd::HDel {
                    key: key.clone(),
                    field: "ttl",
                });
                cmds.push(DbCmd::Expire {
                    seconds: key_lifetime((rr_ttl - now).max(0), scan_period),
                    key,
                });
            }
            Kind::Rr => {
                cmds.push(DbCmd::HSet {
                    key: key.clone(),
                    fields: vec![
                        ("epoch", now.to_string()),
                        ("kind", "rr".to_string()),
                        ("ttl", rr_ttl.to_string()),
                        ("qname", qname.to_string()),
                    ],
                });
                cmds.push(DbCmd::HDel {
                    key: key.clone(),
                    field: "expires",
                });
                cmds.push(DbCmd::Expire {
                    seconds: key_lifetime(
                        rr_ttl.saturating_mul(ttl_multiplier as i64),
                        scan_period,
                    ),
                    key,
                });
            }
        }
    }
    db.run_atomic(&cmds)
}

/// Remove IPs from the table.
pub fn db_pop(db: &mut impl Db, table: &str, ips: &[String]) -> Result<(), DbError> {
    let cmds: Vec<DbCmd> = ips
        .iter()
        .map(|ip| DbCmd::Del {
            key: format!("{table}^{ip}"),
        })
        .collect();
    db.run_atomic(&cmds)
}

/// True when one IP's hash has expired. The rule branches on `kind`, never on
/// which fields are present: a key refreshed by both paths holds `ttl` and
/// `expires`, and field presence would judge a fresh record against a stale
/// one. Unreadable metadata cannot authorise egress, so it counts as expired,
/// as does an unrecognised `kind`.
pub fn is_expired(meta: &HashMap<String, String>, now: i64, multiplier: u32) -> bool {
    let int = |field: &str| meta.get(field).and_then(|v| v.parse::<i64>().ok());
    match meta.get("kind").map(String::as_str) {
        Some("cache") => match int("expires") {
            Some(expires) => expires <= now,
            None => true,
        },
        Some("rr") => match int("ttl") {
            Some(ttl) => {
                let epoch = int("epoch").unwrap_or(now);
                epoch.saturating_add(ttl.saturating_mul(multiplier as i64)) <= now
            }
            None => true,
        },
        _ => true,
    }
}

/// IPs of every expired key in `table`, read in batches of `batch`.
///
/// A per-key fault or an empty hash skips that key; connection errors
/// propagate so the caller skips the cycle rather than diffing a partial read.
pub fn expired_keys(
    db: &mut impl Db,
    table: &str,
    now: i64,
    multiplier: u32,
    batch: usize,
) -> Result<Vec<String>, DbError> {
    let keys = db.scan_keys(&format!("{table}^*"), batch)?;
    let mut expired = Vec::new();
    for chunk in keys.chunks(batch.max(1)) {
        let metas = db.hgetall_batch(chunk)?;
        for (key, meta) in chunk.iter().zip(metas) {
            let Some(meta) = meta else { continue };
            if meta.is_empty() {
                continue;
            }
            if is_expired(&meta, now, multiplier) {
                if let Some((_, ip)) = key.split_once('^') {
                    expired.push(ip.to_string());
                }
            }
        }
    }
    Ok(expired)
}

/// Every IP currently keyed in `table`, from the key names alone.
pub fn db_ips(db: &mut impl Db, table: &str, batch: usize) -> Result<Vec<String>, DbError> {
    Ok(db
        .scan_keys(&format!("{table}^*"), batch)?
        .iter()
        .filter_map(|key| key.split_once('^').map(|(_, ip)| ip.to_string()))
        .collect())
}

/// Production Db over a redis-rs connection.
pub struct RedisDb<C: redis::ConnectionLike>(pub C);

fn map_err(e: redis::RedisError) -> DbError {
    DbError {
        connection: e.is_io_error() || e.is_timeout() || e.is_connection_dropped(),
        msg: e.to_string(),
    }
}

impl<C: redis::ConnectionLike> Db for RedisDb<C> {
    fn run_atomic(&mut self, cmds: &[DbCmd]) -> Result<(), DbError> {
        if cmds.is_empty() {
            return Ok(());
        }
        let mut pipe = redis::pipe();
        pipe.atomic();
        for cmd in cmds {
            match cmd {
                DbCmd::HSet { key, fields } => {
                    let c = pipe.cmd("HSET").arg(key);
                    for (field, value) in fields {
                        c.arg(*field).arg(value);
                    }
                    c.ignore();
                }
                DbCmd::HDel { key, field } => {
                    pipe.cmd("HDEL").arg(key).arg(*field).ignore();
                }
                DbCmd::Expire { key, seconds } => {
                    pipe.cmd("EXPIRE").arg(key).arg(*seconds).ignore();
                }
                DbCmd::Del { key } => {
                    pipe.cmd("DEL").arg(key).ignore();
                }
            }
        }
        pipe.query::<()>(&mut self.0).map_err(map_err)
    }

    fn scan_keys(&mut self, pattern: &str, count: usize) -> Result<Vec<String>, DbError> {
        let mut keys = Vec::new();
        let mut cursor: u64 = 0;
        loop {
            let (next, mut slice): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(count)
                .query(&mut self.0)
                .map_err(map_err)?;
            keys.append(&mut slice);
            if next == 0 {
                return Ok(keys);
            }
            cursor = next;
        }
    }

    fn hgetall_batch(
        &mut self,
        keys: &[String],
    ) -> Result<Vec<Option<HashMap<String, String>>>, DbError> {
        let mut pipe = redis::pipe();
        for key in keys {
            pipe.cmd("HGETALL").arg(key);
        }
        match pipe
            .query::<Vec<HashMap<String, String>>>(&mut self.0)
            .map_err(map_err)
        {
            Ok(metas) => Ok(metas.into_iter().map(Some).collect()),
            // A single WRONGTYPE key fails the whole pipeline, so fall back
            // to per-key reads and skip only the offending key
            Err(e) if !e.connection => keys
                .iter()
                .map(|key| {
                    match redis::cmd("HGETALL")
                        .arg(key)
                        .query::<HashMap<String, String>>(&mut self.0)
                        .map_err(map_err)
                    {
                        Ok(meta) => Ok(Some(meta)),
                        Err(e) if !e.connection => Ok(None),
                        Err(e) => Err(e),
                    }
                })
                .collect(),
            Err(e) => Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeDb {
        cmds: Vec<DbCmd>,
        fail: bool,
        keys: Vec<String>,
        metas: Vec<Option<HashMap<String, String>>>,
        scan_fails: bool,
    }

    impl Db for FakeDb {
        fn run_atomic(&mut self, cmds: &[DbCmd]) -> Result<(), DbError> {
            if self.fail {
                return Err(DbError {
                    connection: true,
                    msg: "connection refused".into(),
                });
            }
            self.cmds.extend(cmds.iter().map(clone_cmd));
            Ok(())
        }
        fn scan_keys(&mut self, _pattern: &str, _count: usize) -> Result<Vec<String>, DbError> {
            if self.scan_fails {
                return Err(DbError {
                    connection: true,
                    msg: "connection refused".into(),
                });
            }
            Ok(self.keys.clone())
        }
        fn hgetall_batch(
            &mut self,
            keys: &[String],
        ) -> Result<Vec<Option<HashMap<String, String>>>, DbError> {
            Ok(self.metas[..keys.len()].to_vec())
        }
    }

    fn clone_cmd(c: &DbCmd) -> DbCmd {
        match c {
            DbCmd::HSet { key, fields } => DbCmd::HSet {
                key: key.clone(),
                fields: fields.clone(),
            },
            DbCmd::HDel { key, field } => DbCmd::HDel {
                key: key.clone(),
                field,
            },
            DbCmd::Expire { key, seconds } => DbCmd::Expire {
                key: key.clone(),
                seconds: *seconds,
            },
            DbCmd::Del { key } => DbCmd::Del { key: key.clone() },
        }
    }

    fn meta(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn field<'a>(cmds: &'a [DbCmd], key: &str, name: &str) -> Option<&'a str> {
        cmds.iter().find_map(|c| match c {
            DbCmd::HSet { key: k, fields } if k == key => fields
                .iter()
                .find(|(f, _)| *f == name)
                .map(|(_, v)| v.as_str()),
            _ => None,
        })
    }

    fn expire_of(cmds: &[DbCmd], key: &str) -> Option<i64> {
        cmds.iter().find_map(|c| match c {
            DbCmd::Expire { key: k, seconds } if k == key => Some(*seconds),
            _ => None,
        })
    }

    const NOW: i64 = 1_700_000_000;

    fn push_one(db: &mut FakeDb, ttl: i64, kind: Kind, scan_period: u64, multiplier: u32) {
        db_push(
            db,
            "t",
            &[("8.8.8.8".to_string(), ttl)],
            kind,
            "example.com.",
            NOW,
            scan_period,
            multiplier,
        )
        .unwrap();
    }

    #[test]
    fn rr_ttl_is_stored_exactly_as_sent() {
        for ttl in [0i64, 1, 60, 3600, 604800] {
            let mut db = FakeDb::default();
            push_one(&mut db, ttl, Kind::Rr, 300, 4);
            assert_eq!(field(&db.cmds, "t^8.8.8.8", "ttl"), Some(&*ttl.to_string()));
        }
    }

    #[test]
    fn short_ttl_is_not_raised_to_an_hour() {
        let mut db = FakeDb::default();
        push_one(&mut db, 60, Kind::Rr, 300, 4);
        assert_eq!(field(&db.cmds, "t^8.8.8.8", "ttl"), Some("60"));
        assert_eq!(expire_of(&db.cmds, "t^8.8.8.8"), Some(60 * 4 + 300));
    }

    #[test]
    fn do_not_cache_answer_keeps_its_zero_ttl() {
        let mut db = FakeDb::default();
        push_one(&mut db, 0, Kind::Rr, 300, 4);
        assert_eq!(field(&db.cmds, "t^8.8.8.8", "ttl"), Some("0"));
    }

    #[test]
    fn zero_ttl_key_is_not_deleted_by_its_own_backstop() {
        let mut db = FakeDb::default();
        push_one(&mut db, 0, Kind::Rr, 300, 4);
        assert_eq!(expire_of(&db.cmds, "t^8.8.8.8"), Some(300));
    }

    #[test]
    fn backstop_is_never_non_positive_even_with_a_zero_scan_period() {
        let mut db = FakeDb::default();
        push_one(&mut db, 0, Kind::Rr, 0, 4);
        assert_eq!(expire_of(&db.cmds, "t^8.8.8.8"), Some(1));
    }

    #[test]
    fn cache_entry_stores_the_absolute_expiry_and_drops_the_ttl_field() {
        let mut db = FakeDb::default();
        push_one(&mut db, NOW + 120, Kind::Cache, 300, 4);
        assert_eq!(
            field(&db.cmds, "t^8.8.8.8", "expires"),
            Some(&*(NOW + 120).to_string())
        );
        assert_eq!(field(&db.cmds, "t^8.8.8.8", "kind"), Some("cache"));
        assert!(db.cmds.contains(&DbCmd::HDel {
            key: "t^8.8.8.8".into(),
            field: "ttl"
        }));
        assert_eq!(expire_of(&db.cmds, "t^8.8.8.8"), Some(120 + 300));
    }

    #[test]
    fn rr_entry_drops_the_expires_field() {
        let mut db = FakeDb::default();
        push_one(&mut db, 60, Kind::Rr, 300, 4);
        assert!(db.cmds.contains(&DbCmd::HDel {
            key: "t^8.8.8.8".into(),
            field: "expires"
        }));
    }

    #[test]
    fn already_expired_cache_entry_still_gets_a_positive_backstop() {
        let mut db = FakeDb::default();
        push_one(&mut db, NOW - 500, Kind::Cache, 300, 4);
        assert_eq!(expire_of(&db.cmds, "t^8.8.8.8"), Some(300));
    }

    #[test]
    fn qname_is_recorded_per_key() {
        let mut db = FakeDb::default();
        push_one(&mut db, 60, Kind::Rr, 300, 4);
        assert_eq!(field(&db.cmds, "t^8.8.8.8", "qname"), Some("example.com."));
    }

    #[test]
    fn db_failure_is_reported() {
        let mut db = FakeDb {
            fail: true,
            ..Default::default()
        };
        let result = db_push(
            &mut db,
            "t",
            &[("8.8.8.8".to_string(), 60)],
            Kind::Rr,
            "",
            NOW,
            300,
            4,
        );
        assert!(result.is_err());
    }

    #[test]
    fn db_pop_deletes_each_key() {
        let mut db = FakeDb::default();
        db_pop(&mut db, "t", &["8.8.8.8".into(), "1.1.1.1".into()]).unwrap();
        assert_eq!(
            db.cmds,
            vec![
                DbCmd::Del {
                    key: "t^8.8.8.8".into()
                },
                DbCmd::Del {
                    key: "t^1.1.1.1".into()
                }
            ]
        );
    }

    #[test]
    fn cache_entry_not_expired_before_expires() {
        let m = meta(&[("kind", "cache"), ("expires", &(NOW + 60).to_string())]);
        assert!(!is_expired(&m, NOW, 4));
    }

    #[test]
    fn cache_entry_expired_after_expires() {
        let m = meta(&[("kind", "cache"), ("expires", &(NOW - 1).to_string())]);
        assert!(is_expired(&m, NOW, 4));
    }

    #[test]
    fn rr_entry_uses_ttl_times_multiplier() {
        let m = meta(&[
            ("kind", "rr"),
            ("ttl", "60"),
            ("epoch", &(NOW - 239).to_string()),
        ]);
        assert!(!is_expired(&m, NOW, 4)); // 60*4 = 240 > 239
        let m = meta(&[
            ("kind", "rr"),
            ("ttl", "60"),
            ("epoch", &(NOW - 240).to_string()),
        ]);
        assert!(is_expired(&m, NOW, 4));
    }

    #[test]
    fn long_ttl_rr_is_not_treated_as_a_timestamp() {
        // A week-long TTL stays relative: fresh entry, nowhere near expiry
        let m = meta(&[
            ("kind", "rr"),
            ("ttl", "604800"),
            ("epoch", &NOW.to_string()),
        ]);
        assert!(!is_expired(&m, NOW + 60, 4));
    }

    #[test]
    fn merged_hash_prefers_kind_over_field_presence() {
        // Holds a live cache expiry AND a stale rr ttl; kind decides
        let m = meta(&[
            ("kind", "cache"),
            ("expires", &(NOW + 600).to_string()),
            ("ttl", "1"),
            ("epoch", &(NOW - 999).to_string()),
        ]);
        assert!(!is_expired(&m, NOW, 4));
    }

    #[test]
    fn legacy_key_without_kind_is_purged() {
        let m = meta(&[("ttl", "60"), ("epoch", &NOW.to_string())]);
        assert!(is_expired(&m, NOW, 4));
    }

    #[test]
    fn malformed_metadata_is_purged() {
        let m = meta(&[("kind", "rr"), ("ttl", "not-a-number")]);
        assert!(is_expired(&m, NOW, 4));
        let m = meta(&[("kind", "cache")]);
        assert!(is_expired(&m, NOW, 4));
    }

    #[test]
    fn one_unreadable_key_does_not_void_the_batch() {
        let mut db = FakeDb {
            keys: vec!["t^1.1.1.1".into(), "t^2.2.2.2".into(), "t^3.3.3.3".into()],
            metas: vec![
                Some(meta(&[("kind", "cache"), ("expires", "1")])), // expired
                None,                                               // WRONGTYPE: skipped
                Some(HashMap::new()),                               // vanished: skipped
            ],
            ..Default::default()
        };
        assert_eq!(
            expired_keys(&mut db, "t", NOW, 4, 500).unwrap(),
            vec!["1.1.1.1".to_string()]
        );
    }

    #[test]
    fn connection_error_propagates_to_caller() {
        let mut db = FakeDb {
            scan_fails: true,
            ..Default::default()
        };
        assert!(expired_keys(&mut db, "t", NOW, 4, 500).is_err());
    }

    #[test]
    fn expired_key_yields_the_ip_after_the_separator() {
        let mut db = FakeDb {
            keys: vec!["t^2001:db8::1".into()],
            metas: vec![Some(meta(&[("kind", "cache"), ("expires", "1")]))],
            ..Default::default()
        };
        // Split on the first ^ only, so IPv6 colons survive
        assert_eq!(
            expired_keys(&mut db, "t", NOW, 4, 500).unwrap(),
            vec!["2001:db8::1".to_string()]
        );
    }
}
