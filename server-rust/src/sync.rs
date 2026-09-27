//! The expiry loop, one thread per address family. Each cycle expires Redis
//! entries whose TTL or cache expiry has passed, then reconciles the PF table
//! and the persist file with what Redis still holds.
//!
//! The read order is load-bearing: the PF table, or the file, is read before
//! Redis. Deletions are driven by "present in the table, absent from Redis",
//! so reading Redis first would make an IP whitelisted between the two reads
//! look orphaned. Reading Redis last only retains an expired entry one cycle.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::logger::Logger;
use crate::persist;
use crate::store::Expired;

/// The stores one sync cycle reads and writes, behind a trait so tests can
/// inject fakes. Reads return errors, since a partial read must skip the
/// cycle; writes log internally, as the receiver's do.
pub trait SyncOps: Send + Sync {
    /// Entries whose Redis metadata says they are past expiry.
    fn expired_entries(&self, table: &str) -> Result<Vec<Expired>, String>;
    fn db_pop(&self, table: &str, ips: &[String]) -> Result<(), String>;
    /// Every IP currently keyed in the table.
    fn db_ips(&self, table: &str) -> Result<Vec<String>, String>;
    /// The PF table's current contents, canonicalised.
    fn table_show(&self, table: &str) -> Result<Vec<String>, String>;
    fn table_pop(&self, table: &str, ips: &[String]);
    fn table_push(&self, table: &str, ips: &[String]);
}

/// What one cycle did, for the summary line.
#[derive(Default)]
struct Worked {
    /// Entries in the PF table after the cycle read it
    size: usize,
    expired: usize,
    table_added: usize,
    table_removed: usize,
    file_added: usize,
    file_removed: usize,
}

impl Worked {
    /// A steady state logs nothing, so every summary line means work was done.
    fn changed(&self) -> bool {
        self.expired | self.table_added | self.table_removed | self.file_added | self.file_removed
            != 0
    }
}

/// Expire IPs whose metadata says they are past their TTL or cache expiry.
fn scan_redis_db(ops: &dyn SyncOps, table: &str, log: &Logger) -> usize {
    let expired = match ops.expired_entries(table) {
        Ok(e) => e,
        Err(e) => {
            // A transient Redis fault is retried next SCAN_PERIOD
            log.error(&format!(
                "Failed to scan Redis for {table}, retrying next scan: {e}"
            ));
            return 0;
        }
    };
    if expired.is_empty() {
        return 0;
    }
    let ips: Vec<String> = expired.iter().map(|e| e.ip.clone()).collect();
    if log.verbose {
        let detail = expired
            .iter()
            .map(|e| {
                let qname = if e.qname.is_empty() {
                    "<no qname>"
                } else {
                    &e.qname
                };
                format!("{} ({})", e.ip, qname)
            })
            .collect::<Vec<_>>()
            .join(" ");
        log.info(&format!("TTL expired from {table}: {detail}"));
    }
    if let Err(e) = ops.db_pop(table, &ips) {
        log.error(&format!("Failed to delete {ips:?} from Redis: {e}"));
        return 0;
    }
    ips.len()
}

/// Remove orphaned IPs (no Redis key) from the PF table, add missing ones.
/// Returns the table's size, then what was added and removed.
fn sync_pf_table(ops: &dyn SyncOps, table: &str, log: &Logger) -> (usize, usize, usize) {
    // PF table before Redis, and never diff against a partial read
    let t_ips = match ops.table_show(table) {
        Ok(ips) => ips,
        Err(e) => {
            log.error(&format!(
                "Failed to read PF table {table}, skipping this sync: {e}"
            ));
            return (0, 0, 0);
        }
    };
    let size = t_ips.len();
    let db_ips = match ops.db_ips(table) {
        Ok(ips) => ips,
        Err(e) => {
            log.error(&format!(
                "Failed to read Redis for {table}, skipping this sync: {e}"
            ));
            return (size, 0, 0);
        }
    };
    let t_set: BTreeSet<&str> = t_ips.iter().map(String::as_str).collect();
    let db_set: BTreeSet<&str> = db_ips.iter().map(String::as_str).collect();

    let del: Vec<String> = t_set.difference(&db_set).map(|s| s.to_string()).collect();
    if !del.is_empty() {
        ops.table_pop(table, &del);
    }
    let add: Vec<String> = db_set.difference(&t_set).map(|s| s.to_string()).collect();
    if !add.is_empty() {
        ops.table_push(table, &add);
    }
    (size, add.len(), del.len())
}

/// Remove orphaned IPs from the persist file, add missing ones. Set-based, so
/// file_push's duplicate appends collapse here.
/// Returns what was added and removed.
fn sync_pf_file(ops: &dyn SyncOps, table: &str, file: &Path, log: &Logger) -> (usize, usize) {
    // File before Redis, for the reason given on sync_pf_table
    let content = match std::fs::read_to_string(file) {
        Ok(c) => c,
        Err(e) => {
            log.error(&format!(
                "Failed to read {}, skipping this sync: {e}",
                file.display()
            ));
            return (0, 0);
        }
    };
    let db_ips = match ops.db_ips(table) {
        Ok(ips) => ips,
        Err(e) => {
            log.error(&format!(
                "Failed to read Redis for {table}, skipping this sync: {e}"
            ));
            return (0, 0);
        }
    };
    let f_set: BTreeSet<&str> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .collect();
    let db_set: BTreeSet<&str> = db_ips.iter().map(String::as_str).collect();

    let del: Vec<String> = f_set.difference(&db_set).map(|s| s.to_string()).collect();
    if !del.is_empty() {
        if let Err(e) = persist::file_pop(file, &del) {
            log.error(&format!(
                "Failed to delete {del:?} from {}: {e}",
                file.display()
            ));
        }
    }
    let add: Vec<String> = db_set.difference(&f_set).map(|s| s.to_string()).collect();
    if !add.is_empty() {
        if let Err(e) = persist::file_push(file, &add) {
            log.error(&format!(
                "Failed to append {add:?} to {}: {e}",
                file.display()
            ));
        }
    }
    (add.len(), del.len())
}

/// One full cycle for one address family's table and file.
pub fn run_cycle(ops: &dyn SyncOps, table: &str, file: &Path, log: &Logger) {
    if log.verbose {
        log.info(&format!("Scan for expiring {table} IPs"));
    }
    let mut worked = Worked {
        expired: scan_redis_db(ops, table, log),
        ..Default::default()
    };
    // Each reconciliation reads its own Redis snapshot, after the store it
    // may delete from
    let (size, table_added, table_removed) = sync_pf_table(ops, table, log);
    (worked.size, worked.table_added, worked.table_removed) = (size, table_added, table_removed);
    (worked.file_added, worked.file_removed) = sync_pf_file(ops, table, file, log);

    if worked.changed() {
        log.info(&format!(
            "{table}: {} addresses, {} expired, table +{}/-{}, file +{}/-{}",
            worked.size,
            worked.expired,
            worked.table_added,
            worked.table_removed,
            worked.file_added,
            worked.file_removed
        ));
    }
}

/// Run cycles every `scan_period` seconds until `term`, sleeping in one-second
/// slices so shutdown never waits a whole period. A panicking cycle is caught
/// and retried, since a transient fault must not end expiry for this table.
pub fn spawn(
    ops: Arc<dyn SyncOps>,
    table: String,
    file: PathBuf,
    scan_period: u64,
    term: Arc<AtomicBool>,
    log: Arc<Logger>,
) -> std::io::Result<std::thread::JoinHandle<()>> {
    std::thread::Builder::new()
        .name(format!("sync-{table}"))
        .spawn(move || {
            log.info(&format!("[+] Sync thread started for {table}"));
            'outer: while !term.load(Ordering::Relaxed) {
                let cycle = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run_cycle(ops.as_ref(), &table, &file, &log)
                }));
                if cycle.is_err() {
                    log.error(&format!(
                        "Sync cycle failed for {table}, retrying next scan"
                    ));
                }
                for _ in 0..scan_period.max(1) {
                    if term.load(Ordering::Relaxed) {
                        break 'outer;
                    }
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
            log.info(&format!("[-] Sync thread closing for {table}"));
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogLevel;
    use std::sync::Mutex;

    fn log() -> Logger {
        Logger::stderr(LogLevel::Error, false)
    }

    #[derive(Default)]
    struct FakeOps {
        expired: Vec<Expired>,
        db: Vec<String>,
        table: Vec<String>,
        show_fails: bool,
        db_fails: bool,
        panics: bool,
        calls: Mutex<Vec<String>>,
        popped: Mutex<Vec<Vec<String>>>,
        pushed: Mutex<Vec<Vec<String>>>,
        db_popped: Mutex<Vec<Vec<String>>>,
    }

    impl FakeOps {
        fn record(&self, what: &str) {
            self.calls.lock().unwrap().push(what.to_string());
        }
    }

    impl SyncOps for FakeOps {
        fn expired_entries(&self, _table: &str) -> Result<Vec<Expired>, String> {
            self.record("expired_entries");
            Ok(self.expired.clone())
        }
        fn db_pop(&self, _table: &str, ips: &[String]) -> Result<(), String> {
            self.db_popped.lock().unwrap().push(ips.to_vec());
            Ok(())
        }
        fn db_ips(&self, _table: &str) -> Result<Vec<String>, String> {
            self.record("db_ips");
            if self.db_fails {
                return Err("connection refused".into());
            }
            Ok(self.db.clone())
        }
        fn table_show(&self, _table: &str) -> Result<Vec<String>, String> {
            self.record("table_show");
            if self.panics {
                panic!("unexpected");
            }
            if self.show_fails {
                return Err("pfctl exited 1: table does not exist".into());
            }
            Ok(self.table.clone())
        }
        fn table_pop(&self, _table: &str, ips: &[String]) {
            self.popped.lock().unwrap().push(ips.to_vec());
        }
        fn table_push(&self, _table: &str, ips: &[String]) {
            self.pushed.lock().unwrap().push(ips.to_vec());
        }
    }

    fn strings(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn expired_table_entry_is_removed() {
        let ops = FakeOps {
            db: strings(&["8.8.8.8"]),
            table: strings(&["8.8.8.8", "1.1.1.1"]),
            ..Default::default()
        };
        sync_pf_table(&ops, "t", &log());
        assert_eq!(*ops.popped.lock().unwrap(), vec![strings(&["1.1.1.1"])]);
        assert!(ops.pushed.lock().unwrap().is_empty());
    }

    #[test]
    fn missing_table_entry_is_added() {
        let ops = FakeOps {
            db: strings(&["8.8.8.8", "1.1.1.1"]),
            table: strings(&["8.8.8.8"]),
            ..Default::default()
        };
        sync_pf_table(&ops, "t", &log());
        assert_eq!(*ops.pushed.lock().unwrap(), vec![strings(&["1.1.1.1"])]);
        assert!(ops.popped.lock().unwrap().is_empty());
    }

    #[test]
    fn a_failing_table_read_does_not_look_like_an_empty_table() {
        // A failed read must not diff as empty, which would delete nothing,
        // re-add every live IP, and never expire
        let ops = FakeOps {
            db: strings(&["8.8.8.8"]),
            table: strings(&["8.8.8.8", "1.1.1.1"]),
            show_fails: true,
            ..Default::default()
        };
        sync_pf_table(&ops, "t", &log());
        assert!(ops.popped.lock().unwrap().is_empty());
        assert!(ops.pushed.lock().unwrap().is_empty());
    }

    #[test]
    fn a_genuinely_empty_table_still_gets_its_entries_added() {
        let ops = FakeOps {
            db: strings(&["8.8.8.8"]),
            ..Default::default()
        };
        sync_pf_table(&ops, "t", &log());
        assert_eq!(*ops.pushed.lock().unwrap(), vec![strings(&["8.8.8.8"])]);
    }

    #[test]
    fn a_failing_redis_read_skips_the_diff() {
        let ops = FakeOps {
            table: strings(&["8.8.8.8"]),
            db_fails: true,
            ..Default::default()
        };
        sync_pf_table(&ops, "t", &log());
        assert!(ops.popped.lock().unwrap().is_empty());
        assert!(ops.pushed.lock().unwrap().is_empty());
    }

    #[test]
    fn the_pf_table_is_read_before_redis() {
        let ops = FakeOps::default();
        sync_pf_table(&ops, "t", &log());
        let calls = ops.calls.lock().unwrap();
        let show = calls.iter().position(|c| c == "table_show").unwrap();
        let db = calls.iter().position(|c| c == "db_ips").unwrap();
        assert!(show < db, "table_show must precede db_ips: {calls:?}");
    }

    #[test]
    fn expired_entries_are_popped_from_redis() {
        let ops = FakeOps {
            expired: vec![Expired {
                ip: "9.9.9.9".into(),
                qname: "quad9.example.".into(),
            }],
            ..Default::default()
        };
        scan_redis_db(&ops, "t", &log());
        assert_eq!(*ops.db_popped.lock().unwrap(), vec![strings(&["9.9.9.9"])]);
    }

    #[test]
    fn file_sync_removes_orphans_and_adds_missing() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("persist");
        std::fs::write(&file, "1.1.1.1\n9.9.9.9\n9.9.9.9\n").unwrap();
        let ops = FakeOps {
            db: strings(&["1.1.1.1", "8.8.8.8"]),
            ..Default::default()
        };
        sync_pf_file(&ops, "t", &file, &log());
        let mut lines: Vec<String> = std::fs::read_to_string(&file)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        lines.sort();
        // 9.9.9.9 (orphan, duplicated) gone, 8.8.8.8 added
        assert_eq!(lines, strings(&["1.1.1.1", "8.8.8.8"]));
    }

    #[test]
    fn a_missing_file_skips_the_file_sync() {
        let ops = FakeOps {
            db: strings(&["8.8.8.8"]),
            ..Default::default()
        };
        sync_pf_file(&ops, "t", Path::new("/nonexistent/pfui"), &log());
        // Nothing recorded, nothing panicked; the next cycle retries
    }

    #[test]
    fn a_sync_cycle_failure_does_not_end_the_thread() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("persist");
        std::fs::write(&file, "").unwrap();
        let ops = Arc::new(FakeOps {
            panics: true,
            ..Default::default()
        });
        let term = Arc::new(AtomicBool::new(false));
        let handle = spawn(
            Arc::clone(&ops) as Arc<dyn SyncOps>,
            "t".into(),
            file,
            1,
            Arc::clone(&term),
            Arc::new(log()),
        )
        .unwrap();
        // Give it time for at least one panicking cycle
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!handle.is_finished(), "thread died on a cycle failure");
        assert!(
            ops.calls.lock().unwrap().len() >= 2,
            "expiry scan must still run after a panic"
        );
        term.store(true, Ordering::Relaxed);
        handle.join().unwrap();
    }

    #[test]
    fn a_cycle_that_changed_nothing_logs_nothing() {
        // INFO stays quiet in a steady state
        let quiet = Worked {
            size: 142,
            ..Default::default()
        };
        assert!(!quiet.changed());
        for worked in [
            Worked {
                expired: 1,
                ..Default::default()
            },
            Worked {
                table_added: 1,
                ..Default::default()
            },
            Worked {
                table_removed: 1,
                ..Default::default()
            },
            Worked {
                file_added: 1,
                ..Default::default()
            },
            Worked {
                file_removed: 1,
                ..Default::default()
            },
        ] {
            assert!(worked.changed());
        }
    }

    #[test]
    fn the_summary_counts_every_store_the_cycle_touched() {
        let ops = FakeOps {
            expired: vec![Expired {
                ip: "1.1.1.1".into(),
                qname: "one.one.one.one.".into(),
            }],
            db: vec!["1.0.0.1".into(), "8.8.8.8".into()],
            table: vec!["1.0.0.1".into(), "9.9.9.9".into()],
            ..Default::default()
        };
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("ipv4_domains");
        std::fs::write(&file, "1.0.0.1\n203.0.113.9\n").unwrap();
        run_cycle(&ops, "t4", &file, &log());

        // 8.8.8.8 was missing from the table, 9.9.9.9 orphaned in it
        assert_eq!(
            *ops.pushed.lock().unwrap(),
            vec![vec!["8.8.8.8".to_string()]]
        );
        assert_eq!(
            *ops.popped.lock().unwrap(),
            vec![vec!["9.9.9.9".to_string()]]
        );
        let published: Vec<String> = std::fs::read_to_string(&file)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect();
        assert!(published.contains(&"8.8.8.8".to_string()));
        assert!(!published.contains(&"203.0.113.9".to_string()));
    }
}
