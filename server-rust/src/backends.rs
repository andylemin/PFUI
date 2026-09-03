//! Production backends: PF tables, Redis expiry and persist files.
//!
//! Failures are logged rather than propagated: the PF push runs before the
//! client is acknowledged, and the scan loop reconciles the stores.

use std::cell::RefCell;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::Config;
use crate::logger::Logger;
use crate::pf::{self, PfConfig};
use crate::receiver::Backends;
use crate::store::{self, Kind, RedisDb};

pub struct RealBackends {
    cfg: Arc<Config>,
    log: Arc<Logger>,
    client: redis::Client,
}

thread_local! {
    // One connection per thread, opened lazily and dropped on any error so
    // the next use reconnects
    static CONN: RefCell<Option<redis::Connection>> = const { RefCell::new(None) };
}

impl RealBackends {
    /// REDIS_HOST is resolved once here, before any unveil or pledge lockdown.
    /// The client connects lazily, so a firewall booting before Redis still
    /// starts and whitelists.
    pub fn new(cfg: Arc<Config>, log: Arc<Logger>) -> Result<Self, String> {
        use std::net::ToSocketAddrs;
        let addr = (cfg.redis_host.as_str(), cfg.redis_port)
            .to_socket_addrs()
            .map_err(|e| format!("cannot resolve REDIS_HOST {}: {e}", cfg.redis_host))?
            .next()
            .ok_or_else(|| format!("REDIS_HOST {} resolved to nothing", cfg.redis_host))?;
        let url = format!("redis://{}:{}/{}", addr.ip(), addr.port(), cfg.redis_db);
        let client = redis::Client::open(url).map_err(|e| e.to_string())?;
        Ok(RealBackends { cfg, log, client })
    }

    fn pf_config(&self) -> PfConfig<'_> {
        PfConfig {
            ctl: self.cfg.ctl,
            devpf: &self.cfg.devpf,
            pfctl: Path::new(pf::DEFAULT_PFCTL),
        }
    }

    fn with_conn<T>(
        &self,
        f: impl FnOnce(&mut redis::Connection) -> Result<T, store::DbError>,
    ) -> Result<T, String> {
        CONN.with(|slot| {
            let mut slot = slot.borrow_mut();
            if slot.is_none() {
                *slot = Some(self.client.get_connection().map_err(|e| e.to_string())?);
            }
            match f(slot.as_mut().expect("connection present")) {
                Ok(v) => Ok(v),
                Err(e) => {
                    // Drop it so the next use reconnects
                    *slot = None;
                    Err(e.to_string())
                }
            }
        })
    }

    fn now() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }
}

impl Backends for RealBackends {
    fn table_push(&self, table: &str, ips: &[IpAddr]) {
        match pf::table_push(&self.pf_config(), table, ips) {
            Ok(outcome) => {
                if let Some(ioctl_err) = outcome.ioctl_error {
                    self.log.error(&format!(
                        "IOCTL failed installing into PF table {table} ({ioctl_err}); \
                         pfctl served the call"
                    ));
                }
            }
            Err(e) => self.log.error(&format!(
                "Failed to install {ips:?} into PF table {table}: {e}"
            )),
        }
    }

    fn db_push(&self, table: &str, data: &[(String, i64)], kind: Kind, qname: &str) {
        let result = self.with_conn(|conn| {
            store::db_push(
                &mut RedisDb(&mut *conn),
                table,
                data,
                kind,
                qname,
                Self::now(),
                self.cfg.scan_period,
                self.cfg.ttl_multiplier,
            )
        });
        if let Err(e) = result {
            self.log
                .error(&format!("Failed to store {data:?} to Redis: {e}"));
        }
    }

    fn file_push(&self, file: &Path, ips: &[String]) {
        if let Err(e) = crate::persist::file_push(file, ips) {
            self.log.error(&format!(
                "Failed to append {ips:?} to {}: {e}",
                file.display()
            ));
        }
    }
}

impl crate::sync::SyncOps for RealBackends {
    fn expired_entries(&self, table: &str) -> Result<Vec<store::Expired>, String> {
        self.with_conn(|conn| {
            store::expired_keys(
                &mut RedisDb(&mut *conn),
                table,
                Self::now(),
                self.cfg.ttl_multiplier,
                500,
            )
        })
    }

    fn db_pop(&self, table: &str, ips: &[String]) -> Result<(), String> {
        self.with_conn(|conn| store::db_pop(&mut RedisDb(&mut *conn), table, ips))
    }

    fn db_ips(&self, table: &str) -> Result<Vec<String>, String> {
        self.with_conn(|conn| store::db_ips(&mut RedisDb(&mut *conn), table, 500))
    }

    fn table_show(&self, table: &str) -> Result<Vec<String>, String> {
        match pf::table_show(&self.pf_config(), table) {
            Ok(outcome) => {
                if let Some(ioctl_err) = outcome.ioctl_error {
                    self.log.error(&format!(
                        "IOCTL failed reading PF table {table} ({ioctl_err}); \
                         pfctl served the call"
                    ));
                }
                Ok(outcome.value)
            }
            Err(e) => Err(e.to_string()),
        }
    }

    fn table_pop(&self, table: &str, entries: &[String]) {
        let (ips, skipped) = parse_entries(entries);
        for entry in skipped {
            // PFUI installs host addresses only, so a non-address entry was
            // put there by something else and is left alone
            self.log.error(&format!(
                "PF table {table} holds non-address entry '{entry}'; not touching it"
            ));
        }
        if ips.is_empty() {
            return;
        }
        match pf::table_pop(&self.pf_config(), table, &ips) {
            Ok(outcome) => {
                if let Some(ioctl_err) = outcome.ioctl_error {
                    self.log.error(&format!(
                        "IOCTL failed clearing PF table {table} ({ioctl_err}); \
                         pfctl served the call"
                    ));
                }
            }
            Err(e) => self.log.error(&format!(
                "Failed to clear {ips:?} from PF table {table}: {e}"
            )),
        }
    }

    fn table_push(&self, table: &str, entries: &[String]) {
        let (ips, _) = parse_entries(entries);
        if !ips.is_empty() {
            crate::receiver::Backends::table_push(self, table, &ips);
        }
    }
}

fn parse_entries(entries: &[String]) -> (Vec<IpAddr>, Vec<&String>) {
    let mut ips = Vec::new();
    let mut skipped = Vec::new();
    for entry in entries {
        match entry.parse() {
            Ok(ip) => ips.push(ip),
            Err(_) => skipped.push(entry),
        }
    }
    (ips, skipped)
}

/// Each address family's table and persist file.
pub fn persist_files(cfg: &Config) -> [(String, PathBuf); 2] {
    [
        (cfg.af4_table.clone(), cfg.af4_file.clone()),
        (cfg.af6_table.clone(), cfg.af6_file.clone()),
    ]
}
