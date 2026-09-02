//! PF table interface, dispatched on CTL: IOCTL tries the kernel interface and
//! falls back to pfctl on error, PFCTL goes straight to the subprocess.
//!
//! Addresses arrive as IpAddr, already validated and canonicalised, so an
//! unparseable string cannot reach the ioctl.

pub mod ioctl;
pub mod pfctl;
pub mod structs;

use std::fmt;
use std::net::IpAddr;
use std::path::Path;

pub const DEFAULT_PFCTL: &str = "/sbin/pfctl";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ctl {
    Ioctl,
    Pfctl,
}

#[derive(Debug)]
pub enum PfError {
    /// Table name cannot fit pfrt_name including its terminator
    TableName,
    /// /dev/pf could not be opened
    Dev(String),
    /// `raw` is kept because ESRCH means the table is absent from the active
    /// ruleset, a configuration error worth naming as one.
    Ioctl {
        cmd: u64,
        errno: String,
        raw: Option<i32>,
    },
    /// The table kept growing across bounded DIOCRGETADDRS retries
    Unstable,
    /// The pfctl subprocess failed or could not be executed
    Pfctl(String),
    /// Built without the OpenBSD ioctl (any other platform)
    Unsupported,
}

impl fmt::Display for PfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PfError::TableName => write!(f, "table name too long for pfr_table"),
            PfError::Dev(e) => write!(f, "cannot open pf device: {e}"),
            PfError::Ioctl { cmd, errno, raw } => {
                write!(f, "pf ioctl {cmd:#x} failed: {errno}")?;
                if *raw == Some(libc::ESRCH) {
                    write!(
                        f,
                        " (the table is not in the active ruleset; declare it in \
                         pf.conf and reload, or use CTL: PFCTL)"
                    )?;
                }
                Ok(())
            }
            PfError::Unstable => write!(f, "table kept growing across GETADDRS retries"),
            PfError::Pfctl(e) => write!(f, "{e}"),
            PfError::Unsupported => write!(f, "pf ioctl unavailable on this platform"),
        }
    }
}

pub struct PfConfig<'a> {
    pub ctl: Ctl,
    pub devpf: &'a Path,
    pub pfctl: &'a Path,
}

/// The count, plus the ioctl error when the pfctl fallback served the call.
pub struct Outcome<T> {
    pub value: T,
    pub ioctl_error: Option<String>,
}

fn render(ips: &[IpAddr]) -> Vec<String> {
    ips.iter().map(IpAddr::to_string).collect()
}

fn dispatch<T>(
    cfg: &PfConfig,
    via_ioctl: impl FnOnce() -> Result<T, PfError>,
    via_pfctl: impl FnOnce() -> Result<T, PfError>,
) -> Result<Outcome<T>, PfError> {
    match cfg.ctl {
        Ctl::Pfctl => Ok(Outcome {
            value: via_pfctl()?,
            ioctl_error: None,
        }),
        Ctl::Ioctl => match via_ioctl() {
            Ok(value) => Ok(Outcome {
                value,
                ioctl_error: None,
            }),
            Err(ioctl_err) => Ok(Outcome {
                value: via_pfctl()?,
                ioctl_error: Some(ioctl_err.to_string()),
            }),
        },
    }
}

/// Install IPs into the table. Runs before the client is acknowledged.
pub fn table_push(cfg: &PfConfig, table: &str, ips: &[IpAddr]) -> Result<Outcome<usize>, PfError> {
    dispatch(
        cfg,
        || ioctl::table_add(&mut ioctl::DevPf(cfg.devpf), table, ips),
        || pfctl::add(cfg.pfctl, table, &render(ips)),
    )
}

/// Remove IPs from the table.
pub fn table_pop(cfg: &PfConfig, table: &str, ips: &[IpAddr]) -> Result<Outcome<usize>, PfError> {
    dispatch(
        cfg,
        || ioctl::table_del(&mut ioctl::DevPf(cfg.devpf), table, ips),
        || pfctl::del(cfg.pfctl, table, &render(ips)),
    )
}

/// Read the table's current contents, canonicalised.
pub fn table_show(cfg: &PfConfig, table: &str) -> Result<Outcome<Vec<String>>, PfError> {
    dispatch(
        cfg,
        || {
            ioctl::table_get(&mut ioctl::DevPf(cfg.devpf), table)
                .map(|ips| ips.iter().map(IpAddr::to_string).collect())
        },
        || pfctl::show(cfg.pfctl, table),
    )
}

/// Serialises the stub-script tests: a concurrent fork inherits the stub's
/// open write fd until it execs, and executing it in that window is ETXTBSY.
#[cfg(test)]
pub(crate) static STUB_EXEC: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;

    fn stub(dir: &Path, script: &str) -> PathBuf {
        let path = dir.join("pfctl");
        let mut f = std::fs::File::create(&path).unwrap();
        writeln!(f, "#!/bin/sh\n{script}").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
        path
    }

    #[test]
    fn pfctl_mode_uses_the_subprocess_directly() {
        let _serial = crate::pf::STUB_EXEC.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pfctl = stub(dir.path(), "exit 0");
        let cfg = PfConfig {
            ctl: Ctl::Pfctl,
            devpf: Path::new("/dev/pf"),
            pfctl: &pfctl,
        };
        let out = table_push(&cfg, "t", &["8.8.8.8".parse().unwrap()]).unwrap();
        assert_eq!(out.value, 1);
        assert!(out.ioctl_error.is_none());
    }

    #[test]
    fn ioctl_mode_falls_back_to_pfctl_and_reports_the_ioctl_error() {
        let _serial = crate::pf::STUB_EXEC.lock().unwrap();
        // Off OpenBSD the ioctl path is the Unsupported stub, which IS the
        // fallback scenario: the pfctl stub serves the call
        let dir = tempfile::tempdir().unwrap();
        let pfctl = stub(dir.path(), "printf '8.8.8.8\\n'");
        let cfg = PfConfig {
            ctl: Ctl::Ioctl,
            devpf: Path::new("/dev/pf"),
            pfctl: &pfctl,
        };
        let out = table_show(&cfg, "t").unwrap();
        assert_eq!(out.value, ["8.8.8.8"]);
        assert!(out.ioctl_error.is_some());
    }

    #[test]
    fn both_paths_failing_is_an_error() {
        let _serial = crate::pf::STUB_EXEC.lock().unwrap();
        let cfg = PfConfig {
            ctl: Ctl::Ioctl,
            devpf: Path::new("/dev/pf"),
            pfctl: Path::new("/nonexistent/pfctl"),
        };
        assert!(table_pop(&cfg, "t", &["8.8.8.8".parse().unwrap()]).is_err());
    }
}
