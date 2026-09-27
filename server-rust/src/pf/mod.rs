//! PF table interface. CTL selects the kernel ioctl on /dev/pf or the pfctl(8)
//! subprocess; there is no fallback between them. Addresses arrive validated
//! and canonicalised.

pub mod ioctl;
pub mod pfctl;
pub mod privsep;
pub mod structs;

use std::fmt;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

use ioctl::PfDev;

pub const DEFAULT_PFCTL: &str = "/sbin/pfctl";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Ctl {
    Ioctl,
    Pfctl,
}

impl Ctl {
    pub fn as_str(self) -> &'static str {
        match self {
            Ctl::Ioctl => "IOCTL",
            Ctl::Pfctl => "PFCTL",
        }
    }
}

/// Appended to every control-path error.
const REMEDY: &str = "fix that, or set CTL: PFCTL in /etc/pfui_firewall.yml";

#[derive(Debug)]
pub enum PfError {
    /// Table name cannot fit pfrt_name including its terminator
    TableName,
    /// /dev/pf could not be opened
    Dev { errno: String, raw: Option<i32> },
    /// `raw` selects the guidance in Display.
    Ioctl {
        cmd: u64,
        errno: String,
        raw: Option<i32>,
    },
    /// The table kept growing across bounded DIOCRGETADDRS retries
    Unstable,
    /// The pfctl subprocess failed or could not be executed
    Pfctl(String),
    /// The PF child is gone or answered out of shape
    Child(String),
    /// Built without the OpenBSD ioctl (any other platform)
    Unsupported,
}

/// Operator guidance per errno.
fn explain(raw: Option<i32>) -> Option<&'static str> {
    match raw {
        Some(libc::EACCES) | Some(libc::EPERM) => Some(
            "/dev/pf is not writable by this user: it must be group _pfui_firewall, \
             mode 660, which rc.d/pfui_firewall applies on every start",
        ),
        Some(libc::ENOENT) => Some("/dev/pf does not exist"),
        Some(libc::ESRCH) => Some(
            "the table is not in the loaded ruleset: declare it in pf.conf as \
             'table <name> persist file \"...\"' and reload",
        ),
        Some(libc::ENOTTY) | Some(libc::EINVAL) => {
            Some("not a pf device, or a struct layout the kernel does not recognise")
        }
        _ => None,
    }
}

impl fmt::Display for PfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PfError::TableName => write!(f, "table name too long for pfr_table"),
            PfError::Dev { errno, raw } => {
                write!(f, "cannot open pf device: {errno}")?;
                if let Some(why) = explain(*raw) {
                    write!(f, " ({why}; {REMEDY})")?;
                }
                Ok(())
            }
            PfError::Ioctl { cmd, errno, raw } => {
                write!(f, "pf ioctl {cmd:#x} failed: {errno}")?;
                if let Some(why) = explain(*raw) {
                    write!(f, " ({why}; {REMEDY})")?;
                }
                Ok(())
            }
            PfError::Unstable => write!(f, "table kept growing across GETADDRS retries"),
            PfError::Pfctl(e) => write!(f, "{e}"),
            PfError::Child(e) => write!(f, "{e}"),
            PfError::Unsupported => write!(f, "pf ioctl unavailable on this platform"),
        }
    }
}

/// One device shared by every caller: under IOCTL it is the proxy to the PF
/// child, whose socket carries one call at a time.
pub type SharedDev = Mutex<Box<dyn PfDev + Send>>;

pub struct PfConfig<'a> {
    pub ctl: Ctl,
    pub dev: &'a SharedDev,
    pub pfctl: &'a Path,
}

fn render(ips: &[IpAddr]) -> Vec<String> {
    ips.iter().map(IpAddr::to_string).collect()
}

fn dispatch<T>(
    cfg: &PfConfig,
    via_ioctl: impl FnOnce() -> Result<T, PfError>,
    via_pfctl: impl FnOnce() -> Result<T, PfError>,
) -> Result<T, PfError> {
    match cfg.ctl {
        Ctl::Ioctl => via_ioctl(),
        Ctl::Pfctl => via_pfctl(),
    }
}

/// Install IPs into the table. Runs before the client is acknowledged.
pub fn table_push(cfg: &PfConfig, table: &str, ips: &[IpAddr]) -> Result<usize, PfError> {
    dispatch(
        cfg,
        || ioctl::table_add(&mut **cfg.dev.lock().unwrap(), table, ips),
        || pfctl::add(cfg.pfctl, table, &render(ips)),
    )
}

/// Remove IPs from the table.
pub fn table_pop(cfg: &PfConfig, table: &str, ips: &[IpAddr]) -> Result<usize, PfError> {
    dispatch(
        cfg,
        || ioctl::table_del(&mut **cfg.dev.lock().unwrap(), table, ips),
        || pfctl::del(cfg.pfctl, table, &render(ips)),
    )
}

/// Read the table's current contents, canonicalised.
pub fn table_show(cfg: &PfConfig, table: &str) -> Result<Vec<String>, PfError> {
    dispatch(
        cfg,
        || {
            ioctl::table_get(&mut **cfg.dev.lock().unwrap(), table)
                .map(|ips| ips.iter().map(IpAddr::to_string).collect())
        },
        || pfctl::show(cfg.pfctl, table),
    )
}

/// Read every table through the configured control path. Runs before serving,
/// after the sandbox, so a daemon that cannot reach PF never acknowledges.
pub fn probe(cfg: &PfConfig, tables: &[&str]) -> Result<(), String> {
    for table in tables {
        table_show(cfg, table).map_err(|e| {
            format!(
                "PF table {table} is unreachable via CTL: {}: {e}",
                cfg.ctl.as_str()
            )
        })?;
    }
    Ok(())
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

    fn direct() -> SharedDev {
        Mutex::new(Box::new(ioctl::DevPf(PathBuf::from("/dev/pf"))))
    }

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
        let dev = direct();
        let cfg = PfConfig {
            ctl: Ctl::Pfctl,
            dev: &dev,
            pfctl: &pfctl,
        };
        assert_eq!(
            table_push(&cfg, "t", &["8.8.8.8".parse().unwrap()]).unwrap(),
            1
        );
    }

    #[test]
    fn ioctl_mode_never_reaches_for_pfctl() {
        let _serial = crate::pf::STUB_EXEC.lock().unwrap();
        // Table "t" is in no ruleset, so the ioctl fails on every platform:
        // ESRCH on OpenBSD, the stub's Unsupported elsewhere. A pfctl that ran
        // means a fallback
        let dir = tempfile::tempdir().unwrap();
        let marker = dir.path().join("pfctl-ran");
        let pfctl = stub(
            dir.path(),
            &format!("touch {}; printf '8.8.8.8\\n'", marker.display()),
        );
        let dev = direct();
        let cfg = PfConfig {
            ctl: Ctl::Ioctl,
            dev: &dev,
            pfctl: &pfctl,
        };
        let shown = table_show(&cfg, "t");
        assert!(
            !matches!(shown, Ok(_) | Err(PfError::Pfctl(_))),
            "{shown:?}"
        );
        let pushed = table_push(&cfg, "t", &["8.8.8.8".parse().unwrap()]);
        assert!(
            !matches!(pushed, Ok(_) | Err(PfError::Pfctl(_))),
            "{pushed:?}"
        );
        assert!(!marker.exists(), "pfctl ran under CTL: IOCTL");
    }

    #[test]
    fn the_probe_names_the_table_that_failed() {
        let _serial = crate::pf::STUB_EXEC.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let script = concat!(
            "case \"$*\" in *absent*) echo 'Table does not exist.' >&2; exit 1;; esac\n",
            "exit 0"
        );
        let pfctl = stub(dir.path(), script);
        let dev = direct();
        let cfg = PfConfig {
            ctl: Ctl::Pfctl,
            dev: &dev,
            pfctl: &pfctl,
        };
        assert!(probe(&cfg, &["present"]).is_ok());
        let err = probe(&cfg, &["present", "absent"]).unwrap_err();
        assert!(err.contains("absent"), "{err}");
        assert!(err.contains("PFCTL"), "{err}");
    }

    #[test]
    fn a_control_path_failure_says_what_to_fix() {
        let esrch = PfError::Ioctl {
            cmd: 0xc4504443,
            errno: "No such process".into(),
            raw: Some(libc::ESRCH),
        }
        .to_string();
        assert!(esrch.contains("pf.conf"), "{esrch}");
        assert!(esrch.contains("CTL: PFCTL"), "{esrch}");

        let eacces = PfError::Dev {
            errno: "Permission denied".into(),
            raw: Some(libc::EACCES),
        }
        .to_string();
        assert!(eacces.contains("mode 660"), "{eacces}");
        assert!(eacces.contains("CTL: PFCTL"), "{eacces}");

        let enoent = PfError::Dev {
            errno: "No such file or directory".into(),
            raw: Some(libc::ENOENT),
        }
        .to_string();
        assert!(enoent.contains("/dev/pf does not exist"), "{enoent}");

        // No guidance for an unrecognised errno
        let other = PfError::Ioctl {
            cmd: 0xc4504443,
            errno: "Input/output error".into(),
            raw: Some(libc::EIO),
        }
        .to_string();
        assert!(other.ends_with("Input/output error"), "{other}");
    }
}
