//! OpenBSD hardening: unveil(2), then pledge(2). The plan and the promise set
//! are data, tested on every platform; only the two system calls are OpenBSD
//! code.

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::pf::{self, Ctl};

/// Opened for the pfctl child's stdin by the spawn itself.
pub const DEV_NULL: &str = "/dev/null";

/// Every path the running daemon may see, with its rights. Data rather than
/// calls, so the boundary is testable off OpenBSD.
pub fn unveil_plan(cfg: &Config, config_path: &Path) -> Vec<(PathBuf, &'static str)> {
    let mut plan: Vec<(PathBuf, &'static str)> = vec![(config_path.to_path_buf(), "r")];

    // The parent, not the file: this covers the persist file, its .lock sidecar
    // and the tempfiles a rewrite renames over
    let parent_or_root = |p: &Path| -> PathBuf {
        p.parent()
            .filter(|d| !d.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("/"))
            .to_path_buf()
    };
    for file in [&cfg.af4_file, &cfg.af6_file] {
        plan.push((parent_or_root(file), "rwc"));
    }
    if let Some(sock) = &cfg.socket_unix {
        // The shutdown unlink needs create rights on the directory
        plan.push((parent_or_root(sock), "rwc"));
    }

    // The pfctl child inherits this view: it opens /dev/pf itself, and the
    // spawn opens /dev/null for its stdin. /sbin/pfctl is statically linked.
    // Under IOCTL the PF child opened /dev/pf before the lockdown.
    if cfg.ctl == Ctl::Pfctl {
        plan.push((cfg.devpf.clone(), "rw"));
        plan.push((PathBuf::from(pf::DEFAULT_PFCTL), "rx"));
        plan.push((PathBuf::from(DEV_NULL), "rw"));
    }
    plan
}

/// The pledge(2) promise set, or None when PLEDGE is off.
///
/// inet is always needed: Redis connects lazily, after the pledge. dns never
/// is: REDIS_HOST is resolved before lockdown. fattr covers the persist
/// tempfile chmod, flock its lock. pf is never asked for: it does not permit
/// the table-address ioctls, which is why the PF child exists.
pub fn pledge_promises(cfg: &Config) -> Option<String> {
    if !cfg.pledge {
        return None;
    }
    let mut promises = vec!["stdio", "rpath", "wpath", "cpath", "flock", "fattr", "inet"];
    if cfg.socket_unix.is_some() {
        promises.push("unix");
    }
    if cfg.ctl == Ctl::Pfctl {
        promises.extend(["proc", "exec"]);
    }
    Some(promises.join(" "))
}

/// The PF child's lockdown: no filesystem at all. It holds /dev/pf already,
/// and cannot pledge, since every promise set forbids its ioctls.
#[cfg(target_os = "openbsd")]
pub fn child_lockdown() -> Result<(), String> {
    unveil(Path::new("/var/empty"), "")?;
    unveil_lock()
}

#[cfg(not(target_os = "openbsd"))]
pub fn child_lockdown() -> Result<(), String> {
    Ok(())
}

/// What lockdown applied, for the startup log.
pub struct Sandbox {
    pub unveiled: usize,
    pub promises: Option<String>,
}

#[cfg(target_os = "openbsd")]
fn unveil(path: &Path, permissions: &str) -> Result<(), String> {
    use std::os::unix::ffi::OsStrExt;
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| format!("{} contains NUL", path.display()))?;
    let c_perm = std::ffi::CString::new(permissions).expect("static permissions");
    if unsafe { libc::unveil(c_path.as_ptr(), c_perm.as_ptr()) } == -1 {
        return Err(format!(
            "unveil({}, {permissions}) failed: {}",
            path.display(),
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

#[cfg(target_os = "openbsd")]
fn unveil_lock() -> Result<(), String> {
    if unsafe { libc::unveil(std::ptr::null(), std::ptr::null()) } == -1 {
        return Err(format!(
            "unveil lock failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// execpromises is NULL: a pfctl child runs unpledged.
#[cfg(target_os = "openbsd")]
fn pledge(promises: &str) -> Result<(), String> {
    let c_promises = std::ffi::CString::new(promises).expect("static promises");
    if unsafe { libc::pledge(c_promises.as_ptr(), std::ptr::null()) } == -1 {
        return Err(format!(
            "pledge({promises}) failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Unveil the plan, lock it, pledge. After the binds (getgrnam, the socket
/// node) and REDIS_HOST resolution; before the PF probe.
#[cfg(target_os = "openbsd")]
pub fn lockdown(cfg: &Config, config_path: &Path) -> Result<Sandbox, String> {
    let plan = unveil_plan(cfg, config_path);
    for (path, permissions) in &plan {
        unveil(path, permissions)?;
    }
    unveil_lock()?;
    let promises = pledge_promises(cfg);
    if let Some(p) = &promises {
        pledge(p)?;
    }
    Ok(Sandbox {
        unveiled: plan.len(),
        promises,
    })
}

/// Nothing is applied off OpenBSD.
#[cfg(not(target_os = "openbsd"))]
pub fn lockdown(_cfg: &Config, _config_path: &Path) -> Result<Sandbox, String> {
    Ok(Sandbox {
        unveiled: 0,
        promises: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_config_str;

    fn config(extra: &str) -> Config {
        load_config_str(&format!(
            "
AF4_TABLE: t4
AF4_FILE: /var/db/pfui/ipv4_domains
AF6_TABLE: t6
AF6_FILE: /var/db/pfui/ipv6_domains
SOCKET_LISTEN: 10.10.1.254
{extra}"
        ))
        .unwrap()
    }

    fn plan_for(extra: &str) -> Vec<(PathBuf, &'static str)> {
        unveil_plan(&config(extra), Path::new("/etc/pfui_firewall.yml"))
    }

    fn rights(plan: &[(PathBuf, &'static str)], path: &str) -> Option<&'static str> {
        plan.iter()
            .find(|(p, _)| p == Path::new(path))
            .map(|(_, r)| *r)
    }

    #[test]
    fn pfctl_mode_can_actually_exec_pfctl() {
        let plan = plan_for("CTL: PFCTL\n");
        assert_eq!(rights(&plan, pf::DEFAULT_PFCTL), Some("rx"));
        // The spawn opens /dev/null for the child's stdin before exec
        assert_eq!(
            rights(&plan, DEV_NULL),
            Some("rw"),
            "stdin cannot be opened"
        );
        // The pfctl child opens /dev/pf
        assert_eq!(rights(&plan, "/dev/pf"), Some("rw"));
    }

    #[test]
    fn ioctl_mode_sees_neither_pfctl_nor_the_device() {
        // Nothing to exec, and the PF child holds /dev/pf
        let plan = plan_for("CTL: IOCTL\n");
        assert_eq!(rights(&plan, pf::DEFAULT_PFCTL), None);
        assert_eq!(rights(&plan, DEV_NULL), None);
        assert_eq!(rights(&plan, "/dev/pf"), None);
    }

    #[test]
    fn the_plan_covers_what_serving_needs() {
        let plan = plan_for("SOCKET_UNIX: /var/run/pfui/pfui_firewall.sock\n");
        assert_eq!(rights(&plan, "/etc/pfui_firewall.yml"), Some("r"));
        // Directories, so the .lock sidecar and rewrite tempfiles are covered
        assert_eq!(rights(&plan, "/var/db/pfui"), Some("rwc"));
        assert_eq!(rights(&plan, "/var/run/pfui"), Some("rwc"));
    }

    #[test]
    fn no_socket_directory_is_granted_when_there_is_no_socket() {
        assert_eq!(rights(&plan_for(""), "/var/run/pfui"), None);
    }

    #[test]
    fn promises_follow_ctl() {
        let ioctl = pledge_promises(&config("CTL: IOCTL\n")).unwrap();
        let pfctl = pledge_promises(&config("CTL: PFCTL\n")).unwrap();
        for base in ["stdio", "rpath", "wpath", "cpath", "flock", "fattr", "inet"] {
            assert!(ioctl.split(' ').any(|p| p == base), "IOCTL lacks {base}");
            assert!(pfctl.split(' ').any(|p| p == base), "PFCTL lacks {base}");
        }
        // pf is never pledged: it does not cover the address ioctls, and
        // IOCTL never forks once the PF child exists
        assert!(!ioctl.split(' ').any(|p| p == "pf"), "{ioctl}");
        assert!(
            !ioctl.contains("proc") && !ioctl.contains("exec"),
            "{ioctl}"
        );
        // PFCTL forks and execs pfctl
        assert!(pfctl.split(' ').any(|p| p == "proc"));
        assert!(pfctl.split(' ').any(|p| p == "exec"));
        assert!(!pfctl.split(' ').any(|p| p == "pf"), "{pfctl}");
        // dns is never pledged: REDIS_HOST is resolved before lockdown
        assert!(!ioctl.contains("dns") && !pfctl.contains("dns"));
    }

    #[test]
    fn unix_is_pledged_only_when_a_local_socket_is_bound() {
        let without = pledge_promises(&config("")).unwrap();
        let with = pledge_promises(&config("SOCKET_UNIX: /var/run/pfui/s.sock\n")).unwrap();
        assert!(!without.split(' ').any(|p| p == "unix"), "{without}");
        assert!(with.split(' ').any(|p| p == "unix"), "{with}");
    }

    #[test]
    fn the_emergency_switch_disables_the_pledge() {
        assert!(pledge_promises(&config("PLEDGE: False\n")).is_none());
    }
}
