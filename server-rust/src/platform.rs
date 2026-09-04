//! OpenBSD hardening. unveil(2) is unconditional. Everything here is a no-op
//! on other platforms.

use std::path::{Path, PathBuf};

use crate::config::Config;
use crate::pf;

/// The runtime linker, and where it finds the shared libraries pfctl needs.
pub const LD_SO: &str = "/usr/libexec/ld.so";
pub const LIB_DIR: &str = "/usr/lib";

/// Every path the running daemon may see, and with what rights.
///
/// Built as a list rather than applied inline so it can be tested off OpenBSD,
/// where unveil(2) does not exist. The list is the security boundary and it was
/// incomplete without anywhere to notice; a missing entry is a runtime failure
/// on one code path, which is the hardest kind to find by hand.
pub fn unveil_plan(cfg: &Config, config_path: &Path) -> Vec<(PathBuf, &'static str)> {
    let mut plan: Vec<(PathBuf, &'static str)> =
        vec![(config_path.to_path_buf(), "r"), (cfg.devpf.clone(), "rw")];

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

    // pfctl, plus what exec'ing it requires. It is dynamically linked, so the
    // loader and the libraries the loader maps have to be visible too; granting
    // only the binary left the fallback failing at exec. CTL: IOCTL falls back
    // to pfctl on any ioctl error, so this carries the default configuration
    // exactly when the ioctl is what went wrong.
    plan.push((PathBuf::from(pf::DEFAULT_PFCTL), "rx"));
    plan.push((PathBuf::from(LD_SO), "rx"));
    plan.push((PathBuf::from(LIB_DIR), "r"));
    plan
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

/// Restrict the filesystem to what the running daemon needs. Called after the
/// binds, which need getgrnam and the socket node, and after REDIS_HOST is
/// resolved, so no resolver files have to be unveiled. Children inherit the
/// view, which is what lets the pfctl fallback reach /dev/pf.
#[cfg(target_os = "openbsd")]
pub fn lockdown(cfg: &Config, config_path: &Path) -> Result<(), String> {
    for (path, permissions) in unveil_plan(cfg, config_path) {
        unveil(&path, permissions)?;
    }
    unveil_lock()
}

#[cfg(not(target_os = "openbsd"))]
pub fn lockdown(_cfg: &Config, _config_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::load_config_str;

    fn plan_for(extra: &str) -> Vec<(PathBuf, &'static str)> {
        let cfg = load_config_str(&format!(
            "
AF4_TABLE: t4
AF4_FILE: /var/db/pfui/ipv4_domains
AF6_TABLE: t6
AF6_FILE: /var/db/pfui/ipv6_domains
SOCKET_LISTEN: 10.10.1.254
{extra}"
        ))
        .unwrap();
        unveil_plan(&cfg, Path::new("/etc/pfui_firewall.yml"))
    }

    fn rights(plan: &[(PathBuf, &'static str)], path: &str) -> Option<&'static str> {
        plan.iter()
            .find(|(p, _)| p == Path::new(path))
            .map(|(_, r)| *r)
    }

    #[test]
    fn the_pfctl_fallback_can_actually_exec() {
        // Granting the binary alone was not enough: pfctl is dynamically linked,
        // so exec failed at the loader, and CTL: IOCTL falls back to pfctl on
        // any ioctl error
        let plan = plan_for("");
        assert_eq!(rights(&plan, pf::DEFAULT_PFCTL), Some("rx"));
        assert_eq!(
            rights(&plan, LD_SO),
            Some("rx"),
            "the loader is not visible"
        );
        assert_eq!(
            rights(&plan, LIB_DIR),
            Some("r"),
            "the shared libraries are not visible"
        );
    }

    #[test]
    fn the_plan_covers_what_serving_needs() {
        let plan = plan_for("SOCKET_UNIX: /var/run/pfui/pfui_firewall.sock\n");
        assert_eq!(rights(&plan, "/etc/pfui_firewall.yml"), Some("r"));
        assert_eq!(rights(&plan, "/dev/pf"), Some("rw"));
        // Directories, so the .lock sidecar and rewrite tempfiles are covered
        assert_eq!(rights(&plan, "/var/db/pfui"), Some("rwc"));
        assert_eq!(rights(&plan, "/var/run/pfui"), Some("rwc"));
    }

    #[test]
    fn no_socket_directory_is_granted_when_there_is_no_socket() {
        let plan = plan_for("");
        assert_eq!(rights(&plan, "/var/run/pfui"), None);
    }
}
