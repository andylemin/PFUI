//! OpenBSD hardening. unveil(2) is unconditional. Everything here is a no-op
//! on other platforms.

use std::path::Path;

use crate::config::Config;
#[cfg(target_os = "openbsd")]
use crate::pf;

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
    unveil(config_path, "r")?;
    unveil(&cfg.devpf, "rw")?;
    for file in [&cfg.af4_file, &cfg.af6_file] {
        // Covers the persist file, its .lock sidecar and rewrite tempfiles
        let dir = file.parent().filter(|p| !p.as_os_str().is_empty());
        unveil(dir.unwrap_or_else(|| Path::new("/")), "rwc")?;
    }
    if let Some(sock) = &cfg.socket_unix {
        // The shutdown unlink needs create rights on the directory
        let dir = sock.parent().filter(|p| !p.as_os_str().is_empty());
        unveil(dir.unwrap_or_else(|| Path::new("/")), "rwc")?;
    }
    unveil(Path::new(pf::DEFAULT_PFCTL), "rx")?;
    unveil_lock()
}

#[cfg(not(target_os = "openbsd"))]
pub fn lockdown(_cfg: &Config, _config_path: &Path) -> Result<(), String> {
    Ok(())
}
