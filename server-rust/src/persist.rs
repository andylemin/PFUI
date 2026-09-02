//! PF persist files.
//!
//! file_push is the hot path: called per DNS answer with every receiver thread
//! serialised on one lock, so it appends without reading the file. Duplicate
//! lines are harmless, since PF loads a table as a set, and file_pop's
//! set-based rewrite collapses them once per SCAN_PERIOD.

use std::collections::BTreeSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Exclusive cross-process lock via a sidecar .lock file, which is never
/// truncated or renamed, so the lock cannot be lost with the file it guards.
struct FileLock {
    _file: File,
}

fn lock_path(file: &Path) -> PathBuf {
    let mut p = file.as_os_str().to_owned();
    p.push(".lock");
    PathBuf::from(p)
}

fn lock(file: &Path) -> io::Result<FileLock> {
    let handle = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o640)
        .open(lock_path(file))?;
    loop {
        // Blocking; the kernel queues waiters
        if unsafe { libc::flock(handle.as_raw_fd(), libc::LOCK_EX) } == 0 {
            return Ok(FileLock { _file: handle });
        }
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EINTR) {
            return Err(err);
        }
    }
}

/// Append IPs to the persist file, one per line, without reading it.
pub fn file_push(file: &Path, ips: &[String]) -> io::Result<()> {
    let _lock = lock(file)?;
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o640)
        .open(file)?;
    let mut lines = String::new();
    for ip in ips {
        lines.push_str(ip);
        lines.push('\n');
    }
    f.write_all(lines.as_bytes())
}

/// Remove IPs from the persist file, deduplicating what remains.
///
/// Survivors are rewritten sorted, so an unchanged whitelist produces an
/// unchanged file; PF ignores line order. The tempfile takes the original's
/// mode and is renamed over it, atomic within one filesystem.
pub fn file_pop(file: &Path, ips: &[String]) -> io::Result<()> {
    let remove: BTreeSet<&str> = ips.iter().map(String::as_str).collect();
    let _lock = lock(file)?;

    let mut handle = File::open(file)?;
    // Read from the handle being replaced, so a tightened mode carries over
    let mode = handle.metadata()?.permissions().mode() & 0o7777;
    let mut content = String::new();
    handle.read_to_string(&mut content)?;

    let keep: BTreeSet<&str> = content
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !remove.contains(line))
        .collect();

    let dir = file.parent().filter(|p| !p.as_os_str().is_empty());
    let mut tmp = tempfile::Builder::new()
        .prefix(".pfui_")
        .suffix(".tmp")
        .tempfile_in(dir.unwrap_or_else(|| Path::new(".")))?;
    let mut lines = String::new();
    for ip in &keep {
        lines.push_str(ip);
        lines.push('\n');
    }
    tmp.write_all(lines.as_bytes())?;
    tmp.as_file()
        .set_permissions(std::fs::Permissions::from_mode(mode))?;
    tmp.persist(file).map_err(|e| e.error)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::thread;

    fn read_lines(file: &Path) -> Vec<String> {
        std::fs::read_to_string(file)
            .unwrap()
            .lines()
            .map(str::to_string)
            .collect()
    }

    fn persist_file(dir: &Path) -> PathBuf {
        let file = dir.join("pfui_ipv4_domains");
        std::fs::write(&file, "8.8.8.8\n1.1.1.1\n8.8.8.8\n").unwrap();
        file
    }

    #[test]
    fn push_appends() {
        let dir = tempfile::tempdir().unwrap();
        let file = persist_file(dir.path());
        file_push(&file, &["9.9.9.9".into()]).unwrap();
        assert_eq!(
            read_lines(&file),
            ["8.8.8.8", "1.1.1.1", "8.8.8.8", "9.9.9.9"]
        );
    }

    #[test]
    fn push_creates_a_missing_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("fresh");
        file_push(&file, &["9.9.9.9".into()]).unwrap();
        assert_eq!(read_lines(&file), ["9.9.9.9"]);
    }

    #[test]
    fn pop_removes_and_dedupes_remaining_entries() {
        let dir = tempfile::tempdir().unwrap();
        let file = persist_file(dir.path());
        file_pop(&file, &["1.1.1.1".into()]).unwrap();
        // The duplicate 8.8.8.8 lines collapse in the set-based rewrite
        assert_eq!(read_lines(&file), ["8.8.8.8"]);
    }

    #[test]
    fn pop_preserves_file_mode() {
        for mode in [0o600u32, 0o640, 0o644] {
            let dir = tempfile::tempdir().unwrap();
            let file = persist_file(dir.path());
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(mode)).unwrap();
            file_pop(&file, &["1.1.1.1".into()]).unwrap();
            let got = std::fs::metadata(&file).unwrap().permissions().mode() & 0o7777;
            assert_eq!(got, mode, "mode {mode:o}");
        }
    }

    #[test]
    fn pop_leaves_no_temp_files() {
        let dir = tempfile::tempdir().unwrap();
        let file = persist_file(dir.path());
        file_pop(&file, &["1.1.1.1".into()]).unwrap();
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".pfui_"))
            .collect();
        assert!(leftovers.is_empty(), "left {leftovers:?}");
    }

    #[test]
    fn unchanged_whitelist_is_an_unchanged_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("stable");
        std::fs::write(&file, "1.1.1.1\n8.8.8.8\n").unwrap();
        file_pop(&file, &["9.9.9.9".into()]).unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            "1.1.1.1\n8.8.8.8\n"
        );
    }

    #[test]
    fn concurrent_push_loses_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let file = Arc::new(dir.path().join("concurrent"));
        std::fs::write(&*file, "").unwrap();
        let mut handles = Vec::new();
        for t in 0..8 {
            let file = Arc::clone(&file);
            handles.push(thread::spawn(move || {
                for i in 0..25 {
                    file_push(&file, &[format!("10.{t}.0.{i}")]).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(read_lines(&file).len(), 8 * 25);
    }

    #[test]
    fn concurrent_push_and_pop_keeps_file_parseable() {
        let dir = tempfile::tempdir().unwrap();
        let file = Arc::new(dir.path().join("racing"));
        std::fs::write(&*file, "").unwrap();
        let pusher = {
            let file = Arc::clone(&file);
            thread::spawn(move || {
                for i in 0..50 {
                    file_push(&file, &[format!("10.0.0.{i}")]).unwrap();
                }
            })
        };
        let popper = {
            let file = Arc::clone(&file);
            thread::spawn(move || {
                for i in 0..50 {
                    file_pop(&file, &[format!("10.0.0.{i}")]).unwrap();
                }
            })
        };
        pusher.join().unwrap();
        popper.join().unwrap();
        for line in read_lines(&file) {
            assert!(
                line.parse::<std::net::IpAddr>().is_ok(),
                "unparseable line {line:?}"
            );
        }
    }

    #[test]
    fn push_failure_is_reported() {
        let missing_dir = Path::new("/nonexistent/pfui/file");
        assert!(file_push(missing_dir, &["8.8.8.8".into()]).is_err());
    }
}
