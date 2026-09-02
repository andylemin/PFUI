//! pfctl(8) subprocess path: the whole story under CTL: PFCTL, and the error
//! fallback under CTL: IOCTL. The binary is passed in by absolute path so
//! tests can point at a stub.

use std::path::Path;
use std::process::Command;

use super::PfError;

fn run(pfctl: &Path, table: &str, verb: &str, ips: &[String]) -> Result<Vec<u8>, PfError> {
    let output = Command::new(pfctl)
        .arg("-t")
        .arg(table)
        .arg("-T")
        .arg(verb)
        .args(ips)
        .output()
        .map_err(|e| PfError::Pfctl(format!("{}: {e}", pfctl.display())))?;
    if !output.status.success() {
        // A failing pfctl produces no output, indistinguishable from an
        // empty table, so the sync diff would re-add every live IP and never
        // expire anything
        return Err(PfError::Pfctl(format!(
            "pfctl -t {table} -T {verb} exited {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

pub fn add(pfctl: &Path, table: &str, ips: &[String]) -> Result<usize, PfError> {
    run(pfctl, table, "add", ips)?;
    Ok(ips.len())
}

pub fn del(pfctl: &Path, table: &str, ips: &[String]) -> Result<usize, PfError> {
    run(pfctl, table, "delete", ips)?;
    Ok(ips.len())
}

pub fn show(pfctl: &Path, table: &str) -> Result<Vec<String>, PfError> {
    let stdout = run(pfctl, table, "show", &[])?;
    Ok(String::from_utf8_lossy(&stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_string)
        .collect())
}

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
    fn add_reports_the_count_on_success() {
        let _serial = crate::pf::STUB_EXEC.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pfctl = stub(dir.path(), "exit 0");
        assert_eq!(
            add(&pfctl, "t", &["8.8.8.8".into(), "1.1.1.1".into()]).unwrap(),
            2
        );
    }

    #[test]
    fn a_failing_pfctl_does_not_look_like_an_empty_table() {
        let _serial = crate::pf::STUB_EXEC.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pfctl = stub(dir.path(), "echo 'pf table does not exist' >&2; exit 1");
        let err = show(&pfctl, "t").unwrap_err();
        assert!(err.to_string().contains("does not exist"), "{err}");
    }

    #[test]
    fn a_genuinely_empty_table_is_an_empty_list() {
        let _serial = crate::pf::STUB_EXEC.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pfctl = stub(dir.path(), "exit 0");
        assert!(show(&pfctl, "t").unwrap().is_empty());
    }

    #[test]
    fn show_trims_and_skips_blank_lines() {
        let _serial = crate::pf::STUB_EXEC.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let pfctl = stub(dir.path(), "printf '   8.8.8.8\\n\\n   2001:db8::1\\n'");
        assert_eq!(show(&pfctl, "t").unwrap(), ["8.8.8.8", "2001:db8::1"]);
    }

    #[test]
    fn a_missing_binary_is_a_named_error() {
        let _serial = crate::pf::STUB_EXEC.lock().unwrap();
        let missing = Path::new("/nonexistent/pfctl");
        assert!(add(missing, "t", &["8.8.8.8".into()]).is_err());
    }
}
