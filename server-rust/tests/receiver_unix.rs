//! Unix-socket hardening — the test_unix_socket.py port. The bind path is
//! the whole access control on this transport, so every fail-closed step is
//! exercised: parent checks, stale reclaim, live-socket protection, umask
//! window, group grant, and message flow over the local socket.

use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use pfui_firewall::config::{load_config_str, Config, LogLevel};
use pfui_firewall::listener::{self, StreamListener, WorkerPool, UNIX_SOCKET_MODE};
use pfui_firewall::logger::Logger;
use pfui_firewall::receiver::{Backends, Ctx};
use pfui_firewall::store::Kind;

fn log() -> Logger {
    Logger::stderr(LogLevel::Error, false)
}

/// The caller's own primary group: a grant target that exists and that an
/// unprivileged test may chown to.
fn own_group() -> String {
    let gid = unsafe { libc::getgid() };
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe {
        libc::getgrgid_r(
            gid,
            &mut grp,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    assert!(rc == 0 && !result.is_null(), "cannot resolve own group");
    unsafe { std::ffi::CStr::from_ptr(grp.gr_name) }
        .to_string_lossy()
        .into_owned()
}

/// A socket path short enough for sun_path wherever the tmpdir lands.
fn short_dir() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::Builder::new()
        .prefix("pfui")
        .tempdir_in("/tmp")
        .unwrap();
    let sock = dir.path().join("s.sock");
    (dir, sock)
}

#[test]
fn socket_is_bound_with_the_intended_mode() {
    let (_dir, sock) = short_dir();
    let _listener = listener::bind_unix(&sock, &own_group(), 8, &log()).unwrap();
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o7777;
    assert_eq!(mode, UNIX_SOCKET_MODE);
}

#[test]
fn socket_is_not_readable_or_writable_by_others() {
    let (_dir, sock) = short_dir();
    let _listener = listener::bind_unix(&sock, &own_group(), 8, &log()).unwrap();
    let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
    assert_eq!(mode & 0o007, 0, "others have access: {:o}", mode & 0o7777);
}

#[test]
fn a_stale_socket_from_an_unclean_stop_is_reclaimed() {
    let (_dir, sock) = short_dir();
    // Bind and drop without unlinking: the node remains, nothing listens
    drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
    assert!(sock.exists());
    let _listener = listener::bind_unix(&sock, &own_group(), 8, &log()).unwrap();
    assert!(UnixStream::connect(&sock).is_ok());
}

#[test]
fn a_live_daemons_socket_is_not_stolen() {
    let (_dir, sock) = short_dir();
    let live = listener::bind_unix(&sock, &own_group(), 8, &log()).unwrap();
    let refused = listener::bind_unix(&sock, &own_group(), 8, &log());
    assert!(refused.is_err(), "second bind must refuse");
    // The live daemon's socket survives
    assert!(sock.exists());
    drop(live);
}

#[test]
fn a_missing_group_stops_the_bind_and_leaves_no_socket_behind() {
    let (_dir, sock) = short_dir();
    let refused = listener::bind_unix(&sock, "no-such-group-pfui", 8, &log());
    assert!(refused.is_err());
    assert!(!sock.exists(), "refused bind left the node behind");
}

#[test]
fn a_world_writable_parent_directory_is_refused() {
    let (dir, sock) = short_dir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
    let refused = listener::bind_unix(&sock, &own_group(), 8, &log());
    assert!(refused.is_err());
}

#[test]
fn a_sticky_world_writable_parent_is_allowed() {
    let (dir, sock) = short_dir();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o1777)).unwrap();
    assert!(listener::bind_unix(&sock, &own_group(), 8, &log()).is_ok());
}

#[test]
fn a_missing_parent_directory_stops_the_bind() {
    let refused = listener::bind_unix(
        Path::new("/tmp/pfui-no-such-dir/s.sock"),
        &own_group(),
        8,
        &log(),
    );
    assert!(refused.is_err());
}

#[test]
fn shutdown_removes_the_socket_and_removal_is_safe_when_none_was_bound() {
    let (_dir, sock) = short_dir();
    let listener = listener::bind_unix(&sock, &own_group(), 8, &log()).unwrap();
    drop(listener);
    listener::remove_unix_socket(&sock);
    assert!(!sock.exists());
    // Removing again, or removing a never-bound path, is a no-op
    listener::remove_unix_socket(&sock);
    listener::remove_unix_socket(Path::new("/tmp/pfui-never-bound.sock"));
}

// ------------------------------------------------- message flow over UNIX

#[derive(Default)]
struct Recorder {
    tables: std::sync::Mutex<Vec<String>>,
}

impl Backends for Recorder {
    fn table_push(&self, table: &str, _ips: &[std::net::IpAddr]) {
        self.tables.lock().unwrap().push(table.to_string());
    }
    fn db_push(&self, _t: &str, _d: &[(String, i64)], _k: Kind, _q: &str) {}
    fn file_push(&self, _f: &Path, _i: &[String]) {}
}

fn unix_config() -> Config {
    load_config_str(
        "
AF4_TABLE: t4
AF4_FILE: /tmp/pfui-test-af4
AF6_TABLE: t6
AF6_FILE: /tmp/pfui-test-af6
SOCKET_UNIX: /tmp/placeholder.sock
COMPRESS: False
SOCKET_TIMEOUT: 1
LOG_LEVEL: ERROR
LOGGING: False
MAX_WORKERS: 2
",
    )
    .unwrap()
}

#[test]
fn a_message_over_the_local_socket_is_acknowledged() {
    let (_dir, sock) = short_dir();
    let cfg = Arc::new(unix_config());
    let log = Arc::new(Logger::stderr(cfg.log_level, cfg.logging));
    let recorder = Arc::new(Recorder::default());
    let ctx = Arc::new(Ctx {
        cfg: Arc::clone(&cfg),
        log: Arc::clone(&log),
        backends: Arc::clone(&recorder) as Arc<dyn Backends>,
        udp: None,
    });
    let pool = WorkerPool::start(ctx);
    let bound = listener::bind_unix(&sock, &own_group(), 8, &log).unwrap();
    let term = Arc::new(AtomicBool::new(false));
    let submit = pool.submitter();
    let (term_c, cfg_c, log_c) = (Arc::clone(&term), Arc::clone(&cfg), Arc::clone(&log));
    let sock_c = sock.clone();
    let accept = std::thread::spawn(move || {
        listener::serve_stream(
            StreamListener::Unix(bound, sock_c),
            submit,
            term_c,
            cfg_c,
            log_c,
        )
    });

    // Exactly the framing and replies TCP carries
    let msg = serde_json::json!({
        "kind": "cache",
        "qname": "example.com.",
        "AF4": [{"ip": "1.0.0.1", "ttl": 1999999999i64}],
        "AF6": [],
    });
    let frame = pfui_firewall::wire::encode(&msg, false).unwrap();
    let mut conn = UnixStream::connect(&sock).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(&frame).unwrap();
    conn.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = String::new();
    conn.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "ACKUPDATE");

    // A refusal is carried the same way
    let mut conn = UnixStream::connect(&sock).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(&[0, 0]).unwrap();
    conn.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = String::new();
    conn.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "Empty payload");

    // A peer that leaves before the ack (the EPIPE case) breaks nothing
    {
        let mut conn = UnixStream::connect(&sock).unwrap();
        conn.write_all(&frame).unwrap();
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while recorder.tables.lock().unwrap().len() < 2 {
        assert!(std::time::Instant::now() < deadline, "tables not updated");
        std::thread::sleep(Duration::from_millis(10));
    }

    term.store(true, Ordering::Relaxed);
    accept.join().unwrap();
    pool.shutdown();
    listener::remove_unix_socket(&sock);
    assert!(!sock.exists());
}
