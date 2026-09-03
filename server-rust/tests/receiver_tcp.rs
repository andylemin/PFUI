//! Receiver decision tree over a real TCP listener and real client sockets —
//! the test_receiver.py port. Backends are recorders (the Ctx trait seam
//! replaces Python's monkeypatching); the wire, listener, pool and receiver
//! are all the production code.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pfui_firewall::config::{load_config_str, Config};
use pfui_firewall::listener::{self, StreamListener, WorkerPool};
use pfui_firewall::logger::Logger;
use pfui_firewall::receiver::{Backends, Ctx};
use pfui_firewall::store::Kind;
use pfui_firewall::wire;

struct DbRecord {
    data: Vec<(String, i64)>,
    kind: Kind,
    qname: String,
}

#[derive(Default)]
struct Recorder {
    tables: Mutex<Vec<(String, Vec<IpAddr>)>>,
    db: Mutex<Vec<DbRecord>>,
    files: Mutex<Vec<(String, Vec<String>)>>,
}

impl Backends for Recorder {
    fn table_push(&self, table: &str, ips: &[IpAddr]) {
        self.tables
            .lock()
            .unwrap()
            .push((table.to_string(), ips.to_vec()));
    }
    fn db_push(&self, _table: &str, data: &[(String, i64)], kind: Kind, qname: &str) {
        self.db.lock().unwrap().push(DbRecord {
            data: data.to_vec(),
            kind,
            qname: qname.to_string(),
        });
    }
    fn file_push(&self, file: &Path, ips: &[String]) {
        self.files
            .lock()
            .unwrap()
            .push((file.display().to_string(), ips.to_vec()));
    }
}

struct Daemon {
    addr: SocketAddr,
    recorder: Arc<Recorder>,
    term: Arc<AtomicBool>,
    accept_thread: Option<std::thread::JoinHandle<()>>,
    pool: Option<WorkerPool>,
}

fn test_config() -> Config {
    load_config_str(
        "
AF4_TABLE: t4
AF4_FILE: /tmp/pfui-test-af4
AF6_TABLE: t6
AF6_FILE: /tmp/pfui-test-af6
SOCKET_LISTEN: 127.0.0.1
COMPRESS: False
SOCKET_TIMEOUT: 1
LOG_LEVEL: ERROR
LOGGING: False
MAX_WORKERS: 4
",
    )
    .unwrap()
}

fn start_daemon() -> Daemon {
    let cfg = Arc::new(test_config());
    let log = Arc::new(Logger::stderr(cfg.log_level, cfg.logging));
    let recorder = Arc::new(Recorder::default());
    let ctx = Arc::new(Ctx {
        cfg: Arc::clone(&cfg),
        log: Arc::clone(&log),
        backends: Arc::clone(&recorder) as Arc<dyn Backends>,
        udp: None,
    });
    let pool = WorkerPool::start(ctx);

    // Ephemeral port via the production bind path
    let listener = listener::bind_tcp("127.0.0.1", 0, cfg.socket_backlog).unwrap();
    let addr = listener.local_addr().unwrap();
    let term = Arc::new(AtomicBool::new(false));
    let submit = pool.submitter();
    let (term_c, cfg_c, log_c) = (Arc::clone(&term), Arc::clone(&cfg), Arc::clone(&log));
    let accept_thread = std::thread::spawn(move || {
        listener::serve_stream(StreamListener::Tcp(listener), submit, term_c, cfg_c, log_c)
    });
    Daemon {
        addr,
        recorder,
        term,
        accept_thread: Some(accept_thread),
        pool: Some(pool),
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.term.store(true, Ordering::Relaxed);
        if let Some(t) = self.accept_thread.take() {
            let _ = t.join();
        }
        if let Some(p) = self.pool.take() {
            p.shutdown();
        }
    }
}

/// Send raw bytes, half-close, read the reply.
fn exchange(addr: SocketAddr, bytes: &[u8]) -> String {
    let mut conn = TcpStream::connect(addr).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    conn.write_all(bytes).unwrap();
    conn.shutdown(std::net::Shutdown::Write).unwrap();
    let mut reply = String::new();
    conn.read_to_string(&mut reply).unwrap();
    reply
}

fn framed(payload: &[u8]) -> Vec<u8> {
    let mut out = (payload.len() as u32).to_be_bytes().to_vec();
    out.extend_from_slice(payload);
    out
}

fn valid_message() -> Vec<u8> {
    let msg = serde_json::json!({
        "kind": "rr",
        "qname": "example.com.",
        "AF4": [{"ip": "8.8.8.8", "ttl": 3600}],
        "AF6": [{"ip": "2001:4860:4860::8888", "ttl": 3600}],
    });
    wire::encode(&msg, false).unwrap()
}

#[test]
fn a_valid_message_is_acknowledged_and_recorded() {
    let daemon = start_daemon();
    assert_eq!(exchange(daemon.addr, &valid_message()), "ACKUPDATE");

    // PF tables, Redis and persist files all recorded, canonical
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while daemon.recorder.files.lock().unwrap().len() < 2 {
        assert!(std::time::Instant::now() < deadline, "backends not called");
        std::thread::sleep(Duration::from_millis(10));
    }
    let tables = daemon.recorder.tables.lock().unwrap();
    assert_eq!(tables.len(), 2);
    assert_eq!(tables[0].0, "t4");
    assert_eq!(tables[1].0, "t6");
    let db = daemon.recorder.db.lock().unwrap();
    assert_eq!(db[0].data, vec![("8.8.8.8".to_string(), 3600)]);
    assert_eq!(db[0].kind, Kind::Rr);
    assert_eq!(db[0].qname, "example.com.");
}

#[test]
fn zero_declared_length_is_refused_as_a_bad_length() {
    let daemon = start_daemon();
    assert_eq!(exchange(daemon.addr, &0u32.to_be_bytes()), "Bad length");
}

#[test]
fn oversize_declared_length_is_refused_as_a_bad_length() {
    // Header only: the refusal happens before any payload is buffered, and
    // bytes the server never reads would RST the reply on a real socket
    let daemon = start_daemon();
    let frame = ((wire::MAX_MESSAGE + 1) as u32).to_be_bytes();
    assert_eq!(exchange(daemon.addr, &frame), "Bad length");
}

#[test]
fn short_payload_is_refused_as_truncated() {
    let daemon = start_daemon();
    let mut frame = 8u32.to_be_bytes().to_vec();
    frame.extend_from_slice(b"abc");
    assert_eq!(exchange(daemon.addr, &frame), "Truncated");
}

#[test]
fn peer_that_closes_before_a_header_gets_the_empty_payload_reason() {
    let daemon = start_daemon();
    assert_eq!(exchange(daemon.addr, b""), "Empty payload");
    // 1-3 header bytes is the same non-message
    assert_eq!(exchange(daemon.addr, &[0x00, 0x00]), "Empty payload");
}

#[test]
fn garbage_payload_is_refused_as_undecodable() {
    let daemon = start_daemon();
    assert_eq!(
        exchange(daemon.addr, &framed(b"not json at all")),
        "Failed to decode"
    );
}

#[test]
fn payload_that_is_not_a_message_object_is_an_invalid_datatype() {
    let daemon = start_daemon();
    for payload in [&b"null"[..], b"[]", b"\"rr\"", b"42"] {
        assert_eq!(
            exchange(daemon.addr, &framed(payload)),
            "Invalid datatype",
            "{payload:?}"
        );
    }
}

#[test]
fn message_without_kind_is_refused() {
    let daemon = start_daemon();
    let msg = serde_json::json!({"AF4": [{"ip": "8.8.8.8", "ttl": 60}], "AF6": []});
    let frame = wire::encode(&msg, false).unwrap();
    assert_eq!(exchange(daemon.addr, &frame), "Missing kind");
}

#[test]
fn message_with_an_unrecognised_kind_is_refused() {
    let daemon = start_daemon();
    let msg = serde_json::json!({"kind": "bogus", "AF4": [{"ip": "8.8.8.8", "ttl": 60}]});
    let frame = wire::encode(&msg, false).unwrap();
    assert_eq!(exchange(daemon.addr, &frame), "Missing kind");
}

#[test]
fn well_formed_message_with_no_records_is_refused() {
    let daemon = start_daemon();
    let msg = serde_json::json!({"kind": "rr", "qname": "x.", "AF4": [], "AF6": []});
    let frame = wire::encode(&msg, false).unwrap();
    assert_eq!(exchange(daemon.addr, &frame), "No records");
}

#[test]
fn message_whose_only_records_are_non_global_is_refused() {
    let daemon = start_daemon();
    let msg = serde_json::json!({
        "kind": "rr",
        "AF4": [{"ip": "10.0.0.1", "ttl": 60}, {"ip": "0.0.0.0", "ttl": 60}],
        "AF6": [{"ip": "fe80::1", "ttl": 60}],
    });
    let frame = wire::encode(&msg, false).unwrap();
    assert_eq!(exchange(daemon.addr, &frame), "No records");
    assert!(daemon.recorder.tables.lock().unwrap().is_empty());
}

#[test]
fn a_peer_that_leaves_before_the_ack_is_tolerated() {
    // The non-blocking cache-report pattern: client sends and closes without
    // reading. EPIPE on the reply must not break the daemon.
    let daemon = start_daemon();
    {
        let mut conn = TcpStream::connect(daemon.addr).unwrap();
        conn.write_all(&valid_message()).unwrap();
        // Full close, not shutdown(Write): the reply has nowhere to go
    }
    // The daemon still serves, and the leaver's addresses were installed
    let deadline = std::time::Instant::now() + Duration::from_secs(5);
    while daemon.recorder.tables.lock().unwrap().len() < 2 {
        assert!(std::time::Instant::now() < deadline, "tables not updated");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(exchange(daemon.addr, &valid_message()), "ACKUPDATE");
}

#[test]
fn a_stalled_peer_hits_the_timeout() {
    let daemon = start_daemon();
    let mut conn = TcpStream::connect(daemon.addr).unwrap();
    conn.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    // Declare a payload, never send it, keep the socket open: the server's
    // SOCKET_TIMEOUT (1s here) must fire rather than the worker blocking
    conn.write_all(&8u32.to_be_bytes()).unwrap();
    let mut reply = String::new();
    conn.read_to_string(&mut reply).unwrap();
    assert_eq!(reply, "Socket timeout");
}
