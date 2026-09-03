//! Per-message handling: read, validate, update PF, acknowledge, record. The
//! decision tree and its reply strings are protocol vocabulary; PROTOCOL.md is
//! normative.

use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::Path;
use std::sync::Arc;
use std::time::Instant;

use crate::config::Config;
use crate::logger::Logger;
use crate::store::Kind;
use crate::validate::{extract, IpVersion};
use crate::wire::{self, ReadError, WireError};

/// Every refusal this daemon can send, pinned against PROTOCOL.md by a test.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Refusal {
    EmptyPayload,
    SocketTimeout,
    BadLength,
    Truncated,
    BadFrame,
    FailedToDecode,
    InvalidDatatype,
    MissingKind,
    NoRecords,
}

impl Refusal {
    pub fn as_str(self) -> &'static str {
        match self {
            Refusal::EmptyPayload => "Empty payload",
            Refusal::SocketTimeout => "Socket timeout",
            Refusal::BadLength => "Bad length",
            Refusal::Truncated => "Truncated",
            Refusal::BadFrame => "Bad frame",
            Refusal::FailedToDecode => "Failed to decode",
            Refusal::InvalidDatatype => "Invalid datatype",
            Refusal::MissingKind => "Missing kind",
            Refusal::NoRecords => "No records",
        }
    }

    pub const ALL: [Refusal; 9] = [
        Refusal::EmptyPayload,
        Refusal::SocketTimeout,
        Refusal::BadLength,
        Refusal::Truncated,
        Refusal::BadFrame,
        Refusal::FailedToDecode,
        Refusal::InvalidDatatype,
        Refusal::MissingKind,
        Refusal::NoRecords,
    ];
}

pub const ACK_UPDATE: &str = "ACKUPDATE";
pub const ACK_DATA: &str = "ACKDATA";

/// The stores the receiver writes, behind a trait so tests can inject
/// recorders. Implementations log their own failures rather than returning
/// them: the PF push precedes the acknowledgement, and a Redis or file failure
/// is reconciled by the scan loop.
pub trait Backends: Send + Sync {
    fn table_push(&self, table: &str, ips: &[IpAddr]);
    fn db_push(&self, table: &str, data: &[(String, i64)], kind: Kind, qname: &str);
    fn file_push(&self, file: &Path, ips: &[String]);
}

pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum StreamKind {
    Tcp,
    Unix,
}

pub enum Job {
    Stream {
        kind: StreamKind,
        conn: Box<dyn Stream>,
        peer: String,
    },
    Datagram {
        data: Vec<u8>,
        source: SocketAddr,
    },
}

pub struct Ctx {
    pub cfg: Arc<Config>,
    pub log: Arc<Logger>,
    pub backends: Arc<dyn Backends>,
    /// The bound datagram socket, for ACKs back to a validated sender.
    pub udp: Option<Arc<UdpSocket>>,
}

pub fn handle(job: Job, ctx: &Ctx) {
    match job {
        Job::Stream {
            kind,
            mut conn,
            peer,
        } => handle_stream(kind, conn.as_mut(), &peer, ctx),
        Job::Datagram { data, source } => handle_datagram(&data, source, ctx),
    }
}

/// What one message decoded and validated to.
enum Verdict {
    Act {
        kind: Kind,
        qname: String,
        af4: Vec<(String, i64)>,
        af6: Vec<(String, i64)>,
    },
    Refuse(Refusal),
}

fn judge(decoded: &serde_json::Value, peer: &str, log: &Logger) -> Verdict {
    // Shape before contents: a non-object has no 'kind' to be missing, and
    // reporting one as version skew misdirects the operator
    let Some(map) = decoded.as_object() else {
        log.error(&format!(
            "Message from {peer} decoded to a non-object; dropping. Non-PFUI sender?"
        ));
        return Verdict::Refuse(Refusal::InvalidDatatype);
    };
    let kind = match map.get("kind").and_then(|v| v.as_str()) {
        Some("rr") => Kind::Rr,
        Some("cache") => Kind::Cache,
        other => {
            log.error(&format!(
                "Message from {peer} has no valid 'kind' ({other:?}); dropping. \
                 PFUI_Unbound must run the same release as PFUI_Firewall."
            ));
            return Verdict::Refuse(Refusal::MissingKind);
        }
    };
    // Not type-checked, matching the reference implementation: a non-string
    // scalar is stored as its text
    let qname = match map.get("qname") {
        None | Some(serde_json::Value::Null) => String::new(),
        Some(serde_json::Value::String(s)) => s.clone(),
        Some(serde_json::Value::Array(_)) | Some(serde_json::Value::Object(_)) => String::new(),
        Some(v) => v.to_string(),
    };
    let af4 = extract(map.get("AF4"), IpVersion::V4);
    let af6 = extract(map.get("AF6"), IpVersion::V6);
    if af4.is_empty() && af6.is_empty() {
        log.error(&format!(
            "No routable records from {peer}. Nothing to act on."
        ));
        return Verdict::Refuse(Refusal::NoRecords);
    }
    Verdict::Act {
        kind,
        qname,
        af4,
        af6,
    }
}

/// `ip=ttl` pairs for a log line, or `none` for an empty family.
fn records(data: &[(String, i64)]) -> String {
    if data.is_empty() {
        return "none".to_string();
    }
    data.iter()
        .map(|(ip, ttl)| format!("{ip}={ttl}"))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Update PF tables, then the stores. Callers acknowledge in between: the
/// order PF, ACKUPDATE, Redis, persist file is the latency contract.
fn act(
    ctx: &Ctx,
    kind: Kind,
    qname: &str,
    af4: &[(String, i64)],
    af6: &[(String, i64)],
    ack: impl FnOnce(),
) {
    let ips = |data: &[(String, i64)]| -> Vec<IpAddr> {
        data.iter().filter_map(|(ip, _)| ip.parse().ok()).collect()
    };
    let names =
        |data: &[(String, i64)]| -> Vec<String> { data.iter().map(|(ip, _)| ip.clone()).collect() };

    if !af4.is_empty() {
        ctx.backends.table_push(&ctx.cfg.af4_table, &ips(af4));
    }
    if !af6.is_empty() {
        ctx.backends.table_push(&ctx.cfg.af6_table, &ips(af6));
    }
    if ctx.log.verbose {
        // kind is reported with the TTLs because it decides how to read them:
        // seconds remaining under rr, an absolute expiry under cache
        ctx.log.info(&format!(
            "PF Table updated for {} ({}): AF4 {} AF6 {}",
            if qname.is_empty() { "<no qname>" } else { qname },
            kind.as_str(),
            records(af4),
            records(af6),
        ));
    }

    ack();

    if !af4.is_empty() {
        ctx.backends.db_push(&ctx.cfg.af4_table, af4, kind, qname);
        ctx.backends.file_push(&ctx.cfg.af4_file, &names(af4));
    }
    if !af6.is_empty() {
        ctx.backends.db_push(&ctx.cfg.af6_table, af6, kind, qname);
        ctx.backends.file_push(&ctx.cfg.af6_file, &names(af6));
    }
}

fn handle_stream(_kind: StreamKind, conn: &mut dyn Stream, peer: &str, ctx: &Ctx) {
    let started = ctx.log.stats_enabled().then(Instant::now);

    // Writes to the peer tolerate failure: the client may already be gone,
    // which is routine on the unix transport, and the addresses are installed
    // before any acknowledgement is attempted
    let reply = |conn: &mut dyn Stream, msg: &str| {
        ctx.log.info(&format!("Close msg: {msg}"));
        let _ = conn.write_all(msg.as_bytes());
        let _ = conn.flush();
    };

    let decoded = match wire::read_frame(&mut &mut *conn, ctx.cfg.socket_buffer, ctx.cfg.compress) {
        Ok(Some(v)) => v,
        Ok(None) => {
            // Closed before a complete header: no message, not an error
            ctx.log
                .error(&format!("Empty payload, disconnecting {peer}"));
            reply(conn, Refusal::EmptyPayload.as_str());
            return;
        }
        Err(e) => {
            let refusal = match &e {
                ReadError::Io(io)
                    if io.kind() == std::io::ErrorKind::TimedOut
                        || io.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    Refusal::SocketTimeout
                }
                ReadError::Io(_) => Refusal::FailedToDecode,
                ReadError::Wire(WireError::BadLength(_)) => Refusal::BadLength,
                ReadError::Wire(WireError::Truncated { .. }) => Refusal::Truncated,
                ReadError::Wire(WireError::DecompressUnfinished) => Refusal::BadFrame,
                ReadError::Wire(WireError::DecompressCorrupt(_))
                | ReadError::Wire(WireError::Json(_)) => Refusal::FailedToDecode,
            };
            ctx.log
                .error(&format!("{e}; disconnecting {peer} ({})", refusal.as_str()));
            reply(conn, refusal.as_str());
            return;
        }
    };

    if ctx.log.stats_enabled() {
        ctx.log.info(&format!("Received {decoded} from {peer}"));
    }

    match judge(&decoded, peer, &ctx.log) {
        Verdict::Refuse(refusal) => reply(conn, refusal.as_str()),
        Verdict::Act {
            kind,
            qname,
            af4,
            af6,
        } => {
            act(ctx, kind, &qname, &af4, &af6, || {
                reply(conn, ACK_UPDATE);
            });
            if let Some(t0) = started {
                ctx.log.info(&format!(
                    "latency microsecs total={:.2}",
                    t0.elapsed().as_secs_f64() * 1e6
                ));
            }
        }
    }
}

fn handle_datagram(data: &[u8], source: SocketAddr, ctx: &Ctx) {
    let peer = source.to_string();
    // A refusal is never sent over UDP: the source address is unverified, and
    // replying would make the server a reflector. ACKDATA follows validation,
    // ACKUPDATE follows the table update.
    let send = |msg: &str| {
        if let Some(udp) = &ctx.udp {
            let _ = udp.send_to(msg.as_bytes(), source);
        }
    };

    // Unreachable behind the listener's 1400-byte ceiling
    if data.len() > wire::MAX_MESSAGE {
        ctx.log.error(&format!(
            "Datagram of {} bytes from {peer} too large; dropping silently",
            data.len()
        ));
        return;
    }
    let decoded = match wire::decode(data, ctx.cfg.compress) {
        Ok(v) => v,
        Err(e) => {
            ctx.log
                .error(&format!("Failed to decode datagram from {peer}: {e}"));
            return;
        }
    };
    match judge(&decoded, &peer, &ctx.log) {
        Verdict::Refuse(_) => {} // silence
        Verdict::Act {
            kind,
            qname,
            af4,
            af6,
        } => {
            send(ACK_DATA);
            act(ctx, kind, &qname, &af4, &af6, || send(ACK_UPDATE));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_refusal_reason_is_documented() {
        // PROTOCOL.md's reply table
        let documented = [
            "Missing kind",
            "Bad frame",
            "Bad length",
            "Truncated",
            "Failed to decode",
            "Invalid datatype",
            "No records",
            "Empty payload",
            "Socket timeout",
        ];
        for refusal in Refusal::ALL {
            assert!(
                documented.contains(&refusal.as_str()),
                "{} is not documented in PROTOCOL.md",
                refusal.as_str()
            );
        }
        assert_eq!(Refusal::ALL.len(), documented.len());
    }
}
