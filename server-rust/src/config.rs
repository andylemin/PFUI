//! Configuration. The same file and keys the Python daemon reads, so one yml
//! serves either; unknown keys are ignored.
//!
//! Deserialization is coercive rather than strict: numeric fields accept YAML
//! strings that parse, and an unrecognised LOG_LEVEL falls back to ERROR. The
//! refusal list below is exhaustive.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::pf::Ctl;

/// sockaddr_un.sun_path is 104 bytes on OpenBSD including the terminator.
/// Checked at load so an over-long path is a named error rather than an errno
/// out of bind().
pub const UNIX_PATH_MAX: usize = 103;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LogLevel {
    Debug,
    Info,
    Error,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub logging: bool,
    pub log_level: LogLevel,
    pub socket_listen: Option<String>,
    pub socket_proto: Proto,
    pub socket_unix: Option<PathBuf>,
    pub socket_unix_group: String,
    pub socket_port: u16,
    pub socket_timeout: f64,
    pub socket_buffer: usize,
    pub socket_backlog: i32,
    pub compress: bool,
    pub max_workers: usize,
    pub allow_insecure_udp: bool,
    pub redis_host: String,
    pub redis_port: u16,
    pub redis_db: u8,
    pub scan_period: u64,
    pub ttl_multiplier: u32,
    pub ctl: Ctl,
    pub devpf: PathBuf,
    pub af4_table: String,
    pub af4_file: PathBuf,
    pub af6_table: String,
    pub af6_file: PathBuf,
}

#[derive(Debug)]
pub enum ConfigError {
    Io(String),
    Yaml(String),
    Empty,
    MissingRequired(&'static str),
    BadProto(String),
    RelativeSocketPath(String),
    SocketPathTooLong { path: String, len: usize },
    NoListener,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "cannot read config: {e}"),
            ConfigError::Yaml(e) => write!(f, "cannot parse config: {e}"),
            ConfigError::Empty => write!(f, "config file is empty"),
            ConfigError::MissingRequired(key) => write!(
                f,
                "{key} not found in the YAML config file, please configure it"
            ),
            ConfigError::BadProto(v) => {
                write!(f, "SOCKET_PROTO must be TCP or UDP, not '{v}'")
            }
            ConfigError::RelativeSocketPath(p) => write!(
                f,
                "SOCKET_UNIX must be an absolute path, not '{p}' (a relative \
                 path would resolve against whatever directory rc started in)"
            ),
            ConfigError::SocketPathTooLong { path, len } => write!(
                f,
                "SOCKET_UNIX is {len} bytes, over the {UNIX_PATH_MAX} byte \
                 limit on a socket path: '{path}'"
            ),
            ConfigError::NoListener => write!(
                f,
                "no listener configured: set SOCKET_LISTEN (the inside \
                 interface IP, never 0.0.0.0) for remote resolvers, or \
                 SOCKET_UNIX for a resolver on this host, or both"
            ),
        }
    }
}

type Value = serde_yaml::Value;

/// Any scalar as text.
fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Bool(b) => Some(b.to_string()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

fn as_bool(v: &Value) -> Option<bool> {
    v.as_bool()
}

/// Numbers as-is, numeric strings parsed.
fn as_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)),
        Value::String(s) => s.trim().parse().ok(),
        Value::Bool(b) => Some(*b as i64),
        _ => None,
    }
}

fn as_float(v: &Value) -> Option<f64> {
    match v {
        Value::Number(n) => n.as_f64(),
        Value::String(s) => s.trim().parse().ok(),
        _ => None,
    }
}

struct Doc(serde_yaml::Mapping);

impl Doc {
    fn text(&self, key: &str, default: &str) -> String {
        self.0
            .get(Value::from(key))
            .and_then(as_text)
            .unwrap_or_else(|| default.to_string())
    }
    fn boolean(&self, key: &str, default: bool) -> bool {
        self.0
            .get(Value::from(key))
            .and_then(as_bool)
            .unwrap_or(default)
    }
    fn int(&self, key: &str, default: i64) -> i64 {
        self.0
            .get(Value::from(key))
            .and_then(as_int)
            .unwrap_or(default)
    }
    fn float(&self, key: &str, default: f64) -> f64 {
        self.0
            .get(Value::from(key))
            .and_then(as_float)
            .unwrap_or(default)
    }
    fn required(&self, key: &'static str) -> Result<String, ConfigError> {
        self.0
            .get(Value::from(key))
            .and_then(as_text)
            .ok_or(ConfigError::MissingRequired(key))
    }
}

pub fn load_config(path: &Path) -> Result<Config, ConfigError> {
    let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io(e.to_string()))?;
    load_config_str(&text)
}

pub fn load_config_str(text: &str) -> Result<Config, ConfigError> {
    let value: Value = serde_yaml::from_str(text).map_err(|e| ConfigError::Yaml(e.to_string()))?;
    let mapping = match value {
        Value::Mapping(m) => m,
        Value::Null => return Err(ConfigError::Empty),
        _ => return Err(ConfigError::Yaml("top level is not a mapping".into())),
    };
    let doc = Doc(mapping);

    // Normalised here because the listener is selected by exact match, and a
    // lowercase 'udp' must not slip past the ALLOW_INSECURE_UDP gate
    let proto_raw = doc.text("SOCKET_PROTO", "TCP").trim().to_uppercase();
    let socket_proto = match proto_raw.as_str() {
        "TCP" => Proto::Tcp,
        "UDP" => Proto::Udp,
        _ => return Err(ConfigError::BadProto(proto_raw)),
    };

    let unix_raw = doc.text("SOCKET_UNIX", "");
    let unix_raw = unix_raw.trim();
    let socket_unix = if unix_raw.is_empty() {
        None
    } else {
        if !unix_raw.starts_with('/') {
            return Err(ConfigError::RelativeSocketPath(unix_raw.to_string()));
        }
        if unix_raw.len() > UNIX_PATH_MAX {
            return Err(ConfigError::SocketPathTooLong {
                path: unix_raw.to_string(),
                len: unix_raw.len(),
            });
        }
        Some(PathBuf::from(unix_raw))
    };

    // Neither required nor defaulted, least of all to 0.0.0.0: the port
    // injects PF whitelist entries unauthenticated, and leaving it out is how
    // a same-host deployment says "local socket only"
    let listen_raw = doc.text("SOCKET_LISTEN", "");
    let socket_listen = match listen_raw.trim() {
        "" => None,
        s => Some(s.to_string()),
    };
    if socket_listen.is_none() && socket_unix.is_none() {
        return Err(ConfigError::NoListener);
    }

    // Any LOG_LEVEL other than DEBUG or INFO is ERROR. Trimmed and folded to
    // upper case first: matching the raw text made 'debug' silently mean ERROR.
    let log_level = match doc
        .text("LOG_LEVEL", "DEBUG")
        .trim()
        .to_uppercase()
        .as_str()
    {
        "DEBUG" => LogLevel::Debug,
        "INFO" => LogLevel::Info,
        _ => LogLevel::Error,
    };

    let ctl = match doc.text("CTL", "IOCTL").trim().to_uppercase().as_str() {
        "PFCTL" => Ctl::Pfctl,
        _ => Ctl::Ioctl,
    };

    Ok(Config {
        logging: doc.boolean("LOGGING", true),
        log_level,
        socket_listen,
        socket_proto,
        socket_unix,
        socket_unix_group: doc.text("SOCKET_UNIX_GROUP", "_pfui"),
        socket_port: doc.int("SOCKET_PORT", 10001) as u16,
        socket_timeout: doc.float("SOCKET_TIMEOUT", 3.0),
        socket_buffer: doc.int("SOCKET_BUFFER", 1024).max(1) as usize,
        socket_backlog: doc.int("SOCKET_BACKLOG", 128) as i32,
        compress: doc.boolean("COMPRESS", true),
        max_workers: doc.int("MAX_WORKERS", 32).max(1) as usize,
        allow_insecure_udp: doc.boolean("ALLOW_INSECURE_UDP", false),
        redis_host: doc.text("REDIS_HOST", "127.0.0.1"),
        redis_port: doc.int("REDIS_PORT", 6379) as u16,
        redis_db: doc.int("REDIS_DB", 0) as u8,
        scan_period: doc.int("SCAN_PERIOD", 60).max(0) as u64,
        ttl_multiplier: doc.int("TTL_MULTIPLIER", 2).max(0) as u32,
        ctl,
        devpf: PathBuf::from(doc.text("DEVPF", "/dev/pf")),
        af4_table: doc.required("AF4_TABLE")?,
        af4_file: PathBuf::from(doc.required("AF4_FILE")?),
        af6_table: doc.required("AF6_TABLE")?,
        af6_file: PathBuf::from(doc.required("AF6_FILE")?),
    })
}

/// A network listener in UDP mode needs the explicit opt-in. A startup check
/// rather than a config error, so a local-socket-only config with
/// SOCKET_PROTO: UDP still starts.
pub fn udp_gate_refuses(cfg: &Config) -> bool {
    cfg.socket_proto == Proto::Udp && cfg.socket_listen.is_some() && !cfg.allow_insecure_udp
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "
AF4_TABLE: pfui_ipv4_domains
AF4_FILE: /var/db/pfui/ipv4_domains
AF6_TABLE: pfui_ipv6_domains
AF6_FILE: /var/db/pfui/ipv6_domains
";

    fn with(extra: &str) -> Result<Config, ConfigError> {
        load_config_str(&format!("{BASE}{extra}"))
    }

    #[test]
    fn log_level_is_read_case_insensitively() {
        // Matching the raw text made a lower-case level mean ERROR, so a
        // resolver set to debug logged nothing but faults
        let level = |text: &str| {
            let yaml = format!("SOCKET_LISTEN: 10.10.1.254\nLOG_LEVEL: '{text}'\n");
            with(&yaml).unwrap().log_level
        };
        for text in ["DEBUG", "debug", " Debug ", "dEbUg"] {
            assert_eq!(level(text), LogLevel::Debug, "LOG_LEVEL: {text:?}");
        }
        for text in ["INFO", "info", " info "] {
            assert_eq!(level(text), LogLevel::Info, "LOG_LEVEL: {text:?}");
        }
        // Anything unrecognised stays ERROR rather than opening the logs up
        for text in ["ERROR", "error", "warn", "verbose", ""] {
            assert_eq!(level(text), LogLevel::Error, "LOG_LEVEL: {text:?}");
        }
    }

    #[test]
    fn shipped_config_loads() {
        let shipped = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("server-python/pfui_firewall.yml");
        let cfg = load_config(&shipped).unwrap();
        assert_eq!(cfg.socket_port, 10001);
        assert_eq!(cfg.ttl_multiplier, 4);
        assert_eq!(cfg.redis_db, 9);
        assert!(!cfg.logging);
    }

    #[test]
    fn required_keys_are_refused_when_missing() {
        for key in ["AF4_TABLE", "AF4_FILE", "AF6_TABLE", "AF6_FILE"] {
            let stripped: String = BASE
                .lines()
                .filter(|l| !l.starts_with(key))
                .collect::<Vec<_>>()
                .join("\n");
            let err =
                load_config_str(&format!("{stripped}\nSOCKET_LISTEN: 10.0.0.1\n")).unwrap_err();
            assert!(
                matches!(err, ConfigError::MissingRequired(k) if k == key),
                "{key}: {err}"
            );
        }
    }

    #[test]
    fn no_listener_of_either_kind_is_refused() {
        assert!(matches!(with(""), Err(ConfigError::NoListener)));
        assert!(matches!(
            with("SOCKET_LISTEN: ''\nSOCKET_UNIX: ''\n"),
            Err(ConfigError::NoListener)
        ));
    }

    #[test]
    fn listen_address_is_never_defaulted() {
        let cfg = with("SOCKET_UNIX: /var/run/pfui/s.sock\n").unwrap();
        assert_eq!(cfg.socket_listen, None);
    }

    #[test]
    fn local_socket_alone_is_a_complete_configuration() {
        assert!(with("SOCKET_UNIX: /var/run/pfui/s.sock\n").is_ok());
    }

    #[test]
    fn network_listener_alone_is_a_complete_configuration() {
        assert!(with("SOCKET_LISTEN: 10.10.1.254\n").is_ok());
    }

    #[test]
    fn both_listeners_together_are_accepted() {
        let cfg = with("SOCKET_LISTEN: 10.10.1.254\nSOCKET_UNIX: /var/run/pfui/s.sock\n").unwrap();
        assert!(cfg.socket_listen.is_some() && cfg.socket_unix.is_some());
    }

    #[test]
    fn relative_socket_path_is_refused() {
        for path in ["relative/path.sock", "./s.sock"] {
            assert!(matches!(
                with(&format!("SOCKET_UNIX: {path}\n")),
                Err(ConfigError::RelativeSocketPath(_))
            ));
        }
    }

    #[test]
    fn over_long_socket_path_is_refused_at_load() {
        let long = format!("/{}", "x".repeat(UNIX_PATH_MAX + 1));
        assert!(matches!(
            with(&format!("SOCKET_UNIX: {long}\n")),
            Err(ConfigError::SocketPathTooLong { .. })
        ));
    }

    #[test]
    fn socket_group_defaults_to_the_shared_pfui_group() {
        let cfg = with("SOCKET_UNIX: /var/run/pfui/s.sock\n").unwrap();
        assert_eq!(cfg.socket_unix_group, "_pfui");
    }

    #[test]
    fn udp_gate_does_not_apply_to_a_local_socket_only_daemon() {
        let cfg = with("SOCKET_UNIX: /var/run/pfui/s.sock\nSOCKET_PROTO: UDP\n").unwrap();
        assert!(!udp_gate_refuses(&cfg));
        let cfg = with("SOCKET_LISTEN: 10.0.0.1\nSOCKET_PROTO: UDP\n").unwrap();
        assert!(udp_gate_refuses(&cfg));
        let cfg =
            with("SOCKET_LISTEN: 10.0.0.1\nSOCKET_PROTO: UDP\nALLOW_INSECURE_UDP: True\n").unwrap();
        assert!(!udp_gate_refuses(&cfg));
    }

    #[test]
    fn socket_proto_is_normalised() {
        for (value, expected) in [
            ("tcp", Proto::Tcp),
            (" TCP ", Proto::Tcp),
            ("Udp", Proto::Udp),
            ("udp", Proto::Udp),
        ] {
            let cfg = with(&format!(
                "SOCKET_LISTEN: 10.0.0.1\nALLOW_INSECURE_UDP: True\nSOCKET_PROTO: '{value}'\n"
            ))
            .unwrap();
            assert_eq!(cfg.socket_proto, expected, "{value:?}");
        }
    }

    #[test]
    fn unsupported_socket_proto_is_refused() {
        for value in ["TLS", "SCTP", "''"] {
            assert!(matches!(
                with(&format!("SOCKET_LISTEN: 10.0.0.1\nSOCKET_PROTO: {value}\n")),
                Err(ConfigError::BadProto(_))
            ));
        }
    }

    #[test]
    fn empty_config_file_is_refused() {
        assert!(matches!(load_config_str(""), Err(ConfigError::Empty)));
        assert!(matches!(load_config_str("---\n"), Err(ConfigError::Empty)));
    }

    #[test]
    fn numeric_fields_accept_yaml_strings() {
        // A quoted port must not be refused
        let cfg = with(
            "SOCKET_LISTEN: 10.0.0.1\nSOCKET_PORT: '10002'\nSOCKET_TIMEOUT: '3.5'\nMAX_WORKERS: '8'\n",
        )
        .unwrap();
        assert_eq!(cfg.socket_port, 10002);
        assert_eq!(cfg.socket_timeout, 3.5);
        assert_eq!(cfg.max_workers, 8);
    }

    #[test]
    fn unrecognised_log_level_falls_back_to_error() {
        let cfg = with("SOCKET_LISTEN: 10.0.0.1\nLOG_LEVEL: WARNING\n").unwrap();
        assert_eq!(cfg.log_level, LogLevel::Error);
    }

    #[test]
    fn unknown_keys_are_ignored() {
        assert!(with("SOCKET_LISTEN: 10.0.0.1\nFUTURE_KNOB: 42\n").is_ok());
    }
}
