//! syslog(3) logging, keeping the PFUIFW: prefix operators match on.
//!
//! error() always emits; info() emits unless LOG_LEVEL is ERROR; the chatty
//! per-message lines are gated by the caller on `verbose` (the LOGGING flag).
//! stats_enabled() is LOGGING and DEBUG together, the gate on the latency line.

use std::ffi::CString;

use crate::config::LogLevel;

enum Sink {
    Syslog {
        // openlog(3) keeps the ident pointer, so it is held for the daemon's
        // lifetime
        _ident: CString,
    },
    Stderr,
}

pub struct Logger {
    level: LogLevel,
    pub verbose: bool,
    sink: Sink,
}

impl Logger {
    pub fn syslog(level: LogLevel, verbose: bool) -> Self {
        let ident = CString::new("pfui_firewall").unwrap();
        unsafe { libc::openlog(ident.as_ptr(), libc::LOG_PID, libc::LOG_DAEMON) };
        Logger {
            level,
            verbose,
            sink: Sink::Syslog { _ident: ident },
        }
    }

    /// Foreground (-d) and test logging.
    pub fn stderr(level: LogLevel, verbose: bool) -> Self {
        Logger {
            level,
            verbose,
            sink: Sink::Stderr,
        }
    }

    pub fn stats_enabled(&self) -> bool {
        self.verbose && self.level == LogLevel::Debug
    }

    pub fn error(&self, msg: &str) {
        self.emit(libc::LOG_ERR, msg);
    }

    pub fn info(&self, msg: &str) {
        if self.level != LogLevel::Error {
            self.emit(libc::LOG_INFO, msg);
        }
    }

    fn emit(&self, priority: i32, msg: &str) {
        match &self.sink {
            Sink::Syslog { .. } => {
                let Ok(text) = CString::new(format!("PFUIFW: {msg}")) else {
                    return;
                };
                let fmt = c"%s";
                unsafe { libc::syslog(priority, fmt.as_ptr(), text.as_ptr()) };
            }
            Sink::Stderr => {
                let tag = if priority == libc::LOG_ERR {
                    "ERR"
                } else {
                    "INF"
                };
                eprintln!("pfui_firewall[{tag}]: PFUIFW: {msg}");
            }
        }
    }
}
