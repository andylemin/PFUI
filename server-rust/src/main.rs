//! PFUI_Firewall daemon. Runs in the foreground; rc.d owns backgrounding via
//! rc_bg. Exit codes: 2 config, 3 Redis client, 4 sync thread, 5 UDP gate,
//! 6 bind.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use pfui_firewall::backends::RealBackends;
use pfui_firewall::config::{self, Proto};
use pfui_firewall::listener::{self, StreamListener, WorkerPool};
use pfui_firewall::logger::Logger;
use pfui_firewall::receiver::Ctx;

const CONFIG_LOCATION: &str = "/etc/pfui_firewall.yml";

struct Opts {
    config: PathBuf,
    check_only: bool,
    foreground: bool,
}

fn parse_args() -> Result<Opts, String> {
    let mut opts = Opts {
        config: PathBuf::from(CONFIG_LOCATION),
        check_only: false,
        foreground: false,
    };
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-f" => {
                opts.config = PathBuf::from(args.next().ok_or("-f needs a path")?);
            }
            "-n" => opts.check_only = true,
            "-d" => opts.foreground = true,
            other => {
                return Err(format!(
                    "unknown argument '{other}'; usage: pfui_firewall [-f config] [-n] [-d]"
                ))
            }
        }
    }
    Ok(opts)
}

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(e) => {
            eprintln!("pfui_firewall: {e}");
            return 2;
        }
    };

    let cfg = match config::load_config(&opts.config) {
        Ok(cfg) => Arc::new(cfg),
        Err(e) => {
            eprintln!("pfui_firewall: {e}");
            return 2;
        }
    };
    if opts.check_only {
        println!("pfui_firewall: {} OK", opts.config.display());
        return 0;
    }

    let log = Arc::new(if opts.foreground {
        Logger::stderr(cfg.log_level, cfg.logging)
    } else {
        Logger::syslog(cfg.log_level, cfg.logging)
    });

    // Resolves REDIS_HOST once and never probes the server: a firewall
    // booting before Redis must still start and whitelist
    let backends = match RealBackends::new(Arc::clone(&cfg), Arc::clone(&log)) {
        Ok(b) => Arc::new(b),
        Err(e) => {
            log.error(&format!("Failed to set up Redis client: {e}"));
            return 3;
        }
    };

    let term = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        if let Err(e) = signal_hook::flag::register(signal, Arc::clone(&term)) {
            log.error(&format!("cannot register signal handler: {e}"));
            return 6;
        }
    }
    // A stray HUP must not kill the control plane; the default disposition
    // would terminate
    let _ = signal_hook::flag::register(
        signal_hook::consts::SIGHUP,
        Arc::new(AtomicBool::new(false)),
    );

    // Background expiry, one thread per address family
    let mut sync_threads = Vec::new();
    for (table, file) in pfui_firewall::backends::persist_files(&cfg) {
        match pfui_firewall::sync::spawn(
            Arc::clone(&backends) as Arc<dyn pfui_firewall::sync::SyncOps>,
            table,
            file,
            cfg.scan_period,
            Arc::clone(&term),
            Arc::clone(&log),
        ) {
            Ok(handle) => sync_threads.push(handle),
            Err(e) => {
                log.error(&format!("Scanning thread failed: {e}"));
                return 4;
            }
        }
    }

    if config::udp_gate_refuses(&cfg) {
        log.error(
            "UDP mode is spoofable (a datagram source address is not verified) \
             and is intended for lab use only. Set ALLOW_INSECURE_UDP: True in \
             /etc/pfui_firewall.yml to proceed, or use SOCKET_PROTO: TCP.",
        );
        return 5;
    }

    // Every listener is bound before any is served, so a bind failure is a
    // startup failure rather than a thread that quietly died. Unix first: a
    // network failure after it unlinks the node rather than leaving it behind.
    let unix = match &cfg.socket_unix {
        Some(path) => {
            match listener::bind_unix(path, &cfg.socket_unix_group, cfg.socket_backlog, &log) {
                Ok(l) => Some((l, path.clone())),
                Err(e) => {
                    log.error(&e.to_string());
                    return 6;
                }
            }
        }
        None => None,
    };

    enum Network {
        Tcp(std::net::TcpListener),
        Udp(Arc<std::net::UdpSocket>),
        None,
    }
    let network = match (&cfg.socket_listen, cfg.socket_proto) {
        (Some(listen), Proto::Tcp) => {
            match listener::bind_tcp(listen, cfg.socket_port, cfg.socket_backlog) {
                Ok(l) => {
                    log.info(&format!(
                        "[+] Listening on TCP {listen}:{}",
                        cfg.socket_port
                    ));
                    Network::Tcp(l)
                }
                Err(e) => {
                    log.error(&format!(
                        "Failed to bind TCP {listen}:{}: {e}",
                        cfg.socket_port
                    ));
                    if let Some((_, path)) = &unix {
                        listener::remove_unix_socket(path);
                    }
                    return 6;
                }
            }
        }
        (Some(listen), Proto::Udp) => {
            let timeout = std::time::Duration::from_secs_f64(cfg.socket_timeout.max(0.05));
            match listener::bind_udp(listen, cfg.socket_port, timeout) {
                Ok(s) => {
                    log.info(&format!(
                        "[+] Listening on UDP {listen}:{}",
                        cfg.socket_port
                    ));
                    Network::Udp(Arc::new(s))
                }
                Err(e) => {
                    log.error(&format!(
                        "Failed to bind UDP {listen}:{}: {e}",
                        cfg.socket_port
                    ));
                    if let Some((_, path)) = &unix {
                        listener::remove_unix_socket(path);
                    }
                    return 6;
                }
            }
        }
        (None, _) => Network::None,
    };

    // Binds, group lookup and host resolution are done; the filesystem view
    // now narrows to what serving needs
    if let Err(e) = pfui_firewall::platform::lockdown(&cfg, &opts.config) {
        log.error(&format!("Cannot apply unveil: {e}; refusing to serve"));
        if let Some(path) = &cfg.socket_unix {
            listener::remove_unix_socket(path);
        }
        return 6;
    }

    let ctx = Arc::new(Ctx {
        cfg: Arc::clone(&cfg),
        log: Arc::clone(&log),
        backends,
        udp: match &network {
            Network::Udp(s) => Some(Arc::clone(s)),
            _ => None,
        },
    });
    let pool = WorkerPool::start(Arc::clone(&ctx));
    log.info("[+] PFUI_Firewall service started");

    let mut listeners = Vec::new();
    if let Some((l, path)) = unix {
        let submit = pool.submitter();
        let (term_c, cfg_c, log_c) = (Arc::clone(&term), Arc::clone(&cfg), Arc::clone(&log));
        listeners.push(std::thread::spawn(move || {
            listener::serve_stream(StreamListener::Unix(l, path), submit, term_c, cfg_c, log_c)
        }));
    }
    match network {
        Network::Tcp(l) => {
            let submit = pool.submitter();
            let (term_c, cfg_c, log_c) = (Arc::clone(&term), Arc::clone(&cfg), Arc::clone(&log));
            listeners.push(std::thread::spawn(move || {
                listener::serve_stream(StreamListener::Tcp(l), submit, term_c, cfg_c, log_c)
            }));
        }
        Network::Udp(s) => {
            let submit = pool.submitter();
            let (term_c, log_c) = (Arc::clone(&term), Arc::clone(&log));
            listeners.push(std::thread::spawn(move || {
                listener::serve_udp(s, submit, term_c, log_c)
            }));
        }
        Network::None => {}
    }

    for thread in listeners {
        let _ = thread.join();
    }
    pool.shutdown();
    for thread in sync_threads {
        let _ = thread.join();
    }
    if let Some(path) = &cfg.socket_unix {
        listener::remove_unix_socket(path);
    }
    log.info("[-] PFUI_Firewall service stopped");
    0
}
