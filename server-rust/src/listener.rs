//! Listeners and the worker pool: one accept or recv thread per listener, a
//! shared bounded pool, and shedding beyond twice MAX_WORKERS.

use std::io;
use std::net::{Ipv4Addr, TcpListener, UdpSocket};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::config::Config;
use crate::logger::Logger;
use crate::receiver::{self, Ctx, Job, StreamKind};

/// Hard ceiling on a PFUI message over UDP. A datagram above the link MTU
/// fragments and PF commonly drops fragments, so raising this does not help;
/// the fix for a real deployment is TCP.
pub const UDP_DGRAM_CEILING: usize = 1400;

/// Mode the local socket ends up with, and the umask that gets it there
/// without it ever being briefly wider. Not configurable: the socket is the
/// whole access control for a local resolver.
pub const UNIX_SOCKET_MODE: u32 = 0o660;
pub const UNIX_SOCKET_UMASK: libc::mode_t = 0o177;

// ---------------------------------------------------------------- helpers

fn errno() -> io::Error {
    io::Error::last_os_error()
}

fn check(rc: i32) -> io::Result<()> {
    if rc == -1 {
        Err(errno())
    } else {
        Ok(())
    }
}

fn set_reuseaddr(fd: RawFd) -> io::Result<()> {
    let one: libc::c_int = 1;
    check(unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    })
}

/// Block at most `timeout` until the fd is readable, so every accept loop
/// wakes to re-check the term flag.
fn readable(fd: RawFd, timeout: Duration) -> io::Result<bool> {
    let mut pfd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = timeout.as_millis().min(i32::MAX as u128) as libc::c_int;
    loop {
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc >= 0 {
            return Ok(rc > 0);
        }
        let e = errno();
        if e.raw_os_error() != Some(libc::EINTR) {
            return Err(e);
        }
    }
}

// ------------------------------------------------------------------ binds

/// TCP listener with SO_REUSEADDR, TCP_NODELAY and the configured backlog,
/// which std's bind cannot set.
pub fn bind_tcp(listen: &str, port: u16, backlog: i32) -> io::Result<TcpListener> {
    let addr: Ipv4Addr = listen.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKET_LISTEN is not an IPv4 address",
        )
    })?;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    check(fd)?;
    let listener = unsafe { TcpListener::from_raw_fd(fd) };
    set_reuseaddr(fd)?;
    let one: libc::c_int = 1;
    check(unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_NODELAY,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    })?;
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(addr).to_be(),
        },
        sin_zero: [0; 8],
        #[cfg(any(target_os = "openbsd", target_os = "macos"))]
        sin_len: 0,
    };
    check(unsafe {
        libc::bind(
            fd,
            &sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    })?;
    check(unsafe { libc::listen(fd, backlog) })?;
    listener.set_nonblocking(true)?;
    Ok(listener)
}

/// UDP socket with SO_REUSEADDR and a read timeout for TERM responsiveness.
pub fn bind_udp(listen: &str, port: u16, timeout: Duration) -> io::Result<UdpSocket> {
    let addr: Ipv4Addr = listen.parse().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "SOCKET_LISTEN is not an IPv4 address",
        )
    })?;
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    check(fd)?;
    let socket = unsafe { UdpSocket::from_raw_fd(fd) };
    set_reuseaddr(fd)?;
    let sin = libc::sockaddr_in {
        sin_family: libc::AF_INET as libc::sa_family_t,
        sin_port: port.to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from(addr).to_be(),
        },
        sin_zero: [0; 8],
        #[cfg(any(target_os = "openbsd", target_os = "macos"))]
        sin_len: 0,
    };
    check(unsafe {
        libc::bind(
            fd,
            &sin as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    })?;
    socket.set_read_timeout(Some(timeout))?;
    Ok(socket)
}

/// A refused unix bind. The filesystem is the whole access control on this
/// transport, so every step fails closed.
#[derive(Debug)]
pub struct BindRefused(pub String);

impl std::fmt::Display for BindRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

fn refuse<T>(msg: String) -> Result<T, BindRefused> {
    Err(BindRefused(msg))
}

fn gid_of(group: &str) -> Option<libc::gid_t> {
    let name = std::ffi::CString::new(group).ok()?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0u8; 4096];
    let mut result: *mut libc::group = std::ptr::null_mut();
    let rc = unsafe {
        libc::getgrnam_r(
            name.as_ptr(),
            &mut grp,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc == 0 && !result.is_null() {
        Some(grp.gr_gid)
    } else {
        None
    }
}

/// Remove a socket node left by an unclean stop, but only once a probe shows
/// nothing answers on it: unlinking a live daemon's socket would leave it
/// running and unreachable.
fn reclaim_stale(path: &Path, log: &Logger) -> Result<(), BindRefused> {
    if !path.exists() {
        return Ok(());
    }
    match UnixStream::connect(path) {
        Ok(_) => refuse(format!(
            "Another PFUI_Firewall is already listening on {}",
            path.display()
        )),
        Err(e)
            if e.kind() == io::ErrorKind::ConnectionRefused
                || e.kind() == io::ErrorKind::NotFound =>
        {
            log.info(&format!("Removing stale socket {}", path.display()));
            std::fs::remove_file(path)
                .map_err(|e| BindRefused(format!("cannot remove stale {}: {e}", path.display())))
        }
        Err(e) => refuse(format!(
            "{} exists and cannot be tested ({e}); remove it by hand if no \
             PFUI_Firewall is running",
            path.display()
        )),
    }
}

/// Bind the local stream listener, failing closed at every step: the parent
/// must exist and not be world-writable without sticky, a stale node is
/// reclaimed only after a probe, the node is created inside an 0177 umask
/// window, and the group grant is verified by a re-stat before serving.
pub fn bind_unix(
    path: &Path,
    group: &str,
    backlog: i32,
    log: &Logger,
) -> Result<UnixListener, BindRefused> {
    use std::os::unix::fs::PermissionsExt;

    let parent = path.parent().filter(|p| !p.as_os_str().is_empty());
    let parent = parent.unwrap_or_else(|| Path::new("/"));
    let parent_meta = match std::fs::metadata(parent) {
        Ok(m) if m.is_dir() => m,
        _ => {
            return refuse(format!(
                "SOCKET_UNIX directory {} does not exist; rc.d/pfui_firewall \
                 creates it on start",
                parent.display()
            ))
        }
    };
    let parent_mode = parent_meta.permissions().mode();
    // Otherwise the socket can be replaced and the replacement handed the
    // resolver's messages, whatever mode the socket itself has
    if parent_mode & 0o002 != 0 && parent_mode & 0o1000 == 0 {
        return refuse(format!(
            "SOCKET_UNIX directory {} is world-writable ({:o}); refusing to bind there",
            parent.display(),
            parent_mode & 0o7777
        ));
    }

    reclaim_stale(path, log)?;

    // bind() creates the node with the process umask, narrowed here rather
    // than fixed by a chmod afterwards, which would leave the socket
    // connectable by everyone in between
    let previous = unsafe { libc::umask(UNIX_SOCKET_UMASK) };
    let bound = UnixListener::bind(path);
    unsafe { libc::umask(previous) };
    let listener = match bound {
        Ok(l) => l,
        Err(e) => return refuse(format!("cannot bind {}: {e}", path.display())),
    };

    let granted = (|| -> Result<(), String> {
        let gid = gid_of(group).ok_or_else(|| format!("group {group} does not exist"))?;
        let cpath = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| "socket path contains NUL".to_string())?;
        if unsafe { libc::chown(cpath.as_ptr(), u32::MAX, gid) } == -1 {
            return Err(format!("chown to {group} failed: {}", errno()));
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(UNIX_SOCKET_MODE))
            .map_err(|e| format!("chmod failed: {e}"))?;
        let mode = std::fs::metadata(path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o7777;
        if mode != UNIX_SOCKET_MODE {
            return Err(format!(
                "socket is mode {mode:o}, expected {UNIX_SOCKET_MODE:o}"
            ));
        }
        Ok(())
    })();
    if let Err(reason) = granted {
        // A refused start must not leave a node for the next start to reclaim
        let _ = std::fs::remove_file(path);
        return refuse(format!(
            "cannot restrict {} to group {group}: {reason}; refusing to serve on it",
            path.display()
        ));
    }

    if unsafe { libc::listen(listener.as_raw_fd(), backlog) } == -1 {
        let e = errno();
        let _ = std::fs::remove_file(path);
        return refuse(format!("listen on {} failed: {e}", path.display()));
    }
    listener
        .set_nonblocking(true)
        .map_err(|e| BindRefused(format!("cannot set nonblocking: {e}")))?;
    log.info(&format!(
        "[+] Listening on UNIX {} (group {group}, mode {UNIX_SOCKET_MODE:o})",
        path.display()
    ));
    Ok(listener)
}

/// Unlink our own socket on the way out, so the next start is clean.
pub fn remove_unix_socket(path: &Path) {
    let _ = std::fs::remove_file(path);
}

// ------------------------------------------------------------ worker pool

/// MAX_WORKERS threads plus a MAX_WORKERS-deep queue, so at most twice
/// MAX_WORKERS jobs are in flight and anything beyond is shed rather than
/// queued without limit. PF still denies a shed sender's traffic, and the
/// resolver sees a socket failure rather than a stall.
pub struct WorkerPool {
    tx: Option<SyncSender<Job>>,
    workers: Vec<std::thread::JoinHandle<()>>,
    pub max_inflight: usize,
}

#[derive(Clone)]
pub struct Submitter {
    tx: SyncSender<Job>,
    pub max_inflight: usize,
}

impl WorkerPool {
    pub fn start(ctx: Arc<Ctx>) -> Self {
        let workers_n = ctx.cfg.max_workers;
        let (tx, rx) = sync_channel::<Job>(workers_n);
        let rx = Arc::new(Mutex::new(rx));
        let workers = (0..workers_n)
            .map(|_| {
                let rx: Arc<Mutex<Receiver<Job>>> = Arc::clone(&rx);
                let ctx = Arc::clone(&ctx);
                std::thread::spawn(move || loop {
                    let job = {
                        let guard = rx.lock().unwrap();
                        guard.recv()
                    };
                    match job {
                        // Contained per job: a panic here used to unwind the
                        // whole worker, so a repeatable fault retired the pool
                        // one thread at a time until every message was shed and
                        // nothing was whitelisted at all. The lock is released
                        // above, so the channel cannot be poisoned by this.
                        Ok(job) => {
                            let run = std::panic::AssertUnwindSafe(|| receiver::handle(job, &ctx));
                            if let Err(panic) = std::panic::catch_unwind(run) {
                                ctx.log.error(&format!(
                                    "worker panicked handling a message, \
                                     continuing: {}",
                                    panic_text(&panic)
                                ));
                            }
                        }
                        Err(_) => return, // sender dropped: shutdown
                    }
                })
            })
            .collect();
        WorkerPool {
            tx: Some(tx),
            workers,
            max_inflight: workers_n * 2,
        }
    }

    pub fn submitter(&self) -> Submitter {
        Submitter {
            tx: self.tx.clone().expect("pool running"),
            max_inflight: self.max_inflight,
        }
    }

    /// Drop the sender and drain: workers finish queued jobs and exit.
    pub fn shutdown(mut self) {
        self.tx = None;
        for w in self.workers.drain(..) {
            let _ = w.join();
        }
    }
}

/// What a panic payload says, when it says anything.
fn panic_text(panic: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = panic.downcast_ref::<&str>() {
        (*s).to_string()
    } else if let Some(s) = panic.downcast_ref::<String>() {
        s.clone()
    } else {
        "no message".to_string()
    }
}

/// The outcome of offering one job to the pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Submitted {
    Accepted,
    /// Queue and workers all busy.
    Shed,
    /// The pool is gone, so nothing will run this job or any later one.
    PoolStopped,
}

impl Submitter {
    pub fn try_submit(&self, job: Job) -> Submitted {
        match self.tx.try_send(job) {
            Ok(()) => Submitted::Accepted,
            Err(TrySendError::Full(_)) => Submitted::Shed,
            // Reported as success before, so a job dropped after shutdown looked
            // handled and the loop kept accepting work nothing would ever run
            Err(TrySendError::Disconnected(_)) => Submitted::PoolStopped,
        }
    }
}

// ------------------------------------------------------------ serve loops

pub enum StreamListener {
    Tcp(TcpListener),
    Unix(UnixListener, PathBuf),
}

impl StreamListener {
    fn fd(&self) -> RawFd {
        match self {
            StreamListener::Tcp(l) => l.as_raw_fd(),
            StreamListener::Unix(l, _) => l.as_raw_fd(),
        }
    }

    /// Accept and prepare one connection. Accepted sockets inherit nothing, so
    /// the timeouts are set here; TCP_NODELAY is TCP-only, since setting it on
    /// a unix socket errors.
    fn accept(&self, timeout: Duration) -> io::Result<(Box<dyn receiver::Stream>, String)> {
        match self {
            StreamListener::Tcp(l) => {
                let (conn, peer) = l.accept()?;
                conn.set_nonblocking(false)?;
                conn.set_read_timeout(Some(timeout))?;
                conn.set_write_timeout(Some(timeout))?;
                if let Err(e) = conn.set_nodelay(true) {
                    // Not fatal; costs latency, not correctness
                    return Ok((Box::new(conn), format!("{peer} (no NODELAY: {e})")));
                }
                Ok((Box::new(conn), peer.to_string()))
            }
            StreamListener::Unix(l, path) => {
                let (conn, _) = l.accept()?;
                conn.set_nonblocking(false)?;
                conn.set_read_timeout(Some(timeout))?;
                conn.set_write_timeout(Some(timeout))?;
                // accept() reports no peer on AF_UNIX, so the socket path
                // names the sender in the log
                Ok((Box::new(conn), path.display().to_string()))
            }
        }
    }

    fn kind(&self) -> StreamKind {
        match self {
            StreamListener::Tcp(_) => StreamKind::Tcp,
            StreamListener::Unix(..) => StreamKind::Unix,
        }
    }
}

/// Accept loop shared by the TCP and UNIX listeners; both carry the same
/// frames and replies, so only the peer naming differs.
pub fn serve_stream(
    listener: StreamListener,
    submit: Submitter,
    term: Arc<AtomicBool>,
    cfg: Arc<Config>,
    log: Arc<Logger>,
) {
    let timeout = Duration::from_secs_f64(cfg.socket_timeout.max(0.05));
    while !term.load(Ordering::Relaxed) {
        match readable(listener.fd(), timeout) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(e) => {
                log.error(&format!("poll on listener failed, continuing: {e}"));
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        }
        match listener.accept(timeout) {
            Ok((conn, peer)) => {
                let job = Job::Stream {
                    kind: listener.kind(),
                    conn,
                    peer: peer.clone(),
                };
                match submit.try_submit(job) {
                    Submitted::Accepted => {}
                    // Shed rather than queue; dropping the job closes the fd
                    Submitted::Shed => log.error(&format!(
                        "At capacity ({}), shedding {peer}",
                        submit.max_inflight
                    )),
                    Submitted::PoolStopped => {
                        log.error(&format!(
                            "Worker pool has stopped, dropping {peer} and \
                             closing this listener"
                        ));
                        return;
                    }
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => {
                // ECONNABORTED when a peer goes away, EMFILE or ENFILE under
                // fd pressure: neither is a reason to stop serving
                log.error(&format!("accept() failed, continuing: {e}"));
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Receive loop for the network datagram listener.
pub fn serve_udp(
    socket: Arc<UdpSocket>,
    submit: Submitter,
    term: Arc<AtomicBool>,
    log: Arc<Logger>,
) {
    // Reading one byte past the ceiling makes an oversize datagram detectable
    // rather than silently truncated
    let mut buf = vec![0u8; UDP_DGRAM_CEILING + 1];
    while !term.load(Ordering::Relaxed) {
        let (len, source) = match socket.recv_from(&mut buf) {
            Ok(r) => r,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock || e.kind() == io::ErrorKind::TimedOut =>
            {
                continue
            }
            Err(e) => {
                log.error(&format!("UDP recv failed, continuing: {e}"));
                std::thread::sleep(Duration::from_millis(500));
                continue;
            }
        };
        if len > UDP_DGRAM_CEILING {
            log.error(&format!(
                "Datagram from {source} exceeds the {UDP_DGRAM_CEILING} byte UDP \
                 ceiling ({len}+ bytes); dropping. This answer cannot be \
                 whitelisted over UDP - switch SOCKET_PROTO to TCP."
            ));
            continue;
        }
        if len == 0 {
            continue;
        }
        let job = Job::Datagram {
            data: buf[..len].to_vec(),
            source,
        };
        match submit.try_submit(job) {
            Submitted::Accepted => {}
            Submitted::Shed => log.error(&format!(
                "At capacity ({}), dropping {source}",
                submit.max_inflight
            )),
            Submitted::PoolStopped => {
                log.error(&format!(
                    "Worker pool has stopped, dropping {source} and closing \
                     this listener"
                ));
                return;
            }
        }
    }
}
