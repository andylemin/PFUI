//! The PF child. The pf pledge promise permits none of DIOCRADDADDRS,
//! DIOCRDELADDRS or DIOCRGETADDRS, and no promise set can, so under CTL: IOCTL
//! a child forked before the parent pledges holds /dev/pf alone and runs each
//! ioctl on the parent's behalf over a socketpair. The child cannot pledge
//! either; it unveils the filesystem away and does nothing but read one
//! request, run one ioctl and write one reply.

use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use super::ioctl::{OpenedPf, PfDev};
use super::structs::{PfiocTable, PfrAddr};
use super::PfError;

/// Most addresses one request or reply may carry: 52 MiB of pfr_addr.
pub const MAX_ADDRS: usize = 1 << 20;

/// Request: cmd u64, count u32, reserved u32, then pfioc_table, then count
/// pfr_addr. Reply: status u32, errno i32, count u32, reserved u32, then
/// pfioc_table, then count pfr_addr.
const HEAD: usize = 16;

const OK: u32 = 0;
const OPEN_FAILED: u32 = 1;
const IOCTL_FAILED: u32 = 2;
const REFUSED: u32 = 3;

/// The child's end never times out: it blocks on the parent for its whole
/// life. The parent's end does, so a child that has died cannot wedge a worker.
const PARENT_TIMEOUT: Duration = Duration::from_secs(10);

fn io_bytes(io: &PfiocTable) -> &[u8] {
    // repr(C) and built zeroed, so every byte is initialised
    unsafe {
        std::slice::from_raw_parts(
            io as *const PfiocTable as *const u8,
            std::mem::size_of::<PfiocTable>(),
        )
    }
}

fn io_bytes_mut(io: &mut PfiocTable) -> &mut [u8] {
    unsafe {
        std::slice::from_raw_parts_mut(
            io as *mut PfiocTable as *mut u8,
            std::mem::size_of::<PfiocTable>(),
        )
    }
}

fn addr_bytes(buf: &[PfrAddr]) -> &[u8] {
    unsafe { std::slice::from_raw_parts(buf.as_ptr() as *const u8, std::mem::size_of_val(buf)) }
}

fn addr_bytes_mut(buf: &mut [PfrAddr]) -> &mut [u8] {
    unsafe {
        std::slice::from_raw_parts_mut(buf.as_mut_ptr() as *mut u8, std::mem::size_of_val(buf))
    }
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}

/// The parent's side: a PfDev whose calls run in the child.
pub struct PfProxy {
    sock: UnixStream,
}

/// Fork the child. Must run before any thread exists and before the sandbox:
/// the child inherits neither, and the parent's pledge will not permit fork.
pub fn spawn(devpf: &Path) -> io::Result<PfProxy> {
    let (parent, child) = UnixStream::pair()?;
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => {
            drop(parent);
            child_main(devpf, child)
        }
        _ => {
            drop(child);
            parent.set_read_timeout(Some(PARENT_TIMEOUT))?;
            parent.set_write_timeout(Some(PARENT_TIMEOUT))?;
            Ok(PfProxy { sock: parent })
        }
    }
}

fn child_main(devpf: &Path, sock: UnixStream) -> ! {
    // rc.d stops the parent; this process ends when the socket does
    unsafe {
        libc::signal(libc::SIGTERM, libc::SIG_IGN);
        libc::signal(libc::SIGINT, libc::SIG_IGN);
        libc::signal(libc::SIGHUP, libc::SIG_IGN);
    }
    let opened = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(devpf);
    let locked = crate::platform::child_lockdown();
    let code = match (opened, locked) {
        (Ok(file), Ok(())) => match serve(&mut OpenedPf(file), sock) {
            Ok(()) => 0,
            Err(_) => 1,
        },
        // Every request is answered with the open failure, so the parent's
        // probe reports it with its guidance
        (Err(e), _) => match serve(&mut Unopened(e.raw_os_error()), sock) {
            Ok(()) => 0,
            Err(_) => 1,
        },
        (_, Err(_)) => 2,
    };
    std::process::exit(code)
}

/// /dev/pf could not be opened; every call says so.
pub struct Unopened(pub Option<i32>);

impl PfDev for Unopened {
    fn call(
        &mut self,
        _cmd: u64,
        _io: &mut PfiocTable,
        _buf: &mut [PfrAddr],
    ) -> Result<(), PfError> {
        Err(PfError::Dev {
            errno: os_error(self.0),
            raw: self.0,
        })
    }
}

fn os_error(raw: Option<i32>) -> String {
    match raw {
        Some(code) => io::Error::from_raw_os_error(code).to_string(),
        None => "unknown error".to_string(),
    }
}

/// The child's loop: one request, one ioctl, one reply, until the parent's end
/// closes. Generic over PfDev so it is testable without a fork or a kernel.
pub fn serve(dev: &mut impl PfDev, mut sock: UnixStream) -> io::Result<()> {
    loop {
        let mut head = [0u8; HEAD];
        match sock.read_exact(&mut head) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let cmd = u64::from_le_bytes(head[0..8].try_into().unwrap());
        let count = u32_at(&head, 8) as usize;
        let mut io: PfiocTable = unsafe { std::mem::zeroed() };
        sock.read_exact(io_bytes_mut(&mut io))?;
        if count > MAX_ADDRS {
            // The parent enforces the ceiling too; a request past it is not
            // the parent's, and nothing more is read from this socket
            reply(&mut sock, REFUSED, 0, &io, &[])?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request over MAX_ADDRS",
            ));
        }
        let mut buf = vec![PfrAddr::zeroed(); count];
        sock.read_exact(addr_bytes_mut(&mut buf))?;

        let (status, errno) = match dev.call(cmd, &mut io, &mut buf) {
            Ok(()) => (OK, 0),
            Err(PfError::Dev { raw, .. }) => (OPEN_FAILED, raw.unwrap_or(0)),
            Err(PfError::Ioctl { raw, .. }) => (IOCTL_FAILED, raw.unwrap_or(0)),
            Err(_) => (REFUSED, 0),
        };
        reply(&mut sock, status, errno, &io, &buf)?;
    }
}

fn reply(
    sock: &mut UnixStream,
    status: u32,
    errno: i32,
    io: &PfiocTable,
    buf: &[PfrAddr],
) -> io::Result<()> {
    let mut out =
        Vec::with_capacity(HEAD + std::mem::size_of::<PfiocTable>() + addr_bytes(buf).len());
    out.extend_from_slice(&status.to_le_bytes());
    out.extend_from_slice(&errno.to_le_bytes());
    out.extend_from_slice(&(buf.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(io_bytes(io));
    out.extend_from_slice(addr_bytes(buf));
    sock.write_all(&out)
}

impl PfDev for PfProxy {
    fn call(&mut self, cmd: u64, io: &mut PfiocTable, buf: &mut [PfrAddr]) -> Result<(), PfError> {
        if buf.len() > MAX_ADDRS {
            return Err(PfError::Child(format!(
                "{} addresses exceeds the ceiling of {MAX_ADDRS}",
                buf.len()
            )));
        }
        let gone = |e: io::Error| PfError::Child(format!("PF child unreachable: {e}"));

        let mut req =
            Vec::with_capacity(HEAD + std::mem::size_of::<PfiocTable>() + addr_bytes(buf).len());
        req.extend_from_slice(&cmd.to_le_bytes());
        req.extend_from_slice(&(buf.len() as u32).to_le_bytes());
        req.extend_from_slice(&[0u8; 4]);
        req.extend_from_slice(io_bytes(io));
        req.extend_from_slice(addr_bytes(buf));
        self.sock.write_all(&req).map_err(gone)?;

        let mut head = [0u8; HEAD];
        self.sock.read_exact(&mut head).map_err(gone)?;
        let status = u32_at(&head, 0);
        let errno = i32::from_le_bytes(head[4..8].try_into().unwrap());
        let count = u32_at(&head, 8) as usize;
        if count != buf.len() {
            return Err(PfError::Child(format!(
                "reply carries {count} addresses for a request of {}",
                buf.len()
            )));
        }
        // The child's buffer pointer means nothing here; the counters are read
        let buffer = io.pfrio_buffer;
        self.sock.read_exact(io_bytes_mut(io)).map_err(gone)?;
        io.pfrio_buffer = buffer;
        self.sock.read_exact(addr_bytes_mut(buf)).map_err(gone)?;

        match status {
            OK => Ok(()),
            OPEN_FAILED => Err(PfError::Dev {
                errno: os_error(Some(errno)),
                raw: Some(errno),
            }),
            IOCTL_FAILED => Err(PfError::Ioctl {
                cmd,
                errno: os_error(Some(errno)),
                raw: Some(errno),
            }),
            _ => Err(PfError::Child("the child refused the request".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pf::ioctl::{table_add, table_del, table_get};
    use crate::pf::structs::{ip_of, pfr_addr_of, DIOCRADDADDRS, DIOCRDELADDRS, DIOCRGETADDRS};
    use std::net::IpAddr;

    /// A kernel-shaped fake on the child's side of the socket.
    struct FakeKernel {
        table: Vec<IpAddr>,
        fail_with: Option<i32>,
    }

    impl PfDev for FakeKernel {
        fn call(
            &mut self,
            cmd: u64,
            io: &mut PfiocTable,
            buf: &mut [PfrAddr],
        ) -> Result<(), PfError> {
            if let Some(raw) = self.fail_with {
                return Err(PfError::Ioctl {
                    cmd,
                    errno: "fake".into(),
                    raw: Some(raw),
                });
            }
            match cmd {
                DIOCRADDADDRS => {
                    let mut added = 0;
                    for a in buf.iter() {
                        let ip = ip_of(a).unwrap();
                        if !self.table.contains(&ip) {
                            self.table.push(ip);
                            added += 1;
                        }
                    }
                    io.pfrio_nadd = added;
                }
                DIOCRDELADDRS => {
                    let mut deleted = 0;
                    for a in buf.iter() {
                        let ip = ip_of(a).unwrap();
                        if let Some(pos) = self.table.iter().position(|t| *t == ip) {
                            self.table.remove(pos);
                            deleted += 1;
                        }
                    }
                    io.pfrio_ndel = deleted;
                }
                DIOCRGETADDRS => {
                    io.pfrio_size = self.table.len() as i32;
                    for (slot, ip) in buf.iter_mut().zip(&self.table) {
                        *slot = pfr_addr_of(ip);
                    }
                }
                _ => unreachable!(),
            }
            Ok(())
        }
    }

    fn pair(kernel: FakeKernel) -> (PfProxy, std::thread::JoinHandle<io::Result<()>>) {
        let (parent, child) = UnixStream::pair().unwrap();
        let handle = std::thread::spawn(move || {
            let mut kernel = kernel;
            serve(&mut kernel, child)
        });
        (PfProxy { sock: parent }, handle)
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn calls_round_trip_through_the_child() {
        let (mut proxy, child) = pair(FakeKernel {
            table: Vec::new(),
            fail_with: None,
        });
        assert_eq!(
            table_add(&mut proxy, "t", &ips(&["8.8.8.8", "2001:db8::1"])).unwrap(),
            2
        );
        assert_eq!(
            table_get(&mut proxy, "t").unwrap(),
            ips(&["8.8.8.8", "2001:db8::1"])
        );
        assert_eq!(table_del(&mut proxy, "t", &ips(&["8.8.8.8"])).unwrap(), 1);
        assert_eq!(table_get(&mut proxy, "t").unwrap(), ips(&["2001:db8::1"]));
        drop(proxy);
        assert!(
            child.join().unwrap().is_ok(),
            "the child must end cleanly at EOF"
        );
    }

    #[test]
    fn an_ioctl_error_crosses_with_its_errno() {
        let (mut proxy, child) = pair(FakeKernel {
            table: Vec::new(),
            fail_with: Some(libc::ESRCH),
        });
        let err = table_add(&mut proxy, "t", &ips(&["8.8.8.8"])).unwrap_err();
        assert!(
            matches!(
                err,
                PfError::Ioctl {
                    raw: Some(libc::ESRCH),
                    ..
                }
            ),
            "{err:?}"
        );
        // Composed on the parent's side from the errno alone
        assert!(err.to_string().contains("not in the loaded ruleset"));
        drop(proxy);
        child.join().unwrap().unwrap();
    }

    #[test]
    fn an_unopened_device_is_reported_on_every_call() {
        let (parent, child_sock) = UnixStream::pair().unwrap();
        let child =
            std::thread::spawn(move || serve(&mut Unopened(Some(libc::EACCES)), child_sock));
        let mut proxy = PfProxy { sock: parent };
        let err = table_get(&mut proxy, "t").unwrap_err();
        assert!(
            matches!(
                err,
                PfError::Dev {
                    raw: Some(libc::EACCES),
                    ..
                }
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("mode 660"), "{err}");
        drop(proxy);
        child.join().unwrap().unwrap();
    }

    #[test]
    fn a_dead_child_is_an_error_not_a_hang() {
        let (parent, child_sock) = UnixStream::pair().unwrap();
        drop(child_sock);
        let mut proxy = PfProxy { sock: parent };
        let err = table_get(&mut proxy, "t").unwrap_err();
        assert!(matches!(err, PfError::Child(_)), "{err:?}");
    }

    #[test]
    fn the_ceiling_is_enforced_on_both_sides() {
        let (mut proxy, child) = pair(FakeKernel {
            table: Vec::new(),
            fail_with: None,
        });
        let mut io: PfiocTable = unsafe { std::mem::zeroed() };
        let mut too_many = vec![PfrAddr::zeroed(); MAX_ADDRS + 1];
        assert!(matches!(
            proxy.call(DIOCRADDADDRS, &mut io, &mut too_many),
            Err(PfError::Child(_))
        ));
        // Rejected before the send, so the child is still serving
        assert_eq!(table_get(&mut proxy, "t").unwrap(), Vec::<IpAddr>::new());
        drop(proxy);
        child.join().unwrap().unwrap();
    }
}
