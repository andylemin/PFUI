//! PF table ioctls: DIOCRADDADDRS, DIOCRDELADDRS and DIOCRGETADDRS.
//!
//! The call logic is generic over PfDev so the sizing and retry behaviour can
//! be tested on any platform; only the raw ioctl on /dev/pf is OpenBSD code.

use std::net::IpAddr;
use std::path::Path;

use super::structs::{
    ip_of, pfr_addr_of, PfiocTable, PfrAddr, PfrTable, DIOCRADDADDRS, DIOCRDELADDRS, DIOCRGETADDRS,
};
use super::PfError;

/// One raw table ioctl. The implementation wires `buf` into io.pfrio_buffer;
/// a fake fills `buf` and the counters instead.
pub trait PfDev {
    fn call(&mut self, cmd: u64, io: &mut PfiocTable, buf: &mut [PfrAddr]) -> Result<(), PfError>;
}

fn io_for(table: &str, size: usize) -> Result<PfiocTable, PfError> {
    let table = PfrTable::named(table).ok_or(PfError::TableName)?;
    Ok(PfiocTable {
        pfrio_table: table,
        pfrio_buffer: std::ptr::null_mut(),
        pfrio_esize: std::mem::size_of::<PfrAddr>() as i32,
        pfrio_size: size as i32,
        pfrio_size2: 0,
        pfrio_nadd: 0,
        pfrio_ndel: 0,
        pfrio_nchange: 0,
        pfrio_flags: 0,
        pfrio_ticket: 0,
    })
}

/// Install addresses; returns the kernel's count of effective additions.
pub fn table_add(dev: &mut impl PfDev, table: &str, ips: &[IpAddr]) -> Result<usize, PfError> {
    let mut buf: Vec<PfrAddr> = ips.iter().map(pfr_addr_of).collect();
    let mut io = io_for(table, buf.len())?;
    dev.call(DIOCRADDADDRS, &mut io, &mut buf)?;
    Ok(io.pfrio_nadd.max(0) as usize)
}

/// Remove addresses; returns the kernel's count of effective deletions. nadd
/// and ndel are separate fields, and only ndel counts deletions.
pub fn table_del(dev: &mut impl PfDev, table: &str, ips: &[IpAddr]) -> Result<usize, PfError> {
    let mut buf: Vec<PfrAddr> = ips.iter().map(pfr_addr_of).collect();
    let mut io = io_for(table, buf.len())?;
    dev.call(DIOCRDELADDRS, &mut io, &mut buf)?;
    Ok(io.pfrio_ndel.max(0) as usize)
}

/// Read the whole table, in canonical spelling.
///
/// Two-call protocol: size 0 asks the kernel for the count, the second call
/// fills a buffer of that size. A table that grew between the calls is
/// retried, bounded so a hot table cannot livelock the scan.
pub fn table_get(dev: &mut impl PfDev, table: &str) -> Result<Vec<IpAddr>, PfError> {
    let mut io = io_for(table, 0)?;
    let mut empty: [PfrAddr; 0] = [];
    dev.call(DIOCRGETADDRS, &mut io, &mut empty)?;
    let mut want = io.pfrio_size.max(0) as usize;

    for _ in 0..3 {
        if want == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![PfrAddr::zeroed(); want];
        let mut io = io_for(table, want)?;
        dev.call(DIOCRGETADDRS, &mut io, &mut buf)?;
        let got = io.pfrio_size.max(0) as usize;
        if got <= want {
            return Ok(buf[..got].iter().filter_map(ip_of).collect());
        }
        want = got;
    }
    Err(PfError::Unstable)
}

/// The real /dev/pf, opened per call; it is not a contended resource at these
/// rates.
pub struct DevPf<'a>(pub &'a Path);

#[cfg(target_os = "openbsd")]
impl PfDev for DevPf<'_> {
    fn call(&mut self, cmd: u64, io: &mut PfiocTable, buf: &mut [PfrAddr]) -> Result<(), PfError> {
        use std::os::fd::AsRawFd;
        let dev = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.0)
            .map_err(|e| PfError::Dev(e.to_string()))?;
        if !buf.is_empty() {
            io.pfrio_buffer = buf.as_mut_ptr() as *mut std::ffi::c_void;
        }
        let rc = unsafe { libc::ioctl(dev.as_raw_fd(), cmd as libc::c_ulong, io as *mut _) };
        if rc == -1 {
            let err = std::io::Error::last_os_error();
            return Err(PfError::Ioctl {
                cmd,
                errno: err.to_string(),
                raw: err.raw_os_error(),
            });
        }
        Ok(())
    }
}

#[cfg(not(target_os = "openbsd"))]
impl PfDev for DevPf<'_> {
    fn call(
        &mut self,
        _cmd: u64,
        _io: &mut PfiocTable,
        _buf: &mut [PfrAddr],
    ) -> Result<(), PfError> {
        Err(PfError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A kernel-shaped fake holding a set of addresses.
    struct FakeKernel {
        table: Vec<IpAddr>,
        grow_once: Option<IpAddr>,
        fail: bool,
    }

    impl PfDev for FakeKernel {
        fn call(
            &mut self,
            cmd: u64,
            io: &mut PfiocTable,
            buf: &mut [PfrAddr],
        ) -> Result<(), PfError> {
            if self.fail {
                return Err(PfError::Ioctl {
                    cmd,
                    errno: "EPERM".into(),
                    raw: Some(libc::EPERM),
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
                    if buf.is_empty() {
                        if let Some(extra) = self.grow_once.take() {
                            // Report the pre-growth count, then grow: the
                            // second call sees more than was allocated
                            io.pfrio_size = self.table.len() as i32;
                            self.table.push(extra);
                            return Ok(());
                        }
                        io.pfrio_size = self.table.len() as i32;
                    } else {
                        io.pfrio_size = self.table.len() as i32;
                        for (slot, ip) in buf.iter_mut().zip(&self.table) {
                            *slot = pfr_addr_of(ip);
                        }
                    }
                }
                _ => unreachable!(),
            }
            Ok(())
        }
    }

    fn ips(list: &[&str]) -> Vec<IpAddr> {
        list.iter().map(|s| s.parse().unwrap()).collect()
    }

    #[test]
    fn add_then_delete_reports_counts() {
        let mut kernel = FakeKernel {
            table: Vec::new(),
            grow_once: None,
            fail: false,
        };
        assert_eq!(
            table_add(&mut kernel, "t", &ips(&["8.8.8.8", "1.1.1.1"])).unwrap(),
            2
        );
        // Re-adding an existing entry is not an effective addition
        assert_eq!(table_add(&mut kernel, "t", &ips(&["8.8.8.8"])).unwrap(), 0);
        assert_eq!(table_del(&mut kernel, "t", &ips(&["8.8.8.8"])).unwrap(), 1);
        assert_eq!(table_del(&mut kernel, "t", &ips(&["9.9.9.9"])).unwrap(), 0);
    }

    #[test]
    fn ipv6_addresses_are_accepted() {
        let mut kernel = FakeKernel {
            table: Vec::new(),
            grow_once: None,
            fail: false,
        };
        let v6 = ips(&["2001:4860:4860::8888"]);
        assert_eq!(table_add(&mut kernel, "t6", &v6).unwrap(), 1);
        assert_eq!(table_get(&mut kernel, "t6").unwrap(), v6);
    }

    #[test]
    fn get_reads_the_whole_table() {
        let mut kernel = FakeKernel {
            table: ips(&["8.8.8.8", "2001:db8::1"]),
            grow_once: None,
            fail: false,
        };
        assert_eq!(
            table_get(&mut kernel, "t").unwrap(),
            ips(&["8.8.8.8", "2001:db8::1"])
        );
    }

    #[test]
    fn get_of_an_empty_table_is_empty() {
        let mut kernel = FakeKernel {
            table: Vec::new(),
            grow_once: None,
            fail: false,
        };
        assert!(table_get(&mut kernel, "t").unwrap().is_empty());
    }

    #[test]
    fn get_retries_when_the_table_grows_between_calls() {
        let mut kernel = FakeKernel {
            table: ips(&["8.8.8.8"]),
            grow_once: Some("1.1.1.1".parse().unwrap()),
            fail: false,
        };
        assert_eq!(
            table_get(&mut kernel, "t").unwrap(),
            ips(&["8.8.8.8", "1.1.1.1"])
        );
    }

    #[test]
    fn oversize_table_name_is_a_named_error() {
        let mut kernel = FakeKernel {
            table: Vec::new(),
            grow_once: None,
            fail: false,
        };
        assert!(matches!(
            table_add(&mut kernel, &"x".repeat(40), &ips(&["8.8.8.8"])),
            Err(PfError::TableName)
        ));
    }

    #[test]
    fn ioctl_failure_propagates() {
        let mut kernel = FakeKernel {
            table: Vec::new(),
            grow_once: None,
            fail: true,
        };
        assert!(table_add(&mut kernel, "t", &ips(&["8.8.8.8"])).is_err());
    }
}
