//! #[repr(C)] mirrors of the OpenBSD net/pfvar.h structures the table ioctls
//! use. Layout drift would corrupt every call silently, since pfrio_esize
//! tells the kernel how to read the buffer, so the sizes are pinned by tests.

use std::net::IpAddr;

pub const PATH_MAX: usize = 1024;
pub const PF_TABLE_NAME_SIZE: usize = 32;
pub const IFNAMSIZ: usize = 16;
pub const PFRKE_PLAIN: u8 = 0;

#[repr(C)]
pub struct PfrTable {
    pub pfrt_anchor: [u8; PATH_MAX],
    pub pfrt_name: [u8; PF_TABLE_NAME_SIZE],
    pub pfrt_flags: u32,
    pub pfrt_fback: u8,
}

#[repr(C)]
pub struct PfiocTable {
    pub pfrio_table: PfrTable,
    pub pfrio_buffer: *mut std::ffi::c_void,
    pub pfrio_esize: i32,
    pub pfrio_size: i32,
    pub pfrio_size2: i32,
    pub pfrio_nadd: i32,
    pub pfrio_ndel: i32,
    pub pfrio_nchange: i32,
    pub pfrio_flags: i32,
    pub pfrio_ticket: u32,
}

/// The address union is a plain 16-byte buffer: an IPv4 address occupies the
/// first 4 bytes, IPv6 all 16, exactly as the kernel reads them.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PfrAddr {
    pub pfra_u: [u8; 16],
    pub pfra_ifname: [u8; IFNAMSIZ],
    pub pfra_states: u32,
    pub pfra_weight: u16,
    pub pfra_af: u8,
    pub pfra_net: u8,
    pub pfra_not: u8,
    pub pfra_fback: u8,
    pub pfra_type: u8,
    pub pad: [u8; 7],
}

impl PfrTable {
    /// Zeroed table header naming `table`; None if the name cannot fit
    /// PF_TABLE_NAME_SIZE including its terminator.
    pub fn named(table: &str) -> Option<Self> {
        let bytes = table.as_bytes();
        if bytes.is_empty() || bytes.len() >= PF_TABLE_NAME_SIZE {
            return None;
        }
        let mut t = PfrTable {
            pfrt_anchor: [0; PATH_MAX],
            pfrt_name: [0; PF_TABLE_NAME_SIZE],
            pfrt_flags: 0,
            pfrt_fback: 0,
        };
        t.pfrt_name[..bytes.len()].copy_from_slice(bytes);
        Some(t)
    }
}

impl PfrAddr {
    pub fn zeroed() -> Self {
        PfrAddr {
            pfra_u: [0; 16],
            pfra_ifname: [0; IFNAMSIZ],
            pfra_states: 0,
            pfra_weight: 0,
            pfra_af: 0,
            pfra_net: 0,
            pfra_not: 0,
            pfra_fback: 0,
            pfra_type: PFRKE_PLAIN,
            pad: [0; 7],
        }
    }
}

/// A validated address as the kernel wants it: af, host-width net, plain type,
/// everything else zero.
pub fn pfr_addr_of(ip: &IpAddr) -> PfrAddr {
    let mut a = PfrAddr::zeroed();
    match ip {
        IpAddr::V4(v4) => {
            a.pfra_u[..4].copy_from_slice(&v4.octets());
            a.pfra_af = libc::AF_INET as u8;
            a.pfra_net = 32;
        }
        IpAddr::V6(v6) => {
            a.pfra_u.copy_from_slice(&v6.octets());
            a.pfra_af = libc::AF_INET6 as u8;
            a.pfra_net = 128;
        }
    }
    a
}

/// The address back out of a kernel-filled entry, canonicalised so table reads
/// agree with Redis keys.
pub fn ip_of(a: &PfrAddr) -> Option<IpAddr> {
    if a.pfra_af == libc::AF_INET as u8 {
        let mut o = [0u8; 4];
        o.copy_from_slice(&a.pfra_u[..4]);
        Some(IpAddr::from(o))
    } else if a.pfra_af == libc::AF_INET6 as u8 {
        Some(IpAddr::from(a.pfra_u))
    } else {
        None
    }
}

/// _IOWR('D', num, struct pfioc_table)
pub const fn iowr(group: u8, num: u8, len: usize) -> u64 {
    const IOC_INOUT: u64 = 0x8000_0000 | 0x4000_0000;
    const IOCPARM_MASK: u64 = 0x1fff;
    IOC_INOUT | (((len as u64) & IOCPARM_MASK) << 16) | ((group as u64) << 8) | num as u64
}

pub const DIOCRADDADDRS: u64 = iowr(b'D', 67, std::mem::size_of::<PfiocTable>());
pub const DIOCRDELADDRS: u64 = iowr(b'D', 68, std::mem::size_of::<PfiocTable>());
pub const DIOCRGETADDRS: u64 = iowr(b'D', 70, std::mem::size_of::<PfiocTable>());

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn struct_sizes_are_stable() {
        // Verified against net/pfvar.h on OpenBSD 7.9 amd64
        assert_eq!(size_of::<PfrAddr>(), 52);
        assert_eq!(size_of::<PfrTable>(), 1064);
        assert_eq!(size_of::<PfiocTable>(), 1104);
    }

    #[test]
    fn ioctl_command_numbers() {
        assert_eq!(DIOCRADDADDRS, 0xC450_4443);
        assert_eq!(DIOCRDELADDRS, 0xC450_4444);

        assert_eq!(DIOCRGETADDRS, 0xC450_4446);
    }

    #[test]
    fn addresses_round_trip_through_the_struct() {
        for addr in ["8.8.8.8", "2001:4860:4860::8888"] {
            let ip: IpAddr = addr.parse().unwrap();
            let a = pfr_addr_of(&ip);
            assert_eq!(ip_of(&a), Some(ip), "{addr}");
            assert_eq!(a.pfra_net, if ip.is_ipv4() { 32 } else { 128 });
            assert_eq!(a.pfra_type, PFRKE_PLAIN);
            assert_eq!(a.pfra_not, 0);
        }
    }

    #[test]
    fn v4_bytes_land_in_the_first_four() {
        let ip: IpAddr = "1.2.3.4".parse().unwrap();
        let a = pfr_addr_of(&ip);
        assert_eq!(&a.pfra_u[..4], &[1, 2, 3, 4]);
        assert_eq!(&a.pfra_u[4..], &[0; 12]);
    }

    #[test]
    fn table_name_must_fit_with_its_terminator() {
        assert!(PfrTable::named("pfui_ipv4_domains").is_some());
        assert!(PfrTable::named(&"x".repeat(31)).is_some());
        assert!(PfrTable::named(&"x".repeat(32)).is_none());
        assert!(PfrTable::named("").is_none());
    }

    #[test]
    fn unknown_af_yields_no_address() {
        let a = PfrAddr::zeroed();
        assert_eq!(ip_of(&a), None);
    }
}
