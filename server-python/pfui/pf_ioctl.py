"""OpenBSD PF table ioctl interface (DIOCRADDADDRS / DIOCRDELADDRS).

Imports on any platform; the ioctl calls themselves only work on OpenBSD, so
tests that exercise them must be gated on the running OS.
"""

import subprocess
from ctypes import *
from fcntl import ioctl
from socket import AF_INET, AF_INET6, AddressFamily, inet_pton

# Constants
IFNAMSIZ = 16  # From /usr/include/net/if.h
PF_TABLE_NAME_SIZE = 32  # From /usr/include/net/pfvar.h
PATH_MAX = 1024  # From /usr/include/sys/syslimits.h
PFRKE_PLAIN = 0  # pfrke type (from /usr/include/net/pfvar.h)

# Table flags (from /usr/include/net/pfvar.h)
PFR_TFLAG_PERSIST = 0x01
PFR_TFLAG_CONST = 0x02
PFR_TFLAG_ACTIVE = 0x04
PFR_TFLAG_INACTIVE = 0x08
PFR_TFLAG_REFERENCED = 0x10
PFR_TFLAG_REFDANCHOR = 0x20
PFR_TFLAG_COUNTERS = 0x40
PFR_TFLAG_USRMASK = 0x43
PFR_TFLAG_SETMASK = 0x3C
PFR_TFLAG_ALLMASK = 0x7F

# ioctl() operations
IOCPARM_MASK = 0x1FFF
IOC_OUT = 0x40000000
IOC_IN = 0x80000000
IOC_INOUT = IOC_IN | IOC_OUT


# C Structures
class pfr_table(Structure):  # From /usr/include/net/pfvar.h
    """Data class to create pfr_table struct"""

    _fields_ = [
        ("pfrt_anchor", c_char * PATH_MAX),
        ("pfrt_name", c_char * PF_TABLE_NAME_SIZE),
        ("pfrt_flags", c_uint32),
        ("pfrt_fback", c_uint8),
    ]


class pfioc_table(Structure):  # From /usr/include/net/pfvar.h
    """Data class to create pfioc_table struct, holds pfr_table struct with pfr_addr structs"""

    _fields_ = [
        ("pfrio_table", pfr_table),  # Set target PF Table attributes
        (
            "pfrio_buffer",
            c_void_p,
        ),  # Pointer to byte array of pfr_addr's (pfrio_size elements)
        ("pfrio_esize", c_int),  # size of struct pfr_addr
        ("pfrio_size", c_int),  # total size of all elements
        ("pfrio_size2", c_int),
        ("pfrio_nadd", c_int),  # Returns number of addresses effectively added
        ("pfrio_ndel", c_int),
        ("pfrio_nchange", c_int),
        ("pfrio_flags", c_int),
        ("pfrio_ticket", c_uint32),
    ]


class pfr_addr(Structure):  # From /usr/include/net/pfvar.h
    """Data class to create pfr_addr struct"""

    class _pfra_u(Union):
        _fields_ = [
            ("pfra_ip4addr", c_uint32),  # struct in_addr
            ("pfra_ip6addr", c_uint32 * 4),
        ]  # struct in6_addr

    _fields_ = [
        ("pfra_u", _pfra_u),
        ("pfra_ifname", c_char * IFNAMSIZ),
        ("pfra_states", c_uint32),
        ("pfra_weight", c_uint16),
        ("pfra_af", c_uint8),
        ("pfra_net", c_uint8),
        ("pfra_not", c_uint8),
        ("pfra_fback", c_uint8),
        ("pfra_type", c_uint8),
        ("pad", c_uint8 * 7),
    ]
    _anonymous_ = ("pfra_u",)


def IOCTL(logger, dev: str, iocmd, af: AddressFamily, table: str, addrs: list):
    """
    Populate a complete pfioc_table Structure with target table and IPs,
    and push struct with Action to /dev/pf ioctl interface.
    """

    def pfr_addr_struct(logger, af: AddressFamily, addr: str):
        """Convert this object to a pfr_addr structure.

        Raises on an unparseable address rather than returning a zeroed struct,
        which would have installed 0.0.0.0 or :: into the table.
        """
        a = pfr_addr()

        packed = inet_pton(af, str(addr))  # IP string to packed binary format
        # Copy Addr to v6
        memmove(a.pfra_ip6addr, c_char_p(packed), len(packed))  # (dst, <- src, count)

        a.pfra_af = af
        if af == AF_INET:
            a.pfra_net = 32
        elif af == AF_INET6:
            a.pfra_net = 128
        a.pfra_not = 0
        a.pfra_fback = 0
        a.pfra_ifname = b""
        a.pfra_type = PFRKE_PLAIN
        a.pfra_states = 0
        a.pfra_weight = 0
        return a

    # Init pfr_table(Structure); with target table
    table = pfr_table(pfrt_name=table.encode())

    # Populate pfioc_table(Structure); load the pfr_table(Structure) object,
    # set mem size (bytes) of pfr_addr(Structure), set count of pfr_addr instances
    io = pfioc_table(
        pfrio_table=table, pfrio_esize=sizeof(pfr_addr), pfrio_size=len(addrs)
    )

    # Build list of populated pfr_addr(Structure)'s;
    _addrs = []
    for _addr in addrs:
        _addrs.append(pfr_addr_struct(logger, af, _addr))

    # Populate buffer byte-array of pfr_addr's (echo containing at least pfrio_size elements to add to the table)
    buffer = (pfr_addr * len(addrs))(*[a for a in _addrs])

    # Populate pfioc_table(Structure); set pointer to buffer containing pfr_addr byte array
    io.pfrio_buffer = addressof(buffer)

    with open(dev, "w") as d:
        ioctl(d, iocmd, io)
    return io.pfrio_nadd  # Successful commits


def _IOWR(group, num, type):
    def _IOC(inout, group, num, len):
        return inout | ((len & IOCPARM_MASK) << 16) | group << 8 | num

    return _IOC(IOC_INOUT, ord(group), num, sizeof(type))


DIOCRADDADDRS = _IOWR("D", 67, pfioc_table)
DIOCRDELADDRS = _IOWR("D", 68, pfioc_table)


def table_push(
    logger, log: bool, cfg: dict, af: AddressFamily, table: str, ip_list: list
):
    """
    Install IP(s) into PF Table, Latency sensitive operation.
    Returns the number of IPs successfully pushed onto the table; 0 on failure,
    never None.
    """

    def pfctl_add_addr(table, ip_list):
        """Returns the number of IPs pushed, 0 on failure."""
        r = subprocess.run(
            ["pfctl", "-t", table, "-T", "add"] + ip_list, stdout=subprocess.DEVNULL
        )
        if r.returncode != 0:  # Non-zero error codes
            logger.error(f"PFCTL push failed: {r}")
            return 0
        return len(ip_list)

    if log:
        logger.info(f"PFUIFW: Adding '{ip_list}' to PF Table {table}")

    if cfg["CTL"] == "IOCTL":
        try:
            return IOCTL(
                logger=logger,
                dev=cfg["DEVPF"],
                iocmd=DIOCRADDADDRS,
                af=af,
                table=table,
                addrs=ip_list,
            )
        except Exception as e:
            logger.error(
                f"PFUIFW: IOCTL Failed to install {ip_list} into PF Table {table}, trying PFCTL. {e}"
            )

    # pfctl cli fallback
    try:
        return pfctl_add_addr(table, ip_list)
    except Exception as e:
        logger.error(
            f"PFUIFW: PFCTL Failed to install {ip_list} into PF Table {table}. {e}"
        )
        return 0


def table_pop(
    logger, log: bool, cfg: dict, af: AddressFamily, table: str, ip_list: list
):
    """
    Remove IP(s) from PF Table.
    Returns the number of IPs successfully popped from the table; 0 on failure,
    never None.
    """

    def pfctl_del_addr(table, ip_list):
        """Returns the number of IPs popped, 0 on failure."""
        r = subprocess.run(
            ["pfctl", "-t", table, "-T", "delete"] + ip_list, stdout=subprocess.DEVNULL
        )
        if r.returncode != 0:  # Non-zero error codes
            logger.error(f"PFCTL pop failed: {r}")
            return 0
        return len(ip_list)

    if log:
        logger.info(f"PFUIFW: Clearing '{ip_list}' from PF Table {table}")

    if cfg["CTL"] == "IOCTL":
        try:
            return IOCTL(
                logger=logger,
                dev=cfg["DEVPF"],
                iocmd=DIOCRDELADDRS,
                af=af,
                table=table,
                addrs=ip_list,
            )

        except Exception as e:
            logger.error(
                f"PFUIFW: IOCTL Failed to delete {ip_list} from PF Table {table}, trying PFCTL. {e}"
            )
    try:
        return pfctl_del_addr(table, ip_list)
    except Exception as e:
        logger.error(
            f"PFUIFW: PFCTL Failed to delete {ip_list} from PF Table {table}. {e}"
        )
        return 0
