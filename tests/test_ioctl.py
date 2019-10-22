#!/usr/bin/env python3

# TODO: Use the /dev/pf ioctl interface (https://man.openbsd.org/OpenBSD-6.5/pf) for better performance (pfctl takes ~10-30ms);
# ioctl calls to implement DIOCRADDADDRS, DIOCRGETADDRS, DIOCRDELADDRS
# ioctl: https://man.openbsd.org/ioctl.2 https://docs.python.org/2/library/fcntl.html
# Python-C structs: https://docs.python.org/2/library/struct.html

############ Pycharm Debug ############
import sys
sys.path.append("pydevd-pycharm.egg")
import pydevd_pycharm
pydevd_pycharm.settrace('192.168.174.1', port=12345, stdoutToServer=True, stderrToServer=True)
#######################################

from fcntl import ioctl
from socket import *
from ctypes import *


# /dev/pf supports ioctl(2) commands available through <net/pfvar.h>:
#
# 'DIOCRADDADDRS struct pfioc_table *io'
#     Add one or more addresses to a table.
# On entry, pfrio_table contains the table ID and pfrio_buffer must point to an array of
# struct(s) of type pfr_addr, containing at least pfrio_size elements to add to the table.
# pfrio_esize must be the size of struct pfr_addr.
# On exit, pfrio_nadd contains the number of addresses effectively added.


########################################################################

# Constants
IFNAMSIZ             = 16               # From /usr/include/net/if.h
PF_TABLE_NAME_SIZE   = 32               # From /usr/include/net/pfvar.h
PATH_MAX             = 1024             # From /usr/include/sys/syslimits.h
PFRKE_PLAIN             = 0             # pfrke type (from /usr/include/net/pfvar.h)

# Table flags (from /usr/include/net/pfvar.h)
PFR_TFLAG_PERSIST       = 0x01
PFR_TFLAG_CONST         = 0x02
PFR_TFLAG_ACTIVE        = 0x04
PFR_TFLAG_INACTIVE      = 0x08
PFR_TFLAG_REFERENCED    = 0x10
PFR_TFLAG_REFDANCHOR    = 0x20
PFR_TFLAG_COUNTERS      = 0x40
PFR_TFLAG_USRMASK       = 0x43
PFR_TFLAG_SETMASK       = 0x3C
PFR_TFLAG_ALLMASK       = 0x7F

# ioctl() operations
IOCPARM_MASK     = 0x1fff
IOC_OUT          = 0x40000000
IOC_IN           = 0x80000000
IOC_INOUT        = IOC_IN | IOC_OUT


def _IOC(inout, group, num, len):
    return inout | ((len & IOCPARM_MASK) << 16) | group << 8 | num


def _IOWR(group, num, type):
    return _IOC(IOC_INOUT, ord(group), num, sizeof(type))


class pfr_addr(Structure):              # From /usr/include/net/pfvar.h
    class _pfra_u(Union):
        _fields_ = [("pfra_ip4addr",  c_uint32),      # struct in_addr
                    ("pfra_ip6addr",  c_uint32 * 4)]  # struct in6_addr

    _fields_ = [("pfra_u",            _pfra_u),
                ("pfra_ifname",       c_char * IFNAMSIZ),
                ("pfra_states",       c_uint32),
                ("pfra_weight",       c_uint16),
                ("pfra_af",           c_uint8),
                ("pfra_net",          c_uint8),
                ("pfra_not",          c_uint8),
                ("pfra_fback",        c_uint8),
                ("pfra_type",         c_uint8),
                ("pad",               c_uint8 * 7)]
    _anonymous_ = ("pfra_u",)


class pfr_table(Structure):             # From /usr/include/net/pfvar.h
    _fields_ = [("pfrt_anchor",       c_char * PATH_MAX),
                ("pfrt_name",         c_char * PF_TABLE_NAME_SIZE),
                ("pfrt_flags",        c_uint32),
                ("pfrt_fback",        c_uint8)]


class pfioc_table(Structure):     # From /usr/include/net/pfvar.h
    _fields_ = [("pfrio_table",       pfr_table),  # Set target PF Table attributes
                ("pfrio_buffer",      c_void_p),  # Pointer to byte array of pfr_addr's (containing at least pfrio_size elements to add to the table)
                ("pfrio_esize",       c_int),  # size of struct pfr_addr
                ("pfrio_size",        c_int),  # total size of all elements
                ("pfrio_size2",       c_int),
                ("pfrio_nadd",        c_int),  # Returns number of addresses effectively added
                ("pfrio_ndel",        c_int),
                ("pfrio_nchange",     c_int),
                ("pfrio_flags",       c_int),
                ("pfrio_ticket",      c_uint32)]


DIOCRADDADDRS = _IOWR('D', 67, pfioc_table)
DIOCRDELADDRS = _IOWR('D', 68, pfioc_table)


def addr_struct(af, host):
    """Convert this instance to a pfr_addr structure."""
    a = pfr_addr()

    addr = inet_pton(af, str(host))  # IP string format to packed binary format
    memmove(a.pfra_ip6addr, c_char_p(addr), len(addr))  # (dst, src, count)

    a.pfra_af = af
    if af == AF_INET:
        a.pfra_net = 32
    elif af == AF_INET6:
        a.pfra_net = 128
    a.pfra_not = 0
    a.pfra_fback = 0
    a.pfra_ifname = b""
    a.pfra_type = PFRKE_PLAIN
    a.states = 0
    a.pfra_weight = 0
    return a


def BuildIOStruct(cmd, af, table, *addrs):
    """ Populate complete pfioc_table(Structure) with table and IPs """

    # Populate pfr_table(Structure); with target table
    table = pfr_table(pfrt_name=table.encode())

    # Populate pfioc_table(Structure); load the pfr_table(Structure) object,
    # set mem size (bytes) of pfr_addr(Structure), set count of pfr_addr instances
    io = pfioc_table(pfrio_table=table, pfrio_esize=sizeof(pfr_addr), pfrio_size=len(addrs))

    # Build list of populated pfr_addr(Structure)'s;
    _addrs = []
    for _addr in addrs:
        _addrs.append(addr_struct(af, _addr))

    # Populate byte array of pfr_addr's (containing at least pfrio_size elements to add to the table)
    buffer = (pfr_addr * len(addrs))(*[a for a in _addrs])
    # buffer = (pfr_addr * len(addrs))(*[a._to_struct() for a in _addrs])

    # Populate pfioc_table(Structure); set pointer to buffer containing pfr_addr byte array
    io.pfrio_buffer = addressof(buffer)

    dev = "/dev/pf"
    with open(dev, 'w') as d:
        ioctl(d, cmd, io)
    return io.pfrio_nadd


print("Building Struct")
r1 = BuildIOStruct(DIOCRADDADDRS, AF_INET, "pfui_ipv4_domains", "192.168.17.0", "192.168.41.0")

r1 = BuildIOStruct(DIOCRADDADDRS, AF_INET6, "pfui_ipv6_domains", "2001:db8:1:14::1", "2001:db8:13:2::1")

print("Building Struct")
r2 = BuildIOStruct(DIOCRADDADDRS, AF_INET, "pfui_ipv4_domains", "192.168.41.1")


print("Building Struct")
r3 = BuildIOStruct(DIOCRDELADDRS, AF_INET, "pfui_ipv4_domains", "192.168.16.0")

