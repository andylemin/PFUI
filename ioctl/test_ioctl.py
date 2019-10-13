#!/usr/bin/env python3

# TODO: Use the /dev/pf ioctl interface (https://man.openbsd.org/OpenBSD-6.5/pf) for better performance (pfctl takes ~10-30ms);
# ioctl calls to implement DIOCRADDADDRS, DIOCRGETADDRS, DIOCRDELADDRS
# ioctl: https://man.openbsd.org/ioctl.2 https://docs.python.org/2/library/fcntl.html
# Python-C structs: https://docs.python.org/2/library/struct.html

import ctypes
import fcntl
import socket
import sys

import struct
import os

# WIP.. ioctl interface to issue DIOCRADDADDRS request directly


# /dev/pf supports ioctl(2) commands available through <net/pfvar.h>:
# #define	DIOCRADDADDRS	_IOWR('D', 67, struct pfioc_table)
#
# 'DIOCRADDADDRS struct pfioc_table *io'
#     Add one or more addresses to a table.
# On entry, pfrio_table contains the table ID and pfrio_buffer must point to an array of
# struct pfr_addr, containing at least pfrio_size elements to add to the table.
# pfrio_esize must be the size of struct pfr_addr.
# On exit, pfrio_nadd contains the number of addresses effectively added.


# struct pfr_table {
# 	char		pfrt_anchor[PATH_MAX];
# 	char		pfrt_name[PF_TABLE_NAME_SIZE];
# 	u_int32_t	pfrt_flags;
# 	u_int8_t	pfrt_fback;
# };
class pfr_table(ctypes.Structure):
    _fields_ = [
        ('pfrt_anchor[PATH_MAX]', ctypes.c_char),
        ('pfrt_name[PF_TABLE_NAME_SIZE]', ctypes.c_char),
        ('pfrt_flags', ctypes.c_uint32),
        ('pfrt_fback', ctypes.c_uint8)
    ]


# struct pfioc_table {
# 	struct pfr_table	 pfrio_table;
# 	void			*pfrio_buffer;
# 	int			 pfrio_esize;
# 	int			 pfrio_size;
# 	int			 pfrio_size2;
# 	int			 pfrio_nadd;
# 	int			 pfrio_ndel;
# 	int			 pfrio_nchange;
# 	int			 pfrio_flags;
# 	u_int32_t		 pfrio_ticket;
# };
# #define pfrio_exists    pfrio_nadd
# #define pfrio_nzero     pfrio_nadd
# #define pfrio_nmatch    pfrio_nadd
# #define pfrio_naddr     pfrio_size2
# #define pfrio_setflag   pfrio_size2
# #define pfrio_clrflag   pfrio_nadd
class pfioc_table(ctypes.Structure):
    _fields_ = [
        ('pfrio_table', pfr_table),  # Set this to PF Table
        ('*pfrio_buffer', ctypes.c_void_p),  # Pointer to array of pfr_addr's (containing at least pfrio_size elements to add to the table)
        ('pfrio_esize', ctypes.c_int),  # size of struct pfr_addr
        ('pfrio_size', ctypes.c_int),  # total size of all elements
        ('pfrio_size2', ctypes.c_int),
        ('pfrio_nadd', ctypes.c_int),  # Returns number of addresses effectively added
        ('pfrio_ndel', ctypes.c_int),
        ('pfrio_nchange', ctypes.c_int),
        ('pfrio_flags', ctypes.c_int),
        ('pfrio_ticket', ctypes.c_uint32)]


# struct pfr_addr {
# 	union {
# 		struct in_addr	 _pfra_ip4addr;
# 		struct in6_addr	 _pfra_ip6addr;
# 	}		 pfra_u;
# 	char		 pfra_ifname[IFNAMSIZ];
# 	u_int32_t	 pfra_states;
# 	u_int16_t	 pfra_weight;
# 	u_int8_t	 pfra_af;
# 	u_int8_t	 pfra_net;
# 	u_int8_t	 pfra_not;
# 	u_int8_t	 pfra_fback;
# 	u_int8_t	 pfra_type;
# 	u_int8_t	 pad[7];
# };
# #define pfra_ip4addr    pfra_u._pfra_ip4addr
# #define pfra_ip6addr    pfra_u._pfra_ip6addr
class in_addr(ctypes.Structure):
    _fields_ = [('s_addr', ctypes.c_long)]  # Load with inet_pton()

class in6_addr(ctypes.Structure):
    _fields_ = [('s_addr', ctypes.c_long)]  # Load with inet_pton()

class pfra_u(ctypes.Union):
    _fields_ = [
        ('_pfra_ip4addr', in_addr),
        ('_pfra_ip6addr', in6_addr)
    ]

class pfr_addr(ctypes.Structure):
    _fields_ = [
        ('pfra_u', pfra_u),
        ('pfra_ifname[IFNAMSIZ]', ctypes.c_char),
        ('pfra_states', ctypes.c_uint32),
        ('pfra_weight', ctypes.c_uint16),
        ('pfra_af', ctypes.c_uint8),
        ('pfra_net', ctypes.c_uint8),
        ('pfra_not', ctypes.c_uint8),
        ('pfra_fback', ctypes.c_uint8),
        ('pfra_type', ctypes.c_uint8),
        ('pad[7]', ctypes.c_uint8)]


rTable = pfr_table()
table_name = "pfui_ipv4_domains"
rTable.pfrt_name[sys.getsizeof(table_name)] = table_name

# getsizeof will not work for structs; will not hold true for nested objects or nested dicts or dicts in lists etc.

IP = pfr_addr()
IP.pfra_ip4addr = socket.inet_pton(socket.AF_INET, "1.2.3.4")

iocTable = pfioc_table()
iocTable.pfrio_table = rTable
iocTable.pfrio_buffer = ctypes.pointer(ARRAY_OBJECT)  # Pointer to 'array' of pfr_addr's
iocTable.pfrio_esize = ? # Size of struct pfr_addr
.
.
.

fd = open('/dev/pf', 'rw')
try:
    # request; limited to 32 bits, arg; bytes or bytearray object (1024 byte max), mutate_flag; controls interaction if arg is mutable
    # fcntl.ioctl(fd, request, arg=0, mutate_flag=True)
    fcntl.ioctl(fd, "DIOCRADDADDRS", iocTable)
    # DIOCRADDADDRS or DIOCADDADDRS !?
except OSError as e:
    print("ioctl failed: {}".format(e))

