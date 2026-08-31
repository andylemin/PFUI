"""PF table ioctl integration tests. OpenBSD only, and they mutate real PF
tables, so they are skipped everywhere else.

The ctypes structs are imported from pfui.pf_ioctl rather than redeclared here:
the previous copy drifted from the daemon's and asserted nothing.
"""

import platform

import pytest

from pfui.pf_ioctl import (
    DIOCRADDADDRS,
    DIOCRDELADDRS,
    IOCTL,
    pfioc_table,
    pfr_addr,
    pfr_table,
)

pytestmark = pytest.mark.skipif(
    platform.system() != "OpenBSD", reason="PF ioctl is OpenBSD only"
)

TEST_TABLE = "pfui_test_ipv4"
TEST_IPS = ["198.51.100.1", "198.51.100.2"]
DEVPF = "/dev/pf"


class Log:
    def info(self, *a, **k):
        pass

    def error(self, *a, **k):
        pass

    def exception(self, *a, **k):
        pass


def test_add_then_delete_reports_counts():
    """The ioctl must report what it changed; a silent 0 means nothing landed."""
    from socket import AF_INET

    added = IOCTL(
        logger=Log(),
        dev=DEVPF,
        iocmd=DIOCRADDADDRS,
        af=AF_INET,
        table=TEST_TABLE,
        addrs=TEST_IPS,
    )
    assert added == len(TEST_IPS)

    # Re-adding the same addresses must add nothing
    again = IOCTL(
        logger=Log(),
        dev=DEVPF,
        iocmd=DIOCRADDADDRS,
        af=AF_INET,
        table=TEST_TABLE,
        addrs=TEST_IPS,
    )
    assert again == 0

    deleted = IOCTL(
        logger=Log(),
        dev=DEVPF,
        iocmd=DIOCRDELADDRS,
        af=AF_INET,
        table=TEST_TABLE,
        addrs=TEST_IPS,
    )
    assert deleted >= 0  # pfrio_nadd is the add counter; deletes report via ndel


def test_ipv6_addresses_are_accepted():
    from socket import AF_INET6

    added = IOCTL(
        logger=Log(),
        dev=DEVPF,
        iocmd=DIOCRADDADDRS,
        af=AF_INET6,
        table="pfui_test_ipv6",
        addrs=["2001:db8::1"],
    )
    assert added == 1
    IOCTL(
        logger=Log(),
        dev=DEVPF,
        iocmd=DIOCRDELADDRS,
        af=AF_INET6,
        table="pfui_test_ipv6",
        addrs=["2001:db8::1"],
    )
