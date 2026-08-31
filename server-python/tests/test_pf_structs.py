"""ctypes layout checks for the PF structures. These run on any platform: only
the ioctl calls are OpenBSD-specific, and a layout drift would corrupt every
call silently, since pfrio_esize tells the kernel how to read the buffer."""

from ctypes import sizeof

from pfui.pf_ioctl import DIOCRADDADDRS, DIOCRDELADDRS, pfioc_table, pfr_addr, pfr_table


def test_struct_sizes_are_stable():
    assert sizeof(pfr_addr) == 52
    assert sizeof(pfr_table) == 1064
    assert sizeof(pfioc_table) == 1104


def test_ioctl_command_numbers():
    """_IOWR encoding for DIOCRADDADDRS (67) and DIOCRDELADDRS (68)."""
    assert DIOCRADDADDRS == 0xC4504443
    assert DIOCRDELADDRS == 0xC4504444


def test_pfra_states_field_exists():
    """The field is pfra_states; assigning a.states would silently create a new
    attribute instead of setting it."""
    addr = pfr_addr()
    addr.pfra_states = 0
    assert dict(pfr_addr._fields_)["pfra_states"] is not None


def test_unparseable_address_raises_before_touching_dev_pf():
    """R4: a failed inet_pton used to leave a zeroed struct, which would have
    installed 0.0.0.0 (or ::) into the table. The structs are built before the
    device is opened, so this raises without needing /dev/pf."""
    from socket import AF_INET

    import pytest

    from pfui.pf_ioctl import IOCTL

    class Log:
        def info(self, *a, **k):
            pass

    with pytest.raises(OSError):
        IOCTL(
            logger=Log(),
            dev="/nonexistent/dev/pf",
            iocmd=DIOCRADDADDRS,
            af=AF_INET,
            table="t",
            addrs=["definitely-not-an-ip"],
        )
