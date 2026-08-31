# PFUI_Firewall (Python)

The PFUI server: a daemon for OpenBSD PF firewalls that receives resolved IPs
from the clients and installs them into PF tables via the `/dev/pf` ioctl
interface, tracking expiry in Redis and mirroring the tables to persist files.

| Path | What it is |
|------|------------|
| `pfui_firewall.py` | The daemon (`start`/`stop`/`kill`/`restart`/`check`) |
| `pfui_firewall.yml` | Configuration, installed to `/etc/pfui_firewall.yml` |
| `pfui/pf_ioctl.py` | ctypes PF structures, `DIOCRADDADDRS`/`DIOCRDELADDRS`, `pfctl` fallback |
| `pfui/store.py` | Redis expiry decision |
| `pfui/validate.py` | Ingress address validation |
| `rc.d/pfui_firewall` | OpenBSD rc.d script |

Install with `../install-server-python.sh` from the repository root. The wire
format is specified in [../protocol/PROTOCOL.md](../protocol/PROTOCOL.md); the
installer places `pfui_wire.py` beside the daemon, and the `pfui` package holds
only what is server-specific.

`../server-c/` is a second implementation of the same protocol, currently
framing only. Where the two disagree, the protocol spec is normative.
