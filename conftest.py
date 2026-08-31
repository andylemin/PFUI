"""Put each component on sys.path the same way it is laid out when installed.

The installers place the shared pfui_wire module beside each daemon, so both a
daemon and its tests import it as a top-level module. Mirroring that here keeps
the test imports identical to production rather than merely equivalent.
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent

for path in (
    ROOT / "protocol" / "python",  # shared: pfui_wire
    ROOT / "server-python",        # pfui.store / pfui.validate / pfui.pf_ioctl
    ROOT / "client-unbound",
):
    sys.path.insert(0, str(path))
