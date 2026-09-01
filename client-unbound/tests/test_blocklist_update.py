"""update_dns_blocklist.sh must never publish a list it did not really download.

The script writes the file Unbound loads as its domain filter and then restarts
the resolver. A failed download used to leave an empty or truncated list in place
and restart anyway, so a bad network turned DNS filtering off - silently, and
with a fresh service start to make it take effect. Its sibling
update_root_hints.sh guarded its single download; this one guards every source
and the merged result.

The script is exercised with stub curl/rcctl/chown on PATH, so no network,
no root, and no OpenBSD are needed.
"""

import os
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parent.parent / "tools" / "update_dns_blocklist.sh"

CURL_STUB = r"""#!/usr/bin/env bash
# Stub curl: writes ${CURL_LINES} lines unless the URL matches ${CURL_FAIL}.
dest=""
url=""
while [ $# -gt 0 ]; do
  case "$1" in
    -o) dest="$2"; shift 2 ;;
    -*) shift ;;
    *) url="$1"; shift ;;
  esac
done
echo "curl $url -> $dest" >> "${CURL_LOG}"
if [ -n "${CURL_FAIL:-}" ]; then
  case "$url" in
    *${CURL_FAIL}*) exit 22 ;;   # What curl -f does on an HTTP error
  esac
fi
lines=${CURL_LINES:-1200}
awk -v n="$lines" 'BEGIN { for (i = 0; i < n; i++) print "0.0.0.0 bad" i ".example.com" }' \
  > "$dest"
"""

RECORDER_STUB = r"""#!/usr/bin/env bash
echo "$(basename "$0") $*" >> "${CURL_LOG}"
exit 0
"""


@pytest.fixture
def harness(tmp_path):
    """A stubbed environment; returns a runner and the paths it writes."""
    etc = tmp_path / "etc"
    etc.mkdir()
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    log.write_text("")

    (bin_dir / "curl").write_text(CURL_STUB)
    for name in ("rcctl", "chown"):
        (bin_dir / name).write_text(RECORDER_STUB)
    for name in ("curl", "rcctl", "chown"):
        os.chmod(bin_dir / name, 0o755)

    published = etc / "dns_blocklist"

    def run(*args, **env):
        environment = dict(os.environ)
        environment.update(
            {
                "PATH": f"{bin_dir}:{environment['PATH']}",
                "ETC": str(etc),
                "CURL_LOG": str(log),
            }
        )
        environment.update({k: str(v) for k, v in env.items()})
        return subprocess.run(
            ["bash", str(SCRIPT), *args],
            capture_output=True,
            env=environment,
            timeout=120,
        )

    class Harness:
        def __init__(self):
            self.run = run
            self.etc = etc
            self.published = published

        def calls(self):
            return log.read_text()

        def lines(self):
            return [
                l for l in published.read_text().splitlines() if l
            ] if published.exists() else None

    return Harness()


def test_a_good_run_publishes_and_restarts(harness):
    result = harness.run()
    assert result.returncode == 0, result.stderr.decode()
    assert harness.lines(), "nothing was published"
    assert "rcctl restart pfui_unbound" in harness.calls()


def test_norestart_publishes_without_restarting(harness):
    assert harness.run("norestart").returncode == 0
    assert harness.lines()
    assert "rcctl" not in harness.calls()


def test_a_failed_source_falls_back_to_the_mirror(harness):
    """The StevenBlack lists have a second URL; using it is not a failure."""
    result = harness.run(CURL_FAIL="raw.githubusercontent.com")
    assert result.returncode == 0, result.stderr.decode()
    assert "sbc.io" in harness.calls()
    assert harness.lines()


def test_a_source_that_cannot_be_downloaded_at_all_aborts(harness):
    """No previous copy to fall back on, so there is nothing to publish."""
    result = harness.run(CURL_FAIL="hosts")
    assert result.returncode != 0
    assert harness.lines() is None, "published a list built from a failed download"
    assert "rcctl" not in harness.calls(), "restarted the resolver anyway"


def test_a_source_that_fails_today_is_reused_from_yesterday(harness):
    """A source that has a local copy is not a reason to abort or to publish a
    list missing its domains: the copy is reused and the run completes."""
    assert harness.run("norestart").returncode == 0
    before = harness.lines()

    result = harness.run("norestart", CURL_FAIL="pgl.yoyo.org")
    assert result.returncode == 0, result.stderr.decode()
    assert harness.lines() == before, "reusing a cached source lost domains"


def test_a_previously_published_list_survives_a_failed_run(harness):
    """The case that matters: yesterday's filter must stay in force. Nothing is
    cached here, so every source really is unavailable."""
    assert harness.run("norestart").returncode == 0
    before = harness.lines()
    for stale in harness.etc.iterdir():
        if stale.name != "dns_blocklist":
            stale.unlink()

    result = harness.run(CURL_FAIL="hosts")
    assert result.returncode != 0
    assert harness.lines() == before, "a failed run replaced a working blocklist"
    assert "rcctl" not in harness.calls(), "restarted the resolver anyway"


def test_an_implausibly_short_list_is_not_published(harness):
    """A feed that answers with a handful of lines is a broken feed, not a world
    where only three domains are malicious."""
    result = harness.run(CURL_LINES=3, MIN_ENTRIES=1000)
    assert result.returncode != 0
    assert harness.lines() is None
    assert "rcctl" not in harness.calls()


def test_a_list_that_collapses_is_not_published(harness):
    """Each source answered, so nothing failed outright, but the merged result
    lost most of its entries."""
    assert harness.run("norestart", CURL_LINES=1200).returncode == 0
    before = harness.lines()

    result = harness.run("norestart", CURL_LINES=500, MIN_ENTRIES=100, MIN_PERCENT=50)
    assert result.returncode != 0
    assert harness.lines() == before
    assert b"shrank" in result.stderr


def test_a_modest_shrink_is_still_published(harness):
    """Blocklists do lose entries; only a collapse is treated as a fault."""
    assert harness.run("norestart", CURL_LINES=1200).returncode == 0
    before = len(harness.lines())

    assert harness.run("norestart", CURL_LINES=1000).returncode == 0
    assert len(harness.lines()) < before


def test_an_empty_download_is_treated_as_a_failure(harness):
    result = harness.run(CURL_LINES=0)
    assert result.returncode != 0
    assert harness.lines() is None


def test_no_staging_files_are_left_behind(harness):
    harness.run("norestart", CURL_LINES=3)  # Refused
    leftovers = [p.name for p in harness.etc.iterdir() if ".new." in p.name]
    assert leftovers == [], f"left {leftovers} in place"
