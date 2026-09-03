#!/usr/bin/env bash
#
# Installs PFUI Firewall (Rust daemon)
#
# Drop-in replacement for the Python daemon: same config, same Redis schema,
# same rc.d service name, same binary path. The two server installers are
# mutually exclusive on one firewall.

err=0
trap 'err=1' ERR

# Abort immediately on a step nothing can proceed without
die() {
  echo "PFUIFW: FATAL: $*" >&2
  exit 1
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
HOUR=$(date +%d-%b-%H_%M)

if [[ $(id -u) -ne 0 ]]; then
  echo "PFUIFW: Please run as root user"
  exit 1
fi

echo "*************************************************************************************"
echo "* Welcome to the PFUI_Firewall (Rust) Installer (https://github.com/andylemin/PFUI) *"
echo "*************************************************************************************"

if [[ $(uname) != "OpenBSD" ]]; then
  echo "PFUIFW: Looks like a non-supported operating system."
  echo "PFUIFW Supported OS: OpenBSD"
  exit 2
fi

# Build here with the ports rustc (which is the MSRV pin), or install a
# prebuilt artifact from the release builder: PFUI_BINARY=/path skips the
# toolchain and the build entirely.
if [[ -n "${PFUI_BINARY}" ]]; then
  [[ -x "${PFUI_BINARY}" ]] || die "PFUI_BINARY=${PFUI_BINARY} is not an executable"
  BINARY="${PFUI_BINARY}"
else
  echo "PFUIFW: Installing the Rust toolchain"
  pkg_add -i rust
  command -v cargo >/dev/null || die "cargo not found after pkg_add rust"

  # / is under a gigabyte on a default disklayout, and the crate cache and
  # target tree are hundreds of megabytes each. /usr/local has the room and is
  # the partition mounted wxallowed.
  BUILD_ROOT=/usr/local/pfui-build
  install -d -m 700 "${BUILD_ROOT}" || die "cannot create ${BUILD_ROOT}"
  mount | grep -q " $(df -P "${BUILD_ROOT}" | awk 'NR==2 {print $6}') .*wxallowed" \
    || echo "PFUIFW: WARNING ${BUILD_ROOT} is not on a wxallowed filesystem;" \
            "if the build fails, add wxallowed to that partition in /etc/fstab"
  export CARGO_HOME="${BUILD_ROOT}/cargo"
  export CARGO_TARGET_DIR="${BUILD_ROOT}/target"

  echo "PFUIFW: Building pfui_firewall in ${BUILD_ROOT} (release, locked to Cargo.lock)"
  (cd "${DIR}/server-rust" && cargo build --release --locked) \
    || die "cargo build failed"
  BINARY="${CARGO_TARGET_DIR}/release/pfui_firewall"
fi

echo "PFUIFW: Installing and Starting Redis"
pkg_add -i redis
# Redis holds the whitelist that the sync loop pushes into the PF tables, so
# anything able to write those keys can authorise egress. Keep it loopback-only.
REDIS_CONF=/etc/redis/redis.conf
if [ -f "${REDIS_CONF}" ]; then
  cp -p "${REDIS_CONF}" "${REDIS_CONF}.${HOUR}"
  if grep -Eq '^[[:space:]]*bind[[:space:]]' "${REDIS_CONF}"; then
    sed -i -e 's/^[[:space:]]*bind[[:space:]].*/bind 127.0.0.1/' "${REDIS_CONF}"
  else
    echo "bind 127.0.0.1" >> "${REDIS_CONF}"
  fi
  grep -Eq '^[[:space:]]*protected-mode' "${REDIS_CONF}" \
    || echo "protected-mode yes" >> "${REDIS_CONF}"
else
  echo "PFUIFW: WARNING ${REDIS_CONF} not found; verify Redis binds 127.0.0.1 only"
fi
rcctl enable redis
rcctl restart redis
# Verify rather than assume
if command -v redis-cli >/dev/null 2>&1; then
  echo "PFUIFW: Redis bind is now: $(redis-cli config get bind 2>/dev/null | tail -1)"
fi

echo "PFUIFW: Creating daemon user '_pfui_firewall'"
groupadd _pfui_firewall 2>/dev/null || true
useradd -g _pfui_firewall -s /sbin/nologin -d /var/empty _pfui_firewall 2>/dev/null || true
id _pfui_firewall >/dev/null || die "daemon user _pfui_firewall was not created"

# Shared group for the local socket (SOCKET_UNIX), which a PFUI_Unbound on this
# same host connects to. It is a group of its own rather than reusing _unbound
# or _pfui_firewall: membership of it means "may inject PF whitelist entries",
# and that should not be implied by running as the resolver or as the daemon.
# install-client-unbound.sh adds _unbound to it when a resolver is installed here.
echo "PFUIFW: Creating group '_pfui' (permits the local PFUI socket)"
groupadd _pfui 2>/dev/null || true
groupinfo _pfui >/dev/null 2>&1 || die "group _pfui was not created"
# -G replaces secondary memberships on OpenBSD rather than adding to them, so
# the existing set is merged rather than substituted.
if ! groupinfo _pfui | grep -qw _pfui_firewall; then
  primary_group=$(id -gn _pfui_firewall)
  merged_groups=""
  for g in $(id -Gn _pfui_firewall); do
    [[ "${g}" == "${primary_group}" || "${g}" == "_pfui" ]] && continue
    merged_groups="${merged_groups}${merged_groups:+,}${g}"
  done
  merged_groups="${merged_groups}${merged_groups:+,}_pfui"
  usermod -G "${merged_groups}" _pfui_firewall \
    || die "cannot add _pfui_firewall to _pfui"
  echo "PFUIFW: _pfui_firewall secondary groups are now ${merged_groups}"
fi

# PF ioctl access without wheel, which would also grant su. rc.d/pfui_firewall
# re-applies this on every start, because MAKEDEV resets it on release upgrades
chgrp _pfui_firewall /dev/pf && chmod 660 /dev/pf || die "cannot set /dev/pf ownership"

echo "PFUIFW: Installing PFUI Firewall daemon"
# The binary is the whole install: no module tree, no wire module. Overwrites
# the Python daemon at the same path when present, deliberately, for drop-in.
install -m 755 -o root -g wheel "${BINARY}" /usr/local/sbin/pfui_firewall \
  || die "cannot install the daemon"

# This daemon reads the same keys as the Python one, so an existing config is
# still correct and is kept rather than replaced.
if [ -f /etc/pfui_firewall.yml ]; then
  cp -p /etc/pfui_firewall.yml "/etc/pfui_firewall.yml.${HOUR}"
  echo "PFUIFW: Keeping the existing /etc/pfui_firewall.yml"
  echo "PFUIFW: (backup at /etc/pfui_firewall.yml.${HOUR}; compare it against"
  echo "        ${DIR}/server-python/pfui_firewall.yml for keys added since)"
else
  # One yml serves either daemon, so the shipped config is the shared one.
  # root-owned: the daemon only reads it, and CTL: PFCTL makes it a command source
  install -m 644 -o root -g wheel "${DIR}"/server-python/pfui_firewall.yml \
    /etc/pfui_firewall.yml || die "cannot install the configuration file"
  echo "PFUIFW: Default configuration installed at '/etc/pfui_firewall.yml' (please configure)"
fi
/usr/local/sbin/pfui_firewall -n -f /etc/pfui_firewall.yml \
  || echo "PFUIFW: WARNING the config does not validate; fix it before starting"

# root-owned: rcctl runs this as root, and a file's owner can always chmod it
install -m 555 -o root -g wheel "${DIR}"/server-rust/rc.d/pfui_firewall /etc/rc.d/pfui_firewall \
  || die "cannot install the rc.d script"

install -m 644 -o root -g wheel "${DIR}"/examples/pf.conf /etc/pf-pfui-example.conf
echo "PFUIFW: An example pf.conf file is located at '/etc/pf-pfui-example.conf'"
echo "PFUIFW: /etc/pf.conf is NOT modified; merge the PFUI tables and rules yourself"

# Where the local socket lives when SOCKET_UNIX is configured. Group _pfui at
# 0750 so only that group can traverse to the socket, and so the socket
# inherits the group; rc.d/pfui_firewall re-applies this on every start
install -d -o _pfui_firewall -g _pfui -m 750 /var/run/pfui \
  || die "cannot create /var/run/pfui"

PERSIST_DIR=/var/db/pfui
echo "PFUIFW: Persist files in ${PERSIST_DIR}"
# Daemon-owned directory: file_push/file_pop need to create a .lock sidecar and
# rename a tempfile over the persist file, so the directory itself must be
# writable, not just the files. pfctl reads them as root, so no world access.
install -d -o _pfui_firewall -g _pfui_firewall -m 750 "${PERSIST_DIR}" \
  || die "cannot create ${PERSIST_DIR}"
for af in ipv4 ipv6; do
  new="${PERSIST_DIR}/${af}_domains"
  # Copied, never moved: pf.conf loads its tables from the path it names, and
  # moving the file out from under it breaks the next ruleset load
  if [ ! -f "${new}" ]; then
    for old in "/var/spool/pfui/pfui_${af}_domains" "/var/spool/pfui_${af}_domains"; do
      if [ -f "${old}" ]; then
        echo "PFUIFW: Seeding ${new} from ${old} (${old} is left in place)"
        cp "${old}" "${new}"
        break
      fi
    done
  fi
  [ -f "${new}" ] || install -o _pfui_firewall -g _pfui_firewall -m 640 /dev/null "${new}"
  chown _pfui_firewall:_pfui_firewall "${new}"
  chmod 640 "${new}"
done
if grep -q 'persist file "/var/spool/pfui' /etc/pf.conf 2>/dev/null; then
  echo "PFUIFW: WARNING /etc/pf.conf still loads its PFUI tables from /var/spool."
  echo "        Point those 'persist file' paths at ${PERSIST_DIR}/ipv{4,6}_domains"
  echo "        (see /etc/pf-pfui-example.conf), then delete the old files."
  echo "        Until then a PF reload restores whatever the old files hold."
fi

if [[ $err != 0 ]]; then
  echo "PFUIFW: All Completed, but with some errors. Please investigate."
  exit 1
else
  echo "PFUIFW: All Completed successfully."
fi
echo "PFUIFW: Enable service 'rcctl enable pfui_firewall'"
echo "PFUIFW: Start service 'rcctl start pfui_firewall'"
echo
echo "PFUIFW: If PFUI_Unbound runs on THIS host, uncomment SOCKET_UNIX in"
echo "        /etc/pfui_firewall.yml and add '- SOCKET: /var/run/pfui/pfui_firewall.sock'"
echo "        to the resolver's FIREWALLS. No pf.conf rule is needed for that path;"
echo "        membership of group '_pfui' is what permits it."
