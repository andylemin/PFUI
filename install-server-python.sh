#!/usr/bin/env bash
#
# Installs PFUI Firewall
#

err=0
trap 'err=1' ERR

# Abort immediately on a step nothing can proceed without
die() {
  echo "PFUIFW: FATAL: $*" >&2
  exit 1
}

# Install packages without ever prompting. A release's package set holds one
# version of each package, so there is no "latest" to choose; -i only ever
# prompts when a stem matches several flavours, and answering that from a
# script is guesswork. Name the candidates instead and let the operator pick.
add_pkg() {
  local pkg
  for pkg in "$@"; do
    pkg_add -I "${pkg}" && continue
    echo "PFUIFW: cannot install '${pkg}'. Candidates:" >&2
    pkg_info -Q "${pkg}" >&2 || true
    die "install one explicitly, Eg 'pkg_add ${pkg}-<version>'"
  done
}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
HOUR=$(date +%d-%b-%H_%M)

if [[ $(id -u) -ne 0 ]]; then
  echo "PFUIFW: Please run as root user"
  exit 1
fi

echo "***************************************************************************************"
echo "* Welcome to the PFUI_Firewall (Python) Installer (https://github.com/andylemin/PFUI) *"
echo "***************************************************************************************"

if [[ $(uname) == "OpenBSD" ]]; then
  OS="OpenBSD"
else
  echo "PFUIFW: Looks like a non-supported operating system."
  echo "PFUIFW Supported OS: OpenBSD"
  exit 2
fi

if [[ "$OS" = "OpenBSD" ]]; then
  echo "PFUIFW: Installing Python3"
  add_pkg python3 py3-pip py3-setuptools
  which python >/dev/null
  if [[ $? != 0 ]]; then
    ln -s `which python3` /usr/local/bin/python
  fi

  echo "PFUIFW: Installing and Starting Redis"
  add_pkg redis
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
  # -G replaces secondary memberships on OpenBSD, so it is only applied when the
  # daemon account is not already in the group. _pfui_firewall is created here and
  # has no other secondary groups
  if ! groupinfo _pfui | grep -qw _pfui_firewall; then
    usermod -G _pfui _pfui_firewall || die "cannot add _pfui_firewall to _pfui"
  fi

  # PF ioctl access without wheel, which would also grant su. rc.d/pfui_firewall
  # re-applies this on every start, because MAKEDEV resets it on release upgrades
  chgrp _pfui_firewall /dev/pf && chmod 660 /dev/pf || die "cannot set /dev/pf ownership"

  echo "PFUIFW: Installing Python dependencies for the system interpreter"
  # Not a virtualenv: the daemon runs under /usr/local/bin/python3 (see its
  # shebang), so the dependencies have to be importable there.
  add_pkg py3-lz4 py3-yaml py3-redis
  # 'service' is not packaged, and the system interpreter is externally managed
  # (PEP 668), so pip has to be told that writing to it is deliberate
  python3 -m pip install --break-system-packages 'service>=0.6,<1' \
    || die "cannot install the 'service' module"
  python3 -c "import lz4.frame, yaml, redis, service" \
    || die "dependencies are not importable by $(command -v python3)"

  echo "PFUIFW: Installing PFUI Firewall Service (will backup any existing pfui_firewall configuration)"
  install -m 755 -o root -g wheel "${DIR}"/server-python/pfui_firewall.py /usr/local/sbin/pfui_firewall \
    || die "cannot install the daemon"
  # Shared modules must sit beside the daemon; a script's own directory is sys.path[0]
  install -d -m 755 -o root -g wheel /usr/local/sbin/pfui
  # Shared protocol module sits beside the daemon, as a top-level module
  install -m 644 -o root -g wheel "${DIR}"/protocol/python/pfui_wire.py \
    /usr/local/sbin/ || die "cannot install the shared wire module"
  install -m 644 -o root -g wheel "${DIR}"/server-python/pfui/__init__.py \
    "${DIR}"/server-python/pfui/store.py "${DIR}"/server-python/pfui/validate.py \
    "${DIR}"/server-python/pfui/pf_ioctl.py /usr/local/sbin/pfui/ \
    || die "cannot install the pfui modules"

  # An existing config is kept so an upgrade does not disturb a running
  # deployment; only a first install lays down the example
  if [ -f /etc/pfui_firewall.yml ]; then
    cp -p /etc/pfui_firewall.yml "/etc/pfui_firewall.yml.${HOUR}"
    echo "PFUIFW: Keeping the existing /etc/pfui_firewall.yml"
    echo "PFUIFW: (backup at /etc/pfui_firewall.yml.${HOUR}; compare it against"
    echo "        ${DIR}/server-python/pfui_firewall.yml for keys added since)"
  else
    # root-owned: the daemon only reads this, and CTL: PFCTL makes it a command source
    install -m 644 -o root -g wheel "${DIR}"/server-python/pfui_firewall.yml \
      /etc/pfui_firewall.yml || die "cannot install the configuration file"
    echo "PFUIFW: Default configuration installed at '/etc/pfui_firewall.yml' (please configure)"
  fi
  # root-owned: rcctl runs this as root, and a file's owner can always chmod it
  install -m 555 -o root -g wheel "${DIR}"/server-python/rc.d/pfui_firewall /etc/rc.d/pfui_firewall \
    || die "cannot install the rc.d script"

  install -m 644 -o root -g wheel "${DIR}"/examples/pf.conf /etc/pf-pfui-example.conf
  echo "PFUIFW: An example pf.conf file is located at '/etc/pf-pfui-example.conf'"
  echo "PFUIFW: /etc/pf.conf is NOT modified; merge the PFUI tables and rules yourself"

  # Where the daemon's pid file and, if SOCKET_UNIX is configured, its local socket
  # live. Group _pfui at 0750 so only that group can traverse to the socket, and so
  # the socket inherits the group; rc.d/pfui_firewall re-applies this on every start
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
    # An existing file from an earlier layout is COPIED, never moved: pf.conf
    # loads its tables from whatever path it names, and moving the file out from
    # under it breaks the next ruleset load
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
  echo "PFUIFW: NOTE point pf.conf 'persist file' paths at ${PERSIST_DIR}/ipv{4,6}_domains (see /etc/pf-pfui-example.conf)"
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

