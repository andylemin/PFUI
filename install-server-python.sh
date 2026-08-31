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

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
HOUR=$(date +%d-%b-%H_%M)

if [[ $(id -u) -ne 0 ]]; then
  echo "PFUIFW: Please run as root user"
  exit 1
fi

if [[ $(uname) == "OpenBSD" ]]; then
  OS="OpenBSD"
else
  echo "PFUIFW: Looks like a non-supported operating system."
  echo "PFUIFW Supported OS: OpenBSD"
  exit 2
fi

if [[ "$OS" = "OpenBSD" ]]; then
  echo "PFUIFW: Installing Python3"
  pkg_add -i python3 py3-setuptools py3-pip
  which python >/dev/null
  if [[ $? != 0 ]]; then
    ln -s `which python3` /usr/local/bin/python
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

  # PF ioctl access without wheel, which would also grant su. rc.d/pfui_firewall
  # re-applies this on every start, because MAKEDEV resets it on release upgrades
  chgrp _pfui_firewall /dev/pf && chmod 660 /dev/pf || die "cannot set /dev/pf ownership"

  echo "PFUIFW: Installing Python dependencies for the system interpreter"
  # Not a virtualenv: the daemon runs under /usr/local/bin/python3 (see its
  # shebang), so the dependencies have to be importable there. The previous
  # venv was never wired into the daemon and was the only place these landed.
  python3 -m pip install -r "${DIR}/server-python/requirements.txt" \
    || die "cannot install Python dependencies"

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

  [ -f /etc/pfui_firewall.yml ] && cp -p /etc/pfui_firewall.yml "/etc/pfui_firewall.yml.${HOUR}"
  # root-owned: the daemon only reads this, and CTL: PFCTL makes it a command source
  install -m 644 -o root -g wheel "${DIR}"/server-python/pfui_firewall.yml /etc/pfui_firewall.yml
  echo "PFUIFW: PFUI_Firewall default configuration file located at '/etc/pfui_firewall.yml' (please configure)"
  # root-owned: rcctl runs this as root, and a file's owner can always chmod it
  install -m 555 -o root -g wheel "${DIR}"/server-python/rc.d/pfui_firewall /etc/rc.d/pfui_firewall \
    || die "cannot install the rc.d script"

  install -m 644 -o root -g wheel "${DIR}"/examples/pf.conf /etc/pf-pfui-example.conf
  echo "PFUIFW: An example pf.conf file is located at '/etc/pf-pfui-example.conf'"
  echo "PFUIFW: /etc/pf.conf is NOT modified; merge the PFUI tables and rules yourself"

  echo "PFUIFW: Updating Persist files /var/spool/pfui/pfui_ipv<*>_domains"
  # Daemon-owned directory: file_push/file_pop need to create a .lock sidecar and
  # mkstemp here. pfctl reads the files as root, so no world access is needed.
  install -d -o _pfui_firewall -g _pfui_firewall -m 750 /var/spool/pfui \
    || die "cannot create /var/spool/pfui"
  for f in pfui_ipv4_domains pfui_ipv6_domains; do
    if [ -f "/var/spool/${f}" ] && [ ! -f "/var/spool/pfui/${f}" ]; then
      echo "PFUIFW: Migrating existing /var/spool/${f} to /var/spool/pfui/${f}"
      mv "/var/spool/${f}" "/var/spool/pfui/${f}"
    fi
    [ -f "/var/spool/pfui/${f}" ] || install -o _pfui_firewall -g _pfui_firewall -m 640 \
      /dev/null "/var/spool/pfui/${f}"
    chown _pfui_firewall:_pfui_firewall "/var/spool/pfui/${f}"
    chmod 640 "/var/spool/pfui/${f}"
  done
  echo "PFUIFW: NOTE update pf.conf 'persist file' paths to /var/spool/pfui/ (see /etc/pf-pfui-example.conf)"
fi

if [[ $err != 0 ]]; then
  echo "PFUIFW: All Completed, but with some errors. Please investigate."
  exit 1
else
  echo "PFUIFW: All Completed successfully."
fi
echo "PFUIFW: Enable service 'rcctl enable pfui_firewall'"
echo "PFUIFW: Start service 'rcctl start pfui_firewall'"

