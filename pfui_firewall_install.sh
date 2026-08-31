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

args=("$@")
SETPFCONF=${args[0]}

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
  rcctl enable redis
  rcctl start redis

  echo "PFUIFW: Creating daemon user '_pfui_firewall'"

#  groupadd _pfui_firewall
#  useradd -s /sbin/nologin -d /var/empty _pfui_firewall
#install -m 755 -o root -g bin unbound-adblock.sh /usr/local/bin/unbound-adblock
# https://www.geoghegan.ca/pub/unbound-adblock/latest/install/openbsd.txt

  groupadd _pfui_firewall 2>/dev/null || true
  useradd -g _pfui_firewall -s /sbin/nologin -d /var/empty _pfui_firewall 2>/dev/null || true
  id _pfui_firewall >/dev/null || die "daemon user _pfui_firewall was not created"

  # PF ioctl access without wheel, which would also grant su. rc.d/pfui_firewall
  # re-applies this on every start, because MAKEDEV resets it on release upgrades
  chgrp _pfui_firewall /dev/pf && chmod 660 /dev/pf || die "cannot set /dev/pf ownership"

  echo "PFUIFW: Creating Python virtual environment and installing dependencies"
  python -m venv pfui_firewall
  ./pfui_firewall/bin/pip install --upgrade pip
  ./pfui_firewall/bin/pip install redis pyyaml service lz4
#  echo "PFUIFW: Installing Python Libraries"
#  python3 -m pip install redis pyyaml service lz4
#  ldconfig -mv /usr/local/lib

# TODO Get pfui_firewall daemon working with venv. Needs to be in directory with daemon?

  echo "PFUIFW: Installing PFUI Firewall Service (will backup any existing pfui_firewall configuration)"
  install -m 755 -o root -g wheel "${DIR}"/pfui_firewall.py /usr/local/sbin/pfui_firewall \
    || die "cannot install the daemon"
  # Shared modules must sit beside the daemon; a script's own directory is sys.path[0]
  install -d -m 755 -o root -g wheel /usr/local/sbin/pfui
  install -m 644 -o root -g wheel "${DIR}"/pfui/__init__.py "${DIR}"/pfui/wire.py \
    "${DIR}"/pfui/store.py "${DIR}"/pfui/validate.py /usr/local/sbin/pfui/ \
    || die "cannot install the pfui modules"

#  cp -f "${DIR}/pfui_firewall.py" /usr/local/sbin/pfui_firewall
#  chmod 755 /usr/local/sbin/pfui_firewall
  [ -f /etc/pfui_firewall.yml ] && cp -p /etc/pfui_firewall.yml "/etc/pfui_firewall.yml.${HOUR}"
  # root-owned: the daemon only reads this, and CTL: PFCTL makes it a command source
  install -m 644 -o root -g wheel "${DIR}"/pfui_firewall.yml /etc/pfui_firewall.yml
  echo "PFUIFW: PFUI_Firewall default configuration file located at '/etc/pfui_firewall.yml' (please configure)"
#  cp -f "${DIR}/pfui_firewall.yml" /etc/pfui_firewall.yml
#  chmod 644 /etc/pfui_firewall.yml
  # root-owned: rcctl runs this as root, and a file's owner can always chmod it
  install -m 555 -o root -g wheel "${DIR}"/rc.d/pfui_firewall /etc/rc.d/pfui_firewall \
    || die "cannot install the rc.d script"
#  cp -f "${DIR}/rc.d/pfui_firewall" /etc/rc.d/pfui_firewall
#  chmod 555 /etc/rc.d/pfui_firewall

  install -m 644 -o root -g wheel "${DIR}"/examples/pf.conf /etc/pf-pfui-example.conf
  echo "PFUIFW: An example pf.conf file is located at '/etc/pf-pfui-example.conf'"

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

