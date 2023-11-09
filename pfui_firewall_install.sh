#!/usr/bin/env bash
#
# Installs PFUI Firewall
#

err=0
trap 'err=1' ERR

args=("$@")
SETPFCONF=${args[0]}

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

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

  groupadd _pfui_firewall
  adduser -batch _pfui_firewall _pfui_firewall _pfui_firewall _pfui_firewall -silent
  echo "This script needs to interact with PF through /dev/pf and ioctl messages"
  user mod -G wheel _pfui_firewall

  # TODO: Get everything using _pfui_firewall user

  echo "PFUIFW: Creating Python virtual environment and installing dependencies"
  python -m venv pfui_firewall
  ./pfui_firewall/bin/pip install --upgrade pip
  ./pfui_firewall/bin/pip install redis pyyaml service lz4
#  echo "PFUIFW: Installing Python Libraries"
#  python3 -m pip install redis pyyaml service lz4
#  ldconfig -mv /usr/local/lib

# TODO Get pfui_firewall daemon working with venv. Needs to be in directory with daemon?

  echo "PFUIFW: Installing PFUI Firewall Service (will backup any existing pfui_firewall configuration)"
  install -m 755 -o root -g wheel pfui_firewall.py /usr/local/sbin/pfui_firewall
  # TODO Get this running with _pfui_firewall user
  # chmod a+s /usr/local/sbin/pfui_firewall
  chmod 775 /var/run

#  cp -f "${DIR}/pfui_firewall.py" /usr/local/sbin/pfui_firewall
#  chmod 755 /usr/local/sbin/pfui_firewall
  [ -f "${TARGET}/pfui_firewall.yml" ] && mv "${TARGET}/pfui_firewall.yml" "${TARGET}/pfui_firewall.yml.${HOUR}"
  install -m 644 -o _pfui_firewall -g _pfui_firewall pfui_firewall.yml /etc/pfui_firewall.yml
  echo "PFUIFW: PFUI_Firewall default configuration file located at '/etc/pfui_firewall.yml' (please configure)"
#  cp -f "${DIR}/pfui_firewall.yml" /etc/pfui_firewall.yml
#  chmod 644 /etc/pfui_firewall.yml
  install -m 555 -o _pfui_firewall -g _pfui_firewall rc.d/pfui_firewall /etc/rc.d/pfui_firewall
#  cp -f "${DIR}/rc.d/pfui_firewall" /etc/rc.d/pfui_firewall
#  chmod 555 /etc/rc.d/pfui_firewall

  cp -f "${DIR}/examples/pf.conf" /etc/pf-pfui-example.conf
  echo "PFUIFW: An example pf.conf file is located at '/etc/pf-pfui-example.conf'"

  echo "PFUIFW: Updating Persist files /var/spool/pfui_ipv<*>_domains"
  touch /var/spool/pfui_ipv4_domains
  touch /var/spool/pfui_ipv6_domains
  chmod 666 /var/spool/pfui_ipv4_domains
  chmod 666 /var/spool/pfui_ipv6_domains
  chown root:wheel /var/spool/pfui_ipv4_domains
  chown root:wheel /var/spool/pfui_ipv6_domains
fi

if [[ $err != 0 ]]; then
  echo "PFUIFW: All Completed, but with some errors. Please investigate."
else
  echo "PFUIFW: All Completed successfully."
fi
echo "PFUIFW: Enable service 'rcctl enable pfui_firewall'"
echo "PFUIFW: Start service 'rcctl start pfui_firewall'"

