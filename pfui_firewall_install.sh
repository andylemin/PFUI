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
  echo "Supported OS: OpenBSD"
  exit 2
fi

if [[ "$OS" = "OpenBSD" ]]; then
  echo "PFUIFW: Installing Python2"
  export PKG_PATH=http://ftp.openbsd.org/pub/OpenBSD/%v/packages/%a/
  pkg_add -i python%2
  pkg_add -i py-setuptools
  pkg_add -i py-pip
  if [[ ! -e /usr/local/bin/python && -e /usr/local/bin/python2 ]]; then
    ln -s /usr/local/bin/python2 /usr/local/bin/python
  fi

  echo "PFUIFW: Installing Python3"
  pkg_add -i python%3.7; RET=$?
  if [[ ${RET} != 0 ]]; then
    pkg_add -i python%3.6; RET=$?
  fi
    if [[ ${RET} != 0 ]]; then
    pkg_add -i python%3; RET=$?
  fi
  pkg_add -i py3-setuptools
  pkg_add -i py3-pip

  echo "PFUIFW: Installing Python Libraries"
  python3 -m pip install redis pyyaml service

  echo "PFUIFW: Installing and Starting Redis"
  pkg_add -i redis
  rcctl enable redis
  rcctl start redis

  echo "PFUIFW: Installing PFUI Firewall Service"
  cp -f "${DIR}/pfui_firewall.py" /usr/local/sbin/pfui_firewall.py
  chmod 755 /usr/local/sbin/pfui_firewall.py

  cp -f "${DIR}/pfui_firewall.yml" /etc/pfui_firewall.yml
  chmod 644 /etc/pfui_firewall.yml

  cp -f "${DIR}/rc.d/pfui_firewall" /etc/rc.d/pfui_firewall
  chmod 555 /etc/rc.d/pfui_firewall

  while [[ $SETPFCONF != "y" && $SETPFCONF != "n" ]]; do
    read -rp "PFUIFW: Install example pf.conf rules? (Overwites any existing pf.conf) [y/n]: " -e SETPFCONF
  done
  if [[ "$SETPFCONF" == "y" ]]; then
    cp -f "${DIR}/examples/pf.conf.example" /etc/pf.conf
    touch /var/spool/pfui_ipv4_domains
    touch /var/spool/pfui_ipv6_domains
    chmod 666 /var/spool/pfui_ipv4_domains
    chmod 666 /var/spool/pfui_ipv6_domains
  fi
fi

if [[ $err != 0 ]]; then
  echo "PFUIFW: All Completed, but with some errors. Please investigate."
else
  echo "PFUIFW: All Completed successfully."
fi
echo "PFUIFW: PFUI_Firewall configuration file located at '/etc/pfui_firewall.yml'"
echo "PFUIFW: Enable service 'rcctl enable pfui_firewall'"
echo "PFUIFW: Start service 'rcctl start pfui_firewall'"

