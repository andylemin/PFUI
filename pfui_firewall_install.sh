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
  echo "PFUIFW: Installing Python"
  pkg_add -i python%2
  pkg_add -i py-setuptools
  pkg_add -i py-pip
  if [[ ! -e /usr/local/bin/python && -e /usr/local/bin/python2 ]]; then
    ln -s /usr/local/bin/python2 /usr/local/bin/python
  fi
  pkg_add -i python%3
  pkg_add -i py3-setuptools
  pkg_add -i py3-pip
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

  rcctl enable pfui_firewall
  rcctl restart pfui_firewall

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

test $err = 0 # Return non-zero if any command failed
