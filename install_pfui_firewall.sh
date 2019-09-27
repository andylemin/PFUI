#!/usr/bin/env bash
#
# Installs PFUI Firewall
#

if [[ $(id -u) -ne 0 ]]; then
  echo "Please run as root user"
  exit 1
fi

if [[ $(uname) == "OpenBSD" ]]; then
  OS="OpenBSD"
else
  echo "Looks like a non-supported operating system."
  echo "Supported OS: OpenBSD"
  exit 2
fi

if [[ "$OS" = "OpenBSD" ]]; then
  echo "Installing dependancies"
  pkg_add -i python%2
  pkg_add -i py-setuptools
  pkg_add -i py-pip
  if [[ ! -e /usr/local/bin/python && -e /usr/local/bin/python2 ]]; then
    ln -s /usr/local/bin/python2 /usr/local/bin/python
  fi

  pkg_add -i python%3
  pkg_add -i py3-setuptools
  pkg_add -i py3-pip
  python3 -m pip install -r ./requirements_firewall.txt

  pkg_add -i redis
  rcctl enable redis
  rcctl start redis

  echo "Installing PFUI Firewall"
  cp ./pfui_server.py /usr/local/sbin/pfui_server.py
  chmod 755 /usr/local/sbin/pfui_server.py

  cp ./pfui_server.yml /etc/pfui_server.yml
  chmod 644 /etc/pfui_server.yml

  cp ./rc.d/pfui_server /etc/rc.d/pfui_server
  chmod 555 /etc/rc.d/pfui_server

  rcctl enable pfui_server
  rcctl start pfui_server

  while [[ $PFCONF != "y" && $PFCONF != "n" ]]; do
    read -rp "Install example pf.conf rules? (Overwites any existing pf.conf) [y/n]: " -e PFCONF
  done
  if [[ "$PFCONF" == "y" ]]; then
    cp ./examples/pf.conf.example /etc/pf.conf
    touch /var/spool/pfui_ipv4_domains
    touch /var/spool/pfui_ipv6_domains
  fi

fi
