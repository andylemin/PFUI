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
  cp -f ./pfui_firewall.py /usr/local/sbin/pfui_firewall.py
  chmod 755 /usr/local/sbin/pfui_firewall.py

  cp -f ./pfui_firewall.yml /etc/pfui_firewall.yml
  chmod 644 /etc/pfui_firewall.yml

  cp -f ./rc.d/pfui_firewall /etc/rc.d/pfui_firewall
  chmod 555 /etc/rc.d/pfui_firewall

  rcctl enable pfui_firewall
  rcctl restart pfui_firewall

  while [[ $PFCONF != "y" && $PFCONF != "n" ]]; do
    read -rp "Install example pf.conf rules? (Overwites any existing pf.conf) [y/n]: " -e PFCONF
  done
  if [[ "$PFCONF" == "y" ]]; then
    cp -f ./examples/pf.conf.example /etc/pf.conf
    touch /var/spool/pfui_ipv4_domains
    touch /var/spool/pfui_ipv6_domains
    chmod 666 /var/spool/pfui_ipv4_domains
    chmod 666 /var/spool/pfui_ipv6_domains
  fi

fi
