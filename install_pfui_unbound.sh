#!/usr/bin/env bash
#
# Builds Unbound with Python module support, and adds PFUI Client
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
  export PKG_PATH=http://ftp.openbsd.org/pub/OpenBSD/%v/packages/%a/
  pkg_add -i python%2
  pkg_add -i py-setuptools
  pkg_add -i py-pip
  if [[ ! -e /usr/local/bin/python && -e /usr/local/bin/python2 ]]; then
    ln -s /usr/local/bin/python2 /usr/local/bin/python
  fi

  pkg_add -i python%3
  pkg_add -i py3-setuptools
  pkg_add -i py3-pip
  python -m pip install -r ./requirements_unbound.txt
  python3 -m pip install -r ./requirements_unbound.txt

  pkg_add -i swig
  pkg_add -i git

  echo "Installing PFUI for Unbound"
  cp ./unbound_pfui.conf /var/unbound/etc/unbound_pfui.conf
  chmod 644 /var/unbound/etc/unbound_pfui.conf

  cp ./pfui_client.py /var/unbound/etc/pfui_client.py
  chmod 775 /var/unbound/etc/pfui_client.py

  cp ./pfui_client.yml /var/unbound/etc/pfui_client.yml
  chmod 775 /var/unbound/etc/pfui_client.yml

  cp ./rc.d/unbound_pfui /etc/rc.d/unbound_pfui
  chmod 555 /etc/rc.d/unbound_pfui

  cp ./update_root_servers.sh /var/unbound/etc/update_root_servers.sh
  chmod 775 /var/unbound/etc/update_root_servers.sh

  cp ./update_filtered_domains.sh /var/unbound/etc/
  chmod 775 /var/unbound/etc/update_filtered_domains.sh

  echo "Downloading Unbound"
  git clone https://github.com/NLnetLabs/unbound.git /tmp/unbound

  echo "Building Unbound"
  cd /tmp/unbound
  ./configure --enable-allsymbols \
              --with-ssl=/usr \
              --with-libevent=/usr \
              --with-libexpat=/usr \
              --with-pythonmodule \
              --with-chroot-dir=/var/unbound \
              --with-pidfile="" \
              --with-rootkey-file=/var/unbound/db/root.key \
              --with-conf-file=/var/unbound/etc/unbound_pfui.conf \
              --with-username=_unbound \
              --disable-shared
  make && make install

  rcctl enable unbound_pfui
  rcctl start unbound_pfui

fi

