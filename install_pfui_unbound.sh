#!/usr/bin/env bash
#
# Builds Unbound with Python module support, and adds PFUI Client
#

# Set TARGET to the unbound etc directory
TARGET="/var/unbound/etc"

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
  mkdir -p ${TARGET}
  cp -f ./pfui_unbound.conf ${TARGET}/pfui_unbound.conf
  chmod 644 ${TARGET}/pfui_unbound.conf

  cp -f ./pfui_unbound.py ${TARGET}/pfui_unbound.py
  chmod 775 ${TARGET}/pfui_unbound.py

  cp -f ./pfui_unbound.yml ${TARGET}/pfui_unbound.yml
  chmod 775 ${TARGET}/pfui_unbound.yml

  cp -f ./update_root_hints.sh ${TARGET}/update_root_hints.sh
  chmod 775 ${TARGET}/update_root_hints.sh

  cp -f ./update_dns_blacklists.sh ${TARGET}/update_dns_blacklists.sh
  chmod 775 ${TARGET}/update_dns_blacklists.sh

  cp -f ./rc.d/pfui_unbound /etc/rc.d/pfui_unbound
  chmod 555 /etc/rc.d/pfui_unbound

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
              --with-conf-file=${TARGET}/pfui_unbound.conf \
              --with-username=_unbound \
              --disable-shared
  make
  make install

  rcctl enable pfui_unbound
  rcctl restart pfui_unbound

fi

