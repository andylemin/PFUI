#!/usr/bin/env bash
#
# Builds Unbound with Python module support, and adds PFUI_Unbound
#

err=0
trap 'err=1' ERR

args=("$@")
TARGET=${args[0]}
if [[ -z ${TARGET} ]]; then  # True if length zero
  TARGET="/var/unbound/etc"
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

if [[ $(id -u) -ne 0 ]]; then
  echo "PFUIDNS: Please run as root user"
  exit 1
fi

if [[ $(uname) == "OpenBSD" ]]; then
  OS="OpenBSD"
else
  echo "PFUIDNS: Looks like a non-supported operating system."
  echo "Supported OS: OpenBSD"
  exit 2
fi

if [[ "$OS" = "OpenBSD" ]]; then
  echo "PFUIFW: Installing Python"
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
  python -m pip install pyyaml
  python3 -m pip install pyyaml

  echo "PFUIFW: Installing Package Dependancies"
  pkg_add -i swig
  pkg_add -i git

  echo "PFUIDNS: Downloading Unbound Source"
  rm -rf /tmp/unbound_src
  git clone https://github.com/NLnetLabs/unbound.git /tmp/unbound_src

  echo "PFUIDNS: Building Unbound from Source with Python Module Support"
  cd /tmp/unbound_src
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

  echo "PFUIDNS: Installing PFUI Python Module for Unbound"
  if [ ! -d "${TARGET}" ]; then
    mkdir -p "${TARGET}"
  fi
  cp -f "${DIR}/pfui_unbound.conf" "${TARGET}/pfui_unbound.conf"
  chmod 644 ${TARGET}/pfui_unbound.conf

  cp -f "${DIR}/pfui_unbound.py" "${TARGET}/pfui_unbound.py"
  chmod 775 ${TARGET}/pfui_unbound.py

  cp -f "${DIR}/pfui_unbound.yml" "${TARGET}/pfui_unbound.yml"
  chmod 775 ${TARGET}/pfui_unbound.yml

  cp -f "${DIR}/update_root_hints.sh" "${TARGET}/update_root_hints.sh"
  chmod 775 ${TARGET}/update_root_hints.sh

  cp -f "${DIR}/update_dns_blacklists.sh" "${TARGET}/update_dns_blacklists.sh"
  chmod 775 ${TARGET}/update_dns_blacklists.sh

  cp -f "${DIR}/rc.d/pfui_unbound" /etc/rc.d/pfui_unbound
  chmod 555 /etc/rc.d/pfui_unbound
  rcctl enable pfui_unbound
  rcctl restart pfui_unbound

fi

test $err = 0 # Return non-zero if any command failed
