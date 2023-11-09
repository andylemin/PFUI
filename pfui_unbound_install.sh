#!/usr/bin/env bash
#
# Builds Unbound with Python module support enabled, and adds PFUI_Unbound configuration
# https://github.com/NLnetLabs/unbound
#

UNBOUND_BRANCH="branch-1.18.0"  # Stable Unbound branch to use if HEAD is not building without error

err=0
trap 'err=1' ERR

args=("$@")
TARGET=${args[0]}
if [[ -z ${TARGET} ]]; then  # True if length zero
  TARGET="/var/unbound/etc"
fi

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
HOUR=$(date +%d-%b-%H_%M)

if [[ $(id -u) -ne 0 ]]; then
  echo "PFUIDNS: Please run installer as root (to build and install). Unbound runs with '_unbound' user"
  exit 1
fi

echo "*****************************************************************************"
echo "* Welcome to the PFUI_Unbound Installer (https://github.com/andylemin/PFUI) *"
echo "*****************************************************************************"

if [[ $(uname) == "OpenBSD" ]]; then
  OS="OpenBSD"
elif [[ $(uname) == "FreeBSD" ]]; then
  OS="FreeBSD"
else
  echo "PFUIDNS: Looks like this is a non-supported operating system."
  echo "Supported OS: OpenBSD (PFUI_Unbound & PFUI_Firewall), FreeBSD (PFUI_Unbound - Testing)"
  exit 2
fi

if [[ "$OS" = "OpenBSD" ]]; then
  echo "PFUIDNS: Installing Python3 and dependencies"
  pkg_add -i python3 py3-setuptools py3-pip
  retval="$?"
  if [ $retval -ne 0 ]; then
    echo "* Errors trying to install Python. Please resolve and restart pfui_unbound_install.sh"
    exit $retval
  fi

  which python >/dev/null
  if [[ $? != 0 ]]; then
    ln -s "$(which python3)" /usr/local/bin/python
  fi
  PYTHONVER=$(python -V | awk '{ print $2 }')
  PYTHONMAGOR=${PYTHONVER%%.*}
  if [ "$PYTHONMAGOR" -lt 3 ]; then
    echo "PFUIDNS: ERROR, Default Python Version must be Python3. Current default '$(python -V)'"
  else
    echo "PFUIDNS: Default Python must be Python3. Current default is ok '$(python -V)'"
  fi

  echo
  echo "PFUIDNS: Installing Package Dependencies"
  pkg_add -i swig git bash cmake libconfig libiconv bison gawk mawk m4 gettext-runtime gettext-tools py3-openssl curl
  retval="$?"
  if [ $retval -ne 0 ]; then
    echo "* Errors trying to install common dependencies. Please resolve and restart pfui_unbound_install.sh"
    exit $retval
  fi

  echo "PFUIDNS: For the following programs, please choose the latest offered flavour"
  pkg_add -i gcc g++ openssl sphinx
  ldconfig -mv /usr/local/lib

  if [[ -z ${TARGET} ]]; then  # True if length zero
    TARGET="/var/unbound/etc"
    echo "PFUIDNS: Using default TARGET: $TARGET"
  fi

  echo
  echo "Would you like to update the OpenBSD System and Ports source trees; /usr/ports, /usr/src, /usr/src"
  read -p "(WARNING: Deletes any local tree changes) y/n: " yn
  if [[ "$yn" = "y" ]]; then
    echo "PFUIDNS: Cleaning OpenBSD Sources base (can take a while)"
    rm -rf /usr/ports/*
    rm -rf /usr/src/*
    cd /tmp/ || exit
    echo "PFUIDNS: Downloading Ports Sources: ports"
    curl "https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/ports.tar.gz" > "./ports.tar.gz"
    curl "https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/SHA256.sig" > "./SHA256.sig"
    signify -Cp "/etc/signify/openbsd-$(uname -r | cut -c 1,3)-base.pub" -x SHA256.sig ports.tar.gz
    echo "PFUIDNS: Downloading System Sources: src"
    curl "https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/src.tar.gz" > "./src.tar.gz"
    curl "https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/SHA256.sig" > "./SHA256.sig"
    signify -Cp "/etc/signify/openbsd-$(uname -r | cut -c 1,3)-base.pub" -x SHA256.sig src.tar.gz
    echo "PFUIDNS: Downloading System Sources: sys"
    curl "https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/sys.tar.gz" > "./sys.tar.gz"
    curl "https://cdn.openbsd.org/pub/OpenBSD/$(uname -r)/SHA256.sig" > "./SHA256.sig"
    signify -Cp "/etc/signify/openbsd-$(uname -r | cut -c 1,3)-base.pub" -x SHA256.sig sys.tar.gz
    echo

    echo "PFUIDNS: Extracting Ports Sources: ports (can take a while)"
    cd /usr || exit
    tar xzf /tmp/ports.tar.gz
    echo "PFUIDNS: Extracting System Sources: src (can take a while)"
    cd /usr/src || exit
    tar xzf /tmp/src.tar.gz
    echo "PFUIDNS: Extracting System Sources: sys (can take a while)"
    tar xzf /tmp/sys.tar.gz
    echo "PFUIDNS: Removing downloaded sources"
    rm /tmp/ports.tar.gz
    rm /tmp/src.tar.gz
    rm /tmp/sys.tar.gz
    rm /tmp/SHA256.sig
    echo "PFUIDNS: System Sources update complete"
  else
    echo "PFUIDNS: Using your existing System Sources"
    echo "PFUIDNS: If build errors occur, it is likely a source tree issue"
  fi

elif [[ "$OS" = "FreeBSD" ]]; then
  echo "PFUIDNS: Installing Python3"
  pkg install python39
  pkg install py39-setuptools
  pkg install py37-pip

  echo "PFUIDNS: Installing Package Dependencies"
  pkg install swig git cmake libconfig libiconv bison gawk mawk devel/gettext

  if [[ -z ${TARGET} ]]; then  # True if length zero
    TARGET="/var/unbound/conf.d"
    echo "PFUIDNS: Using default TARGET $TARGET"
  fi
fi

echo
echo "PFUIDNS: Installing PFUI Python dependencies"
python3 -m pip install pyyaml lz4

if [[ "$OS" = "OpenBSD" ]]; then
  if [ ! -d "${TARGET}" ]; then
    mkdir -p "${TARGET}"
  fi

  echo
  read -p "Would you like to build Unbound with Python module support (required) y/n: " yn
  if [[ "$yn" = "y" ]]; then
    echo "PFUIDNS: Building Unbound with Python Module Support"
    echo "PFUIDNS: Moving default Unbound source in OpenBSD tree to one side (/usr/src/usr.sbin/unbound.base)"
    mv /usr/src/usr.sbin/unbound /usr/src/usr.sbin/unbound.base
    echo "PFUIDNS: Downloading latest Unbound Source into /usr/src/usr.bin"
    git clone --depth 20 https://github.com/NLnetLabs/unbound.git /usr/src/usr.sbin/unbound
    echo "PFUIDNS: Import OpenBSD make wrapper from base to latest source"
    cp /usr/src/usr.sbin/unbound.base/Makefile.bsd-wrapper /usr/src/usr.sbin/unbound/Makefile.bsd-wrapper

    echo "PFUIDNS: Building"
    cd /usr/src/usr.sbin/unbound || exit
    # Use same build options as Unbound on OpenBSD, but with pythonmodule enabled
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
                --disable-shared \
                --disable-explicit-port-randomisation \
                --without-pthreads
    if [[ $? != 0 ]]; then
      echo "PFUIDNS: Unbound failed to configure with the current HEAD, trying release branch"
      git checkout $UNBOUND_BRANCH  # HEAD of Unbound is occasionally unstable
      make clean
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
                  --disable-shared \
                  --disable-explicit-port-randomisation \
                  --without-pthreads
    fi
    make -f Makefile.bsd-wrapper
    make install-all
    make clean
  fi

  echo "PFUIDNS: Installing PFUI_Unbound and Configuration (Python Module for Unbound)"

  # Install PFUI_Unbound module example configuration
  echo
  read -p "Would you like to install the example pfui_unbound.yml (existing will be backed up) y/n: " yn
  if [[ "$yn" = "y" ]]; then
    [ -f "${TARGET}/pfui_unbound.yml" ] && mv "${TARGET}/pfui_unbound.yml" "${TARGET}/pfui_unbound.yml.${HOUR}"
    install -m 775 -o _unbound -g _unbound "${DIR}"/pfui_unbound.yml ${TARGET}/pfui_unbound.yml
  fi
  echo "Default pfui_unbound config: ${TARGET}/pfui_unbound.yml"

  # Install PFUI_Unbound module script
  install -m 775 -o _unbound -g _unbound "${DIR}"/pfui_unbound.py ${TARGET}/pfui_unbound.py
  # Install PFUI_Unbound RC script
  install -m 555 -o _unbound -g _unbound "${DIR}"/rc.d/openbsd_pfui_unbound /etc/rc.d/pfui_unbound

  echo
  echo "PFUIDNS: Installing Root Hints and example DNS-BL"
  [ -f "${TARGET}/update_root_hints.sh" ] && mv "${TARGET}/update_root_hints.sh" "${TARGET}/update_root_hints.sh.${HOUR}"
  install -m 775 -o _unbound -g _unbound "${DIR}"/update_root_hints.sh ${TARGET}/update_root_hints.sh
  [ -f "${TARGET}/update_dns_blocklist.sh" ] && mv "${TARGET}/update_dns_blocklist.sh" "${TARGET}/update_dns_blocklist.sh.${HOUR}"
  install -m 775 -o _unbound -g _unbound "${DIR}"/update_dns_blocklist.sh ${TARGET}/update_dns_blocklist.sh
  echo "New scripts: ${TARGET}/update_root_hints.sh, ${TARGET}/update_dns_blocklist.sh"

  # Install Unbound example configuration with PFUI_Unbound enabled
  echo
  read -p "Would you like to install the example pfui_unbound.conf (existing will be backed up) y/n: " yn
  if [[ "$yn" = "y" ]]; then
    echo "Installing example ${TARGET}/pfui_unbound.conf"
    [ -f "${TARGET}/pfui_unbound.conf" ] && mv "${TARGET}/pfui_unbound.conf" "${TARGET}/pfui_unbound.conf.${HOUR}"
    install -m 775 -o _unbound -g _unbound "${DIR}/pfui_unbound.conf" "${TARGET}/pfui_unbound.conf"
    cp -f "${DIR}/pfui_unbound.conf" "${TARGET}/pfui_unbound.conf"
    chmod 644 ${TARGET}/pfui_unbound.conf
  fi
  echo "Default pfui_unbound config: ${TARGET}/pfui_unbound.conf"
fi

echo
echo "PFUIDNS: Updating DNS root keys and certs"
cd /var/unbound/etc/ || exit
unbound-anchor -a "/var/unbound/db/root.key"
unbound-control-setup
echo "PFUIDNS: Updating DNS root hints"
${TARGET}/update_root_hints.sh norestart

echo
echo "Checking Unbound configuration"
/usr/local/sbin/unbound-anchor -v
/usr/local/sbin/unbound-checkconf ${TARGET}/pfui_unbound.conf

PATH_UPDATE="export 'PATH=/usr/local/sbin:${PATH}'"
if ! grep -Fxq "$PATH_UPDATE" ~/.zshrc > /dev/null
then
  echo "Updating ~/.zshrc PATH to use latest unbound with Python module support"
  echo "$PATH_UPDATE" >> ~/.zshrc
fi
if ! grep -Fxq "$PATH_UPDATE" ~/.kshrc > /dev/null
then
  echo "Updating ~/.kshrc PATH to use latest unbound with Python module support"
  echo "$PATH_UPDATE" >> ~/.kshrc
fi
if ! grep -Fxq "$PATH_UPDATE" ~/.bashrc > /dev/null
then
  echo "Updating ~/.bashrc PATH to use latest unbound with Python module support"
  echo "$PATH_UPDATE" >> ~/.bashrc
fi

echo
if [[ $err != 0 ]]; then
  echo "PFUIDNS: All built, but with some errors. Please investigate."
else
  echo "PFUIDNS: All built successfully 🍾"
fi
echo
echo "Unbound Version Info"
echo "*****************************************************************************************************************"
/usr/local/sbin/unbound -V
echo "*****************************************************************************************************************"
echo
echo "PFUIDNS: Latest Unbound (with Pythonmod) installed to '/usr/local/sbin/unbound' using service name 'pfui_unbound'"
echo "PFUIDNS: PFUI_Unbound (Unbound) configuration file located at '${TARGET}/pfui_unbound.conf'"
echo "PFUIDNS: PFUI_Unbound (PFUI Client) configuration file located at '${TARGET}/pfui_unbound.yml'"
echo
echo "The default built-in unbound package is unchanged at /usr/sbin/unbound (service name still 'unbound'). Can be used for alternate rdomains etc."
echo
echo "PFUIDNS: Next steps before complete;"
echo "1) Edit pfui_unbound config for Unbound; '${TARGET}/pfui_unbound.conf'  (unbound.conf with the following extra stanza, before forwarders:)"
echo "    module-config: 'validator python iterator'"
echo "python:"
echo "    python-script: '${TARGET}/pfui_unbound.py'"
echo
echo "2) Edit pfui_unbound config for PFUI;    '${TARGET}/pfui_unbound.yml'   (details for all PFUI_Firewall target(s))"
echo
echo "3) Enable PFUI Unbound service"
echo "Stop built-in Unbound daemon;    'rcctl stop unbound'"
echo "Disable built-in Unbound daemon; 'rcctl disable unbound'"
echo "Enable Unbound (+pythonmodule);"
echo "                                 'rcctl enable pfui_unbound'"
echo "                                 'rcctl set pfui_unbound flags '-c /var/unbound/etc/pfui_unbound.conf' '"
echo "Start Unbound (+pythonmodule);   'rcctl start pfui_unbound'"
echo
echo "4) Setup a DNS blocklist source. Eg, https://www.geoghegan.ca/unbound-adblock.html (See README for PFUI compatibility and install steps)"
echo
echo "5) Add the DNS blocklist updater script(s) to CRON"
echo
