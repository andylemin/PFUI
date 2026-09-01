#!/usr/bin/env bash
#
# Builds Unbound with Python module support enabled, and adds PFUI_Unbound configuration
# https://github.com/NLnetLabs/unbound
#

# Exported so unbound_release.sh resolves tags from the same repository this
# clones from, rather than each holding its own copy of the URL
export UNBOUND_REPO="https://github.com/NLnetLabs/unbound.git"
# Which Unbound to build. "latest" asks the upstream repository for its newest
# release tag at run time; set an explicit tag (Eg, UNBOUND_VERSION=release-1.25.2)
# to pin, or "master" to build the development head. The resolution and the
# pinned fallback live in client-unbound/tools/unbound_release.sh, which the
# container that tests this build uses too.
UNBOUND_VERSION="${UNBOUND_VERSION:-latest}"

err=0
trap 'err=1' ERR

# Abort immediately on a step nothing can proceed without
die() {
  echo "PFUIDNS: FATAL: $*" >&2
  exit 1
}

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
  echo "WARNING: this DELETES /usr/ports/* and /usr/src/* after verifying the"
  echo "         signed replacements. Any local changes in those trees are lost."
  read -p "Type 'yes' to proceed, anything else to skip: " yn
  [ "$yn" = "yes" ] && yn="y"
  if [[ "$yn" = "y" ]]; then
    REL=$(uname -r)
    echo "PFUIDNS: Downloading OpenBSD ${REL} sources to /tmp"
    for f in ports src sys; do
      curl -fsSL "https://cdn.openbsd.org/pub/OpenBSD/${REL}/${f}.tar.gz" \
        -o "/tmp/${f}.tar.gz" || die "download of ${f}.tar.gz failed"
    done
    curl -fsSL "https://cdn.openbsd.org/pub/OpenBSD/${REL}/SHA256.sig" \
      -o /tmp/SHA256.sig || die "download of SHA256.sig failed"

    # Verify BEFORE touching /usr/src or /usr/ports. Previously signify's exit
    # status was ignored and the trees were deleted before any download
    # succeeded, so a failed fetch left the host with no sources at all and
    # unverified content was extracted as root.
    cd /tmp || die "cannot cd /tmp"
    signify -Cp "/etc/signify/openbsd-$(echo "${REL}" | cut -c 1,3)-base.pub" \
      -x SHA256.sig ports.tar.gz src.tar.gz sys.tar.gz \
      || die "source signature verification FAILED, /usr/src and /usr/ports untouched"
    echo "PFUIDNS: Signatures verified"

    echo "PFUIDNS: Cleaning OpenBSD Sources base (can take a while)"
    rm -rf /usr/ports/*
    rm -rf /usr/src/*

    echo "PFUIDNS: Extracting Ports Sources: ports (can take a while)"
    cd /usr || die "cannot cd /usr"
    tar xzf /tmp/ports.tar.gz || die "extract of ports.tar.gz failed"
    echo "PFUIDNS: Extracting System Sources: src (can take a while)"
    cd /usr/src || die "cannot cd /usr/src"
    tar xzf /tmp/src.tar.gz || die "extract of src.tar.gz failed"
    echo "PFUIDNS: Extracting System Sources: sys (can take a while)"
    tar xzf /tmp/sys.tar.gz || die "extract of sys.tar.gz failed"
    echo "PFUIDNS: Removing downloaded sources"
    rm -f /tmp/ports.tar.gz /tmp/src.tar.gz /tmp/sys.tar.gz /tmp/SHA256.sig
    echo "PFUIDNS: System Sources update complete"
  else
    echo "PFUIDNS: Using your existing System Sources"
    echo "PFUIDNS: If build errors occur, it is likely a source tree issue"
  fi

elif [[ "$OS" = "FreeBSD" ]]; then
  # The FreeBSD path never built Unbound (that block is OpenBSD-only) and then
  # ran the OpenBSD-only tail regardless, so it could only ever half-install.
  echo "PFUIDNS: FreeBSD support is not implemented yet (README calls it alpha)."
  echo "PFUIDNS: PFUI_Unbound must currently be installed on OpenBSD."
  exit 3
fi

echo
echo "PFUIDNS: Installing PFUI Python dependencies"
# The resolver runs unchrooted (chroot: "" in pfui_unbound.conf), so the module
# imports these from the system interpreter's site-packages
python3 -m pip install -r "${DIR}/client-unbound/requirements.txt" \
  || die "cannot install Python dependencies"

if [[ "$OS" = "OpenBSD" ]]; then
  if [ ! -d "${TARGET}" ]; then
    mkdir -p "${TARGET}"
  fi

  echo
  read -p "Would you like to build Unbound with Python module support (required) y/n: " yn
  if [[ "$yn" = "y" ]]; then
    RELEASE_HELPER="${DIR}/client-unbound/tools/unbound_release.sh"
    [ -x "${RELEASE_HELPER}" ] || die "${RELEASE_HELPER} is missing or not executable"
    echo "PFUIDNS: Resolving which Unbound to build (UNBOUND_VERSION=${UNBOUND_VERSION})"
    UNBOUND_REF=$("${RELEASE_HELPER}" "${UNBOUND_VERSION}") \
      || die "cannot resolve which Unbound release to build"
    echo "PFUIDNS: Building Unbound ${UNBOUND_REF} with Python Module Support"

    # Only move the pristine port aside once: a second run would otherwise
    # overwrite unbound.base with the previous clone, and Makefile.bsd-wrapper
    # is the one thing that has to come from base
    if [ ! -d /usr/src/usr.sbin/unbound.base ]; then
      echo "PFUIDNS: Moving default Unbound source in OpenBSD tree to one side (/usr/src/usr.sbin/unbound.base)"
      mv /usr/src/usr.sbin/unbound /usr/src/usr.sbin/unbound.base \
        || die "cannot move /usr/src/usr.sbin/unbound aside"
    fi
    [ -f /usr/src/usr.sbin/unbound.base/Makefile.bsd-wrapper ] \
      || die "no Makefile.bsd-wrapper in /usr/src/usr.sbin/unbound.base; update the system sources first"
    rm -rf /usr/src/usr.sbin/unbound

    echo "PFUIDNS: Downloading Unbound ${UNBOUND_REF} into /usr/src/usr.sbin/unbound"
    # --branch takes a tag, so a single-commit clone lands directly on the wanted
    # release. The old form cloned the default branch and then tried to check out
    # another ref, which --depth had already made unavailable
    git clone --depth 1 --branch "${UNBOUND_REF}" "${UNBOUND_REPO}" \
      /usr/src/usr.sbin/unbound \
      || die "cannot clone Unbound ${UNBOUND_REF} (does that tag or branch exist?)"

    echo "PFUIDNS: Import OpenBSD make wrapper from base to latest source"
    cp /usr/src/usr.sbin/unbound.base/Makefile.bsd-wrapper /usr/src/usr.sbin/unbound/Makefile.bsd-wrapper \
      || die "cannot import Makefile.bsd-wrapper"

    echo "PFUIDNS: Building"
    cd /usr/src/usr.sbin/unbound || die "cannot cd to the Unbound source"
    # Use same build options as Unbound on OpenBSD, but with pythonmodule enabled
    # Every step below is checked: an unnoticed configure failure used to be
    # followed by make and install-all anyway, leaving whatever those produced
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
                --without-pthreads \
      || die "Unbound ${UNBOUND_REF} failed to configure. Re-run pinned to a known release, Eg 'UNBOUND_VERSION=release-1.25.2 $0 ${TARGET}'"
    make -f Makefile.bsd-wrapper || die "Unbound ${UNBOUND_REF} failed to build"
    make install-all || die "Unbound ${UNBOUND_REF} failed to install"
    make clean
  fi

  echo "PFUIDNS: Installing PFUI_Unbound and Configuration (Python Module for Unbound)"

  # Install PFUI_Unbound module example configuration
  echo
  read -p "Would you like to install the example pfui_unbound.yml (existing will be backed up) y/n: " yn
  if [[ "$yn" = "y" ]]; then
    [ -f "${TARGET}/pfui_unbound.yml" ] && mv "${TARGET}/pfui_unbound.yml" "${TARGET}/pfui_unbound.yml.${HOUR}"
    install -m 644 -o root -g wheel "${DIR}"/client-unbound/pfui_unbound.yml ${TARGET}/pfui_unbound.yml
  fi
  echo "Default pfui_unbound config: ${TARGET}/pfui_unbound.yml"

  # Install PFUI_Unbound module script
  install -m 644 -o root -g wheel "${DIR}"/client-unbound/pfui_unbound.py ${TARGET}/pfui_unbound.py
  # Shared protocol module; pfui_unbound.py adds its own directory to sys.path
  install -m 644 -o root -g wheel "${DIR}"/protocol/python/pfui_wire.py ${TARGET}/
  # Install PFUI_Unbound RC script
  # root-owned: rcctl runs this as root, and a file's owner can always chmod it
  install -m 555 -o root -g wheel "${DIR}"/client-unbound/rc.d/pfui_unbound /etc/rc.d/pfui_unbound

  # Same-host deployment: if PFUI_Firewall is installed here too, the resolver can
  # reach it over the local socket instead of loopback TCP. Group _pfui is what
  # permits that, and it only exists once install-server-python.sh has run
  echo
  if groupinfo _pfui >/dev/null 2>&1; then
    echo "PFUIDNS: PFUI_Firewall is installed on this host (group '_pfui' exists)"
    if groupinfo _pfui | grep -qw _unbound; then
      echo "PFUIDNS: '_unbound' is already in '_pfui'"
    else
      # -G replaces secondary memberships on OpenBSD. _unbound is a base system
      # account with none by default, but any that exist are preserved here
      EXISTING=$(id -Gn _unbound 2>/dev/null | tr ' ' '\n' | grep -v '^_unbound$' | paste -sd, -)
      if [ -n "${EXISTING}" ]; then
        usermod -G "${EXISTING},_pfui" _unbound || die "cannot add _unbound to _pfui"
      else
        usermod -G _pfui _unbound || die "cannot add _unbound to _pfui"
      fi
      echo "PFUIDNS: Added '_unbound' to group '_pfui' (permits the local PFUI socket)"
    fi
    echo "PFUIDNS: To use it, set SOCKET_UNIX in /etc/pfui_firewall.yml and add"
    echo "         '- SOCKET: /var/run/pfui/pfui_firewall.sock' to FIREWALLS in"
    echo "         ${TARGET}/pfui_unbound.yml, then restart both services."
    echo "PFUIDNS: NB Unbound must be restarted for the new group to take effect."
  else
    echo "PFUIDNS: No '_pfui' group, so PFUI_Firewall is not installed on this host;"
    echo "         the resolver will reach its firewall(s) over the network."
  fi

  echo
  echo "PFUIDNS: Installing Root Hints and example DNS-BL"
  [ -f "${TARGET}/update_root_hints.sh" ] && mv "${TARGET}/update_root_hints.sh" "${TARGET}/update_root_hints.sh.${HOUR}"
  # root-owned: these run from cron with the privilege to write /var/unbound and restart the service
  install -m 755 -o root -g wheel "${DIR}"/client-unbound/tools/update_root_hints.sh ${TARGET}/update_root_hints.sh
  [ -f "${TARGET}/update_dns_blocklist.sh" ] && mv "${TARGET}/update_dns_blocklist.sh" "${TARGET}/update_dns_blocklist.sh.${HOUR}"
  install -m 755 -o root -g wheel "${DIR}"/client-unbound/tools/update_dns_blocklist.sh ${TARGET}/update_dns_blocklist.sh
  echo "New scripts: ${TARGET}/update_root_hints.sh, ${TARGET}/update_dns_blocklist.sh"

  # Install Unbound example configuration with PFUI_Unbound enabled
  echo
  read -p "Would you like to install the example pfui_unbound.conf (existing will be backed up) y/n: " yn
  if [[ "$yn" = "y" ]]; then
    echo "Installing example ${TARGET}/pfui_unbound.conf"
    [ -f "${TARGET}/pfui_unbound.conf" ] && mv "${TARGET}/pfui_unbound.conf" "${TARGET}/pfui_unbound.conf.${HOUR}"
    install -m 644 -o root -g wheel "${DIR}/client-unbound/examples/pfui_unbound.conf" \
      "${TARGET}/pfui_unbound.conf" || die "cannot install pfui_unbound.conf"
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

# Not written automatically: the previous version expanded ${PATH} at install
# time and appended a frozen snapshot to root's .zshrc, .kshrc and .bashrc.
echo
echo "PFUIDNS: /usr/local/sbin must precede /usr/sbin in PATH to pick up the"
echo "         Unbound built here. Add this to your shell rc file if needed:"
echo '         export PATH=/usr/local/sbin:$PATH'

echo
if [[ $err != 0 ]]; then
  echo "PFUIDNS: All built, but with some errors. Please investigate."
  exit 1
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
echo "Start Unbound (+pythonmodule);   'rcctl start pfui_unbound'"
echo
echo "4) Setup a DNS blocklist source. Eg, https://www.geoghegan.ca/unbound-adblock.html (See README for PFUI compatibility and install steps)"
echo
echo "5) Add the DNS blocklist updater script(s) to CRON"
echo
