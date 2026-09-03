#!/usr/bin/env bash
#
# Builds Unbound with Python module support enabled, and adds PFUI_Unbound configuration
# https://github.com/NLnetLabs/unbound
#

# Exported so unbound_release.sh resolves tags from the same repository this
# clones from, rather than each holding its own copy of the URL
export UNBOUND_REPO="https://github.com/NLnetLabs/unbound.git"
# Read-only mirror, used only when -current sources are asked for
OPENBSD_SRC_REPO="https://github.com/openbsd/src.git"
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

# Install packages without ever prompting. A release's package set holds one
# version of each package, so there is no "latest" to choose; -i only ever
# prompts when a stem matches several flavours, and answering that from a
# script is guesswork. Name the candidates instead and let the operator pick.
add_pkg() {
  local pkg
  for pkg in "$@"; do
    pkg_add -I "${pkg}" && continue
    echo "PFUIDNS: cannot install '${pkg}'. Candidates:" >&2
    pkg_info -Q "${pkg}" >&2 || true
    die "install one explicitly, Eg 'pkg_add ${pkg}-<version>'"
  done
}

# Replace /usr/src from a signed release set. Verification happens before
# anything is deleted: a failed fetch must not leave the host with no sources,
# and unverified content must never be extracted as root. /usr/ports is not
# touched, because nothing here builds from it.
fetch_release_src() {
  local rel="$1" f key verified=""
  echo "PFUIDNS: Downloading OpenBSD ${rel} sources"
  for f in src sys; do
    curl -fsSL "https://cdn.openbsd.org/pub/OpenBSD/${rel}/${f}.tar.gz" \
      -o "/tmp/${f}.tar.gz" || die "download of ${f}.tar.gz failed"
  done
  curl -fsSL "https://cdn.openbsd.org/pub/OpenBSD/${rel}/SHA256.sig" \
    -o /tmp/SHA256.sig || die "download of SHA256.sig failed"

  cd /tmp || die "cannot cd /tmp"
  for key in /etc/signify/openbsd-*-base.pub; do
    [ -f "${key}" ] || continue
    if signify -Cp "${key}" -x SHA256.sig src.tar.gz sys.tar.gz >/dev/null 2>&1; then
      verified="${key}"
      break
    fi
  done
  [ -n "${verified}" ] \
    || die "signature verification FAILED against every key in /etc/signify; /usr/src untouched"
  echo "PFUIDNS: Signatures verified with $(basename "${verified}")"

  echo "PFUIDNS: Replacing /usr/src (can take a while)"
  rm -rf /usr/src/*
  cd /usr/src || die "cannot cd /usr/src"
  tar xzf /tmp/src.tar.gz || die "extract of src.tar.gz failed"
  tar xzf /tmp/sys.tar.gz || die "extract of sys.tar.gz failed"
  rm -f /tmp/src.tar.gz /tmp/sys.tar.gz /tmp/SHA256.sig
  echo "PFUIDNS: /usr/src now holds the ${rel} sources"
}

# OpenBSD publishes no src or sys tarball for snapshots, so -current sources
# come from the read-only git mirror. Unlike a release set this is NOT signed.
# Fetched in place because /usr/src is commonly its own filesystem and cannot
# be replaced by a rename.
fetch_current_src() {
  command -v git >/dev/null || die "git is required to fetch -current sources"
  echo "PFUIDNS: Fetching -current sources from ${OPENBSD_SRC_REPO} (UNSIGNED)"
  cd /usr/src || die "cannot cd /usr/src"
  rm -rf /usr/src/* /usr/src/.git
  git init -q . || die "cannot initialise a repository in /usr/src"
  git remote add origin "${OPENBSD_SRC_REPO}" || die "cannot add the remote"
  git fetch -q --depth 1 origin master || die "cannot fetch -current sources"
  git checkout -q -f FETCH_HEAD || die "cannot check out the fetched sources"
  [ -f /usr/src/usr.sbin/unbound/Makefile.bsd-wrapper ] \
    || die "the fetched tree has no usr.sbin/unbound/Makefile.bsd-wrapper"
  echo "PFUIDNS: /usr/src now holds -current sources"
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
  echo "PFUIDNS: Installing Package Dependencies"
  # Base supplies the compiler, make, yacc, lex, awk, m4, libevent, expat and
  # LibreSSL, which is what the configure flags below point at, and pkg_add
  # resolves each package's own dependencies. Only these are missing:
  #   swig             generates the Python module bindings
  #   git              resolves the Unbound release tag and clones it
  #   curl             fetches the signed source sets, when that step is taken
  #   py3-lz4 py3-yaml imported by the resolver module
  #
  # The interpreter is not named here. There is no python3 stem to ask for,
  # only python-3.x packages with a branch each, and the py3-* packages depend
  # on the right one.
  add_pkg swig git curl py3-lz4 py3-yaml
  command -v python3 >/dev/null \
    || die "python3 is absent; name a branch explicitly, Eg 'pkg_add python%3.13'"

  # configure --with-pythonmodule looks for 'python', not 'python3'
  command -v python >/dev/null || ln -sf "$(command -v python3)" /usr/local/bin/python
  PYTHONVER=$(python -V 2>&1 | awk '{ print $2 }')
  [ "${PYTHONVER%%.*}" -ge 3 ] 2>/dev/null \
    || die "the default 'python' must be Python 3, not '${PYTHONVER}'"
  echo "PFUIDNS: Default python is ${PYTHONVER}"

  ldconfig -mv /usr/local/lib

  if [[ -z ${TARGET} ]]; then  # True if length zero
    TARGET="/var/unbound/etc"
    echo "PFUIDNS: Using default TARGET: $TARGET"
  fi

  echo
elif [[ "$OS" = "FreeBSD" ]]; then
  # The FreeBSD path never built Unbound (that block is OpenBSD-only) and then
  # ran the OpenBSD-only tail regardless, so it could only ever half-install.
  echo "PFUIDNS: FreeBSD support is not implemented yet (README calls it alpha)."
  echo "PFUIDNS: PFUI_Unbound must currently be installed on OpenBSD."
  exit 3
fi

echo
echo "PFUIDNS: Installing PFUI Python dependencies"
# The resolver runs unchrooted (chroot: "" in pfui_unbound.conf) and imports
# these through its embedded interpreter, which is the system one, so they have
# to be installed for that interpreter rather than into a virtualenv.
#
# On OpenBSD that means packages: the system interpreter is externally managed
# (PEP 668) and pip refuses to write to it.
if [[ "$OS" != "OpenBSD" ]]; then
  python3 -m pip install -r "${DIR}/client-unbound/requirements.txt" \
    || die "cannot install Python dependencies"
fi
# The interpreter the resolver embeds must be able to import these, or the
# module fails at resolver start
python3 -c "import lz4.frame, yaml" \
  || die "lz4 and yaml are not importable by $(command -v python3)"

if [[ "$OS" = "OpenBSD" ]]; then
  if [ ! -d "${TARGET}" ]; then
    mkdir -p "${TARGET}"
  fi

  # Report what is installed, so the choice below is an informed one. A module
  # upgrade is the common case and needs no rebuild.
  if [ -x /usr/local/sbin/unbound ]; then
    INSTALLED_VER=$(/usr/local/sbin/unbound -V 2>/dev/null | sed -n 's/^Version //p' | head -1)
    if /usr/local/sbin/unbound -V 2>/dev/null | grep -q pythonmodule; then
      HAVE_UNBOUND="${INSTALLED_VER:-unknown version}, with the Python module"
      BUILD_DEFAULT=1
    else
      HAVE_UNBOUND="${INSTALLED_VER:-unknown version}, WITHOUT the Python module"
      BUILD_DEFAULT=2
    fi
  else
    HAVE_UNBOUND="none at /usr/local/sbin/unbound"
    BUILD_DEFAULT=2
  fi

  echo
  echo "Unbound resolver (installed: ${HAVE_UNBOUND})"
  echo "  1) keep it, and update only the PFUI module and configuration"
  echo "  2) build and install Unbound (${UNBOUND_VERSION}) with the Python module"
  read -p "Choose 1 or 2 [${BUILD_DEFAULT}]: " build_choice
  [ -n "${build_choice}" ] || build_choice="${BUILD_DEFAULT}"
  if [[ "${build_choice}" = "2" ]]; then
    # Unbound is built with Makefile.bsd-wrapper taken from the system sources,
    # so a usable /usr/src is a prerequisite for the build below
    if [ -f /usr/src/usr.sbin/unbound/Makefile.bsd-wrapper ] \
       || [ -f /usr/src/usr.sbin/unbound.base/Makefile.bsd-wrapper ]; then
      HAVE_SRC="found"
    else
      HAVE_SRC="NOT found"
    fi

    REL=$(uname -r)
    echo "OpenBSD system sources in /usr/src (Unbound's wrapper Makefile comes from there)"
    echo "  1) keep the existing tree and carry on to the build  [${HAVE_SRC}]"
    echo "  2) replace it with the signed ${REL} release sources"
    echo "  3) replace it with -current from the git mirror (unsigned)"
    echo "Options 2 and 3 delete /usr/src/* first. /usr/ports is never touched."
    read -p "Choose 1, 2 or 3 [1]: " src_choice
    case "${src_choice}" in
      2) fetch_release_src "${REL}" ;;
      3) fetch_current_src ;;
      *)
        echo "PFUIDNS: Keeping the existing /usr/src, continuing to the build"
        [ "${HAVE_SRC}" = "found" ] \
          || echo "PFUIDNS: WARNING no Makefile.bsd-wrapper under /usr/src; choose 2 or 3 if the build fails"
        ;;
    esac

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
  else
    echo "PFUIDNS: Keeping the installed Unbound; updating the PFUI module only"
    case "${HAVE_UNBOUND}" in
      *"WITHOUT the Python module"*)
        echo "PFUIDNS: WARNING that Unbound cannot load a Python module, so PFUI" \
             "will not run in it. Re-run and choose 2." ;;
      "none at"*)
        echo "PFUIDNS: WARNING there is no Unbound to load the module." \
             "Re-run and choose 2." ;;
    esac
  fi

  echo "PFUIDNS: Installing PFUI_Unbound and Configuration (Python Module for Unbound)"

  # An existing config is kept so an upgrade does not disturb a running
  # resolver; only a first install lays down the example
  echo
  if [ -f "${TARGET}/pfui_unbound.yml" ]; then
    cp -p "${TARGET}/pfui_unbound.yml" "${TARGET}/pfui_unbound.yml.${HOUR}"
    echo "PFUIDNS: Keeping the existing ${TARGET}/pfui_unbound.yml"
    echo "PFUIDNS: (backup at ${TARGET}/pfui_unbound.yml.${HOUR}; compare it against"
    echo "         ${DIR}/client-unbound/pfui_unbound.yml for keys added since)"
  else
    install -m 644 -o root -g wheel "${DIR}"/client-unbound/pfui_unbound.yml \
      "${TARGET}/pfui_unbound.yml" || die "cannot install pfui_unbound.yml"
    echo "PFUIDNS: Default configuration installed at ${TARGET}/pfui_unbound.yml (please configure)"
  fi

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

  # The resolver's own config carries an operator's whole ruleset, so an
  # existing one is never replaced; only a first install lays down the example
  echo
  if [ -f "${TARGET}/pfui_unbound.conf" ]; then
    cp -p "${TARGET}/pfui_unbound.conf" "${TARGET}/pfui_unbound.conf.${HOUR}"
    echo "PFUIDNS: Keeping the existing ${TARGET}/pfui_unbound.conf"
    echo "PFUIDNS: (backup at ${TARGET}/pfui_unbound.conf.${HOUR}; the example is"
    echo "         ${DIR}/client-unbound/examples/pfui_unbound.conf)"
    echo "PFUIDNS: NB the python module must be enabled there for PFUI to send:"
    echo "         module-config: \"validator python iterator\""
    echo "         python: python-script: \"${TARGET}/pfui_unbound.py\""
  else
    install -m 644 -o root -g wheel "${DIR}/client-unbound/examples/pfui_unbound.conf" \
      "${TARGET}/pfui_unbound.conf" || die "cannot install pfui_unbound.conf"
    echo "PFUIDNS: Default resolver configuration installed at ${TARGET}/pfui_unbound.conf"
  fi
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
