#!/usr/bin/env bash
#
# Prints the Unbound git ref to build. Used by install-client-unbound.sh and by
# the container that tests that build, so the installer and its test cannot
# disagree about which release they mean.
#
# Usage: unbound_release.sh [latest|master|release-1.26.0]
#        UNBOUND_VERSION=release-1.25.2 unbound_release.sh

UNBOUND_REPO="${UNBOUND_REPO:-https://github.com/NLnetLabs/unbound.git}"

# Used only when the upstream tag list cannot be read. Bump this when PFUI has
# been tested against a newer release.
UNBOUND_FALLBACK_TAG="release-1.26.0"

WANTED="${1:-${UNBOUND_VERSION:-latest}}"

# Newest release tag upstream, empty if the tag list cannot be read.
#
# This resolves a tag rather than a branch because release tags are permanent:
# NLnet Labs prunes its branch-<version> heads (nothing before 1.23 survives), so
# the branch-1.18.0 that PFUI used to fall back to no longer exists at all.
#
# The sort key is built by awk rather than passed to sort -V, which is a GNU
# extension OpenBSD's sort does not have.
latest_tag() {
  git ls-remote --tags --refs "${UNBOUND_REPO}" 'release-*' 2>/dev/null \
    | sed 's#.*refs/tags/##' \
    | grep -E '^release-[0-9]+\.[0-9]+(\.[0-9]+)?$' \
    | awk -F'[-.]' '{ printf "%05d%05d%05d %s\n", $2, $3, $4, $0 }' \
    | sort \
    | tail -1 \
    | cut -d' ' -f2
}

if [ "${WANTED}" = "latest" ]; then
  REF=$(latest_tag)
  if [ -z "${REF}" ]; then
    echo "unbound_release.sh: cannot read the tag list at ${UNBOUND_REPO}," \
         "falling back to ${UNBOUND_FALLBACK_TAG}" >&2
    REF="${UNBOUND_FALLBACK_TAG}"
  fi
else
  REF="${WANTED}"
fi

echo "${REF}"
