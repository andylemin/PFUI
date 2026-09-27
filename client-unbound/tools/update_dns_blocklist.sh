#!/usr/bin/env bash

# Example DNS BlockList script: HaGeZi's pro and tif domain lists, converted to
# Unbound's local-zone format and published as one file for 'include:'.
# https://github.com/hagezi/dns-blocklists

set -u

args=("$@")
RESTARTPFUI=${args[0]:-}

ETC=${ETC:-/var/unbound/etc}   # Overridable so the guards below can be tested
PUBLISHED="${ETC}/dns_blocklist"

# A short or empty feed must never reach ${PUBLISHED}: Unbound loads it without
# complaint and every domain the list used to block resolves again, so a failed
# download would quietly turn the DNS filter off and then restart the resolver to
# apply it. Nothing is published unless the new list is plausible, and the
# resolver is only restarted when something was published. update_root_hints.sh
# guards its single download the same way.
MIN_ENTRIES=${MIN_ENTRIES:-1000}     # Absolute floor on the merged list
MIN_PERCENT=${MIN_PERCENT:-50}       # Floor relative to the list in use

log() { /usr/bin/logger -p "daemon.$1" -t update_dns_blocklist.sh "$2"; }

die() {
  log err "$1"
  echo "update_dns_blocklist.sh: $1" >&2
  echo "update_dns_blocklist.sh: ${PUBLISHED} left as it was, resolver not restarted" >&2
  exit 1
}

# fetch <destination> <url>...
# Tries each URL in turn and only replaces <destination> once one has produced a
# non-empty file, so a failure leaves yesterday's copy in place.
fetch() {
  dest=$1
  shift
  tmp="${dest}.new.$$"
  for url in "$@"; do
    if curl -fsSL "$url" -o "$tmp" && [ -s "$tmp" ]; then
      mv "$tmp" "$dest"
      return 0
    fi
    log warning "download failed, trying any remaining source: ${url}"
  done
  rm -f "$tmp"
  return 1
}

# require <path> <description>
# A source is usable if it was just downloaded or survives from a previous run.
require() {
  [ -s "$1" ] || die "$2 is unavailable and no previous copy exists ($1)"
}

# domains_to_unbound <domain list> <unbound-format>
# One domain per line, with comments and a header. A line Unbound cannot parse as
# a local-zone takes the whole include file with it, so only domains are written.
domains_to_unbound() {
  grep -E '^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$' "$1" \
    | awk '{print "local-zone: \""$1"\" redirect\nlocal-data: \""$1" A 0.0.0.0\""}' \
    > "$2"
}

lines() { wc -l < "$1" | tr -d '[:space:]'; }

log info "Updating DNS Domain Filter Lists"

# https://github.com/hagezi/dns-blocklists
# The -onlydomains variants only: wildcard/*.txt carries '*.' prefixes and
# adblock/ carries ABP filter syntax, neither of which Unbound loads.
HG_BASE=https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard
# Same content, used only if the first fails
HG_MIRROR=https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/wildcard

# pro: ads, tracking and telemetry. tif: malware, phishing and scams.
for list in pro tif; do
  log info "Downloading HaGeZi ${list} domains"
  fetch "${ETC}/hagezi_${list}-raw" \
    "${HG_BASE}/${list}-onlydomains.txt" \
    "${HG_MIRROR}/${list}-onlydomains.txt"
  require "${ETC}/hagezi_${list}-raw" "HaGeZi ${list} list"
done

log info "Converting HaGeZi domains to Unbound config format"
for list in pro tif; do
  domains_to_unbound "${ETC}/hagezi_${list}-raw" "${ETC}/hagezi_${list}-unbound"
  [ -s "${ETC}/hagezi_${list}-unbound" ] \
    || die "the HaGeZi ${list} list produced no usable domains"
done

echo
log info "Merging all Bad Domains"
cat "${ETC}/hagezi_pro-unbound" "${ETC}/hagezi_tif-unbound" \
    > "${ETC}/dns_blocklist_all" \
  || die "cannot write ${ETC}/dns_blocklist_all"

echo
log info "Sorting, filtering and de-duplicating all Bad Domains"
# Add 'grep -v -f /var/unbound/etc/dns_blocklist_exceptions' here to allowlist domains
STAGED="${PUBLISHED}.new.$$"
sort -u "${ETC}/dns_blocklist_all" > "${STAGED}" || die "cannot write ${STAGED}"

# Verify before publishing, not after
NEW=$(lines "${STAGED}")
if [ "${NEW}" -lt "${MIN_ENTRIES}" ]; then
  rm -f "${STAGED}"
  die "merged list has only ${NEW} lines, below the ${MIN_ENTRIES} minimum"
fi
if [ -s "${PUBLISHED}" ]; then
  OLD=$(lines "${PUBLISHED}")
  if [ $((NEW * 100)) -lt $((OLD * MIN_PERCENT)) ]; then
    rm -f "${STAGED}"
    die "merged list shrank from ${OLD} to ${NEW} lines, more than ${MIN_PERCENT}% down"
  fi
fi

chown root:_unbound "${STAGED}"
chmod 644 "${STAGED}"
mv "${STAGED}" "${PUBLISHED}" || die "cannot publish ${PUBLISHED}"
log info "Published ${NEW} lines to ${PUBLISHED}"

echo
echo "Written DNS-BL to: ${PUBLISHED} (${NEW} lines)"
echo "Define 'include: ${PUBLISHED}' in ${ETC}/pfui_unbound.conf"

if [[ "$RESTARTPFUI" != "norestart" ]]; then
  echo
  log info "Restarting PFUI_Unbound to apply updates"
  rcctl restart pfui_unbound
fi
echo
