#!/usr/bin/env bash

# Updating Root Anchors https://data.iana.org/root-anchors/

args=("$@")
RESTARTPFUI=${args[0]}

/usr/bin/logger -p daemon.info -t update_root_hints.sh "Updating DNS DNSSEC Root Key"
unbound-anchor -a "/var/unbound/db/root.key"

# https://data.iana.org/root-anchors/
/usr/bin/logger -p daemon.info -t update_root_hints.sh "Updating DNS Root Hints Servers"
# HTTPS, and -f so an HTTP error body is not promoted to root.hints. The old
# form tested $? after two comment lines, so it checked curl only by accident.
if curl -fsSL https://www.internic.net/domain/named.root -o /var/unbound/etc/named.cache; then
  mv /var/unbound/etc/named.cache /var/unbound/etc/root.hints
  chown root:_unbound /var/unbound/etc/root.hints
  chmod 644 /var/unbound/etc/root.hints
else
  /usr/bin/logger -p daemon.err -t update_root_hints.sh "Root hints download failed, keeping the previous root.hints"
  echo "update_root_hints.sh: download failed, previous root.hints kept" >&2
  exit 1
fi

if [[ "$RESTARTPFUI" != "norestart" ]]; then
  rcctl restart pfui_unbound
fi

