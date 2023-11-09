#!/usr/bin/env bash

# Updating Root Anchors https://data.iana.org/root-anchors/

args=("$@")
RESTARTPFUI=${args[0]}

/usr/bin/logger -p daemon.info -t update_root_servers.sh "Updating DNS DNSSEC Root Key"
unbound-anchor -a "/var/unbound/db/root.key"

# https://data.iana.org/root-anchors/
/usr/bin/logger -p daemon.info -t update_root_servers.sh "Updating DNS Root Hints Servers"
curl ftp://ftp.internic.net/domain/named.cache -o /var/unbound/etc/named.cache
#curl ftp://ftp.internic.net/domain/named.cache.sig -o /tmp/named.cache.sig
#/usr/local/bin/gpg --verify /tmp/named.cache.sig /var/unbound/etc/named.cache
if [[ $? == 0 ]]; then
  mv /var/unbound/etc/named.cache /var/unbound/etc/root.hints
  chown root:_unbound /var/unbound/etc/root.hints
fi

if [[ "$RESTARTPFUI" != "norestart" ]]; then
  rcctl restart pfui_unbound
fi

