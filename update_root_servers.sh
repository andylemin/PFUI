#!/usr/bin/env ksh

# https://data.iana.org/root-anchors/

logger -p daemon.info -t update_root_servers.sh "Updating DNS Root Hint Servers"

curl ftp://ftp.internic.net/domain/named.cache -o /var/unbound/etc/named.cache
if [[ $? == 0 ]]; then
  mv /var/unbound/etc/named.cache /var/unbound/etc/root.hints
  rcctl restart unbound_pfui
fi

