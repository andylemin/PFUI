#!/usr/bin/env bash

# Example DNS BlockList script to download common bad domains from some example well known sources

args=("$@")
RESTARTPFUI=${args[0]}

/usr/bin/logger -p daemon.info -t update_dns_blocklist.sh "Updating DNS Domain Filter Lists"

# https://github.com/StevenBlack/hosts
/usr/bin/logger -p daemon.info -t update_dns_blocklist.sh "Downloading StevenBlack Bad Domains - Unified hosts (adware + malware) + fakenews + gambling"
curl -fsSL https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts -o /var/unbound/etc/stephenblack_adware_malware_fakenews_gambling-raw
if [[ $? != 0 ]]; then
    # Fallback is plain HTTP and unauthenticated: content is not verified
    curl -fsSL http://sbc.io/hosts/alternates/fakenews-gambling/hosts -o /var/unbound/etc/stephenblack_adware_malware_fakenews_gambling-raw
fi
/usr/bin/logger -p daemon.info -t update_dns_blocklist.sh "Downloading StevenBlack Bad Domains - Unified hosts (adware + malware) + fakenews + gambling + social"
curl -fsSL https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-social/hosts -o /var/unbound/etc/stephenblack_adware_malware_fakenews_gambling_social-raw
if [[ $? != 0 ]]; then
    # Fallback is plain HTTP and unauthenticated: content is not verified
    curl -fsSL http://sbc.io/hosts/alternates/fakenews-gambling-social/hosts -o /var/unbound/etc/stephenblack_adware_malware_fakenews_gambling_social-raw
fi
/usr/bin/logger -p daemon.info -t update_dns_blocklist.sh "Converting StevenBlack Bad Domains from RAW format to Unbound config format"
cat /var/unbound/etc/stephenblack_adware_malware_fakenews_gambling-raw | grep '^0\.0\.0\.0' | awk '{print "local-zone: \""$2"\" redirect\nlocal-data: \""$2" A 0.0.0.0\""}' > /var/unbound/etc/stephenblack_adware_malware_fakenews_gambling-unbound
cat /var/unbound/etc/stephenblack_adware_malware_fakenews_gambling_social-raw | grep '^0\.0\.0\.0' | awk '{print "local-zone: \""$2"\" redirect\nlocal-data: \""$2" A 0.0.0.0\""}' > /var/unbound/etc/stephenblack_adware_malware_fakenews_gambling_social-unbound

echo
/usr/bin/logger -p daemon.info -t update_dns_blocklist.sh "Downloading YoYo AdServers Bad Domains"
curl -fsSL "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=unbound&showintro=0&mimetype=plaintext" -o /var/unbound/etc/yoyo_adservers-unbound

echo
/usr/bin/logger -p daemon.info -t update_dns_blocklist.sh "Merging all Bad Domains"
cat /var/unbound/etc/stephenblack_adware_malware_fakenews_gambling_social-unbound > /var/unbound/etc/dns_blocklist_all
cat /var/unbound/etc/yoyo_adservers-unbound >> /var/unbound/etc/dns_blocklist_all

echo
/usr/bin/logger -p daemon.info -t update_dns_blocklist.sh "Sorting, filtering and de-duplicating all Bad Domains"
# Add 'grep -v -f /var/unbound/etc/dns_blocklist_exceptions' here to allowlist domains
sort -u /var/unbound/etc/dns_blocklist_all > /var/unbound/etc/dns_blocklist
echo
echo "Written DNS-BL to: /var/unbound/etc/dns_blocklist"
echo "Define 'include: /var/unbound/etc/dns_blocklist' in /var/unbound/etc/pfui_unbound.conf"

echo
/usr/bin/logger -p daemon.info -t update_dns_blocklist.sh "Restarting PFUI_Unbound to apply updates"
chown root:_unbound /var/unbound/etc/dns_blocklist

if [[ "$RESTARTPFUI" != "norestart" ]]; then
  rcctl restart pfui_unbound
fi
echo
