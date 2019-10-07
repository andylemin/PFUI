#!/usr/bin/env ksh

# Bogon Filters (DNS Rebinding);
## Unbound can filter rfc1918 addresses from global domains, so no need for "bogons" filters
## Set 'private-address:' in unbound.conf
#    private-address: 192.168.0.0/16
#    private-address: 172.16.0.0/12
#    private-address: 169.254.0.0/16
#    private-address: 127.0.0.0/8
#    private-address: 10.0.0.0/8


# DNS-Blacklist Filters
## Unbound can filter blacklisted domains
## Set 'include:' in unbound.conf
#    include: /var/unbound/etc/adware_malware.conf

## DNS-BL Examples using Steven Blacks Hosts - https://github.com/StevenBlack/hosts
logger -p daemon.info -t update_filtered_domains.sh "Downloading StevenBlack Hosts (Community DNS-Blacklists)"

## "Unified hosts" (adware + malware) + "fakenews"
#curl https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews/hosts -o /tmp/amf
#if [[ $? != 0 ]]; then
#  http://sbc.io/hosts/alternates/fakenews/hosts
#fi

## "Unified hosts" (adware + malware) + "fakenews" + "gambling"
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts -o /tmp/amfg
if [[ $? != 0 ]]; then
    curl http://sbc.io/hosts/alternates/fakenews-gambling/hosts -o /tmp/amfg
fi

## "Unified hosts" (adware + malware) + "fakenews" + "gambling" + "social media"
#curl https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-social/hosts -o /tmp/amfgs
#if [[ $? != 0 ]]; then
#    curl http://sbc.io/hosts/alternates/fakenews-gambling-social/hosts -o /tmp/amfgs
#fi

## Convert Host List format to Unbound format
#cat /tmp/amf | grep '^0\.0\.0\.0' | awk '{print "local-zone: \""$2"\" redirect\nlocal-data: \""$2" A 0.0.0.0\""}' \
#> /var/unbound/etc/adware_malware_fakenews

cat /tmp/amfg | grep '^0\.0\.0\.0' | awk '{print "local-zone: \""$2"\" redirect\nlocal-data: \""$2" A 0.0.0.0\""}' \
> /var/unbound/etc/adware_malware_fakenews_gambling

#cat /tmp/amfgs | grep '^0\.0\.0\.0' | awk '{print "local-zone: \""$2"\" redirect\nlocal-data: \""$2" A 0.0.0.0\""}' \
#> /var/unbound/etc/adware_malware_fakenews_gambling_social

logger -p daemon.info -t update_filtered_domains.sh "Restarting Unbound to apply DNS-BL updates"
rcctl restart pfui_unbound
