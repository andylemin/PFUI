# PFUI Firewall
**PFUI (Phooey [ foo-ee ]) - Packet Filter Unsolicited IPs**

interjection - Informal; "an exclamation indicating disagreement or rejection".

**PFUI Firewall** provides a "Deny-by-Default DNS Driven PF Firewall", using Unbound DNS and PF Firewall.


------
### PFUI Firewall comprises two parts;

**"PFUI Client"** - A python extension module for the [Unbound](https://nlnetlabs.nl/projects/unbound/about/) DNS resolver; reads successful DNS query responses and 
transmits all resolved IPs and TTLs to the "PFUI Server".

**"PFUI Server"** - A standalone python service; receives data from the "PFUI Client" and installs the IPs into 
local PF Tables (for use with pf.conf).

The "PFUI Server" role also maintains a Redis database, to track and perform IP expiry (TTL expired) of entries 
from the local PF Tables.


------
### The Challenge;

Traditional firewall setups allow nothing in and everything out by default.
So many environments add DNS-Blacklists (DNS-BLs) to internal DNS services to provide the filtering of 
outbound traffic.

It is common to also block UDP ports 53 and 853 ("DNS over TLS" (DoT)) outbound (excluding the internal DNS servers), 
as a means of forcing clients to use the internal DNS (running DNS-BLs), as well as minimising DNS based 
Data Exfiltration.

However, since "DNS over HTTPS" (DoH) it is now no longer possible to separate DNS from HTTPS traffic, 
to block all DNS and force the use of internal DNS-BLs.

Additionally, since "Bring Your Own Device" (BYOD) (where devices have no central control) the use of 
SSL-terminating web proxies with company certificate becomes difficult.


------
### A Solution;

**PFUI Firewall** changes the traditional filtering method by instead always _blocking_ all egress traffic by default 
(thus stopping DoH, Proxy bypasses with BYOD, Botnets, Malware, script-kiddies and hampering Hackers etc).

To permit the legitimate traffic, PFUI simply glue's the DNS layer to the Firewall, by installing every 
DNS resolved IP address into a PF Table, just in time, before the client connects to the resolved domain.


------
### Compatibility;

PFUI Client - Supports any OS Unbound does (Linux BSD etc), and requires Python 2 & 3. (TODO: Remove Python2 possible?)

PFUI Server - Supports OpenBSD and FreeBSD, and requires Python 3.


------
### Known Issues;

Unbound with PFUI Server - Does **not** currently support 'chroot' environments as the Python dependencies need to
also reside in the jailed environment. Virtualenv planned for stable release. Disable chroot for Beta testing.


------
### Recommendations;

- It is recommended to configure the PF firewall to only allow connections on the pfui_firewall port
from the Unbound DNS servers running the pfui_unbound (PFUI does not implement authentication or encryption for 
performance as DNS resolved IPs must be installed in the firewall before the client connects to those IPs).

- It is recommended to not allow all TCP/UDP ports out by default. Only allow ports to known wanted applications.

- To ensure local firewall traffic can flow, install Unbound with PFUI_Unbound on every firewall running
PFUI_Firewall, and configure /etc/resolv.conf on the firewall so all DNS queries flow through Unbound with PFUI.


------
### Docs;
The Unbound "Python Module" [documentation](docs.html.pythonmod/index.html) has been included here for reference 
(requires compiling from source) and all rights remain with nlnetlabs.
The Python Module documentation for Unbound was built with SWIG on: Sep 3 13:18 2019


------
### Similar Projects;
https://github.com/wupeka/dnsfire - PFUI is an analogue to DNSFire, where PFUI is for Unbound and PF rather than BIND and IPSET



