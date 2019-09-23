# PFUI Firewall
**PFUI (Phooey [ foo-ee ]) - Packet Filter Unsolicited IPs**

interjection - Informal; "an exclamation indicating disagreement or rejection".

**PFUI Firewall** provides a "Deny-by-Default DNS Driven PF Firewall", using Unbound DNS and PF Firewall.

------
### PFUI Firewall comprises two parts;

*PFUI Client* - A python extension module for the [Unbound](https://nlnetlabs.nl/projects/unbound/about/) DNS resolver; reads successful DNS query responses and 
transmits all resolved IPs and TTLs to the "PFUI Server".

*PFUI Server* - A standalone python service; receives data from the "PFUI Client" and installs the IPs into 
local PF Tables (for use with pf.conf).

The "PFUI Server" role also maintains a Redis database, to track and perform IP expiry (TTL expired) of entries 
from the local PF Tables.


------
### The Challenge;

Traditional firewall setups allow nothing in and everything out by default.
So many environments add DNS-Blacklists (DNSBLs) to internal DNS services to provide the filtering of 
outbound traffic.

It is common to also block UDP ports 53 and 853 (DNS over TLS) outbound (excluding the internal DNS servers), 
as a means of forcing clients to use the internal DNS (running DNSBLs), as well as minimising DNS based 
Data Exfiltration.

However, since "DNS over HTTPS" (DoH) it is now no longer possible to separate DNS from HTTPS traffic, 
to block all DNS from clients to enforce the use of corporate DNSBLs.

Additionally, since "Bring Your Own Device" (BYOD) (where devices have no central control) the use of 
SSL-terminating web proxies with company certificate becomes difficult.

------
### A Solution;

**PFUI** changes the traditional filtering method by instead always _blocking_ all egress traffic by default 
(thus stopping DoH, Proxy bypasses with BYOD, Botnets, Malware, script-kiddies and hampering Hackers etc).

To permit the legitimate traffic, PFUI simply glue's the DNS layer to the Firewall, by installing every 
DNS resolved IP address into a PF Table, just in time, before the client connects to the resolved domain.

------
### Compatibility;

PFUI Client - Supports any OS Unbound does (Linux BSD etc), and requires Python 2 & 3. (TODO: Remove Python2 possible?)

PFUI Server - Supports OpenBSD and FreeBSD, and requires Python 3.

------
### Recommendations;

- It is recommended to configure the PF firewall to only allow connections on the pfui_server port
from the Unbound DNS servers running the pfui_client (PFUI does not implement authentication or encryption for 
performance as DNS resolved IPs must be installed in the firewall before the client connects to those IPs).

- It is recommended to not allow all TCP/UDP ports out by default. Only allow ports to known wanted applications.

