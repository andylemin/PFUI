# PFUI Firewall
## PFUI (Phooey [ foo-ee ]) - (Packet Filter Unsolicited IPs)
interjection - Informal; "an exclamation indicating disagreement or rejection".

**PFUI Firewall** provides a "Deny-by-Default DNS Driven PF Firewall".

------
### PFUI Firewall comprises two parts;

*PFUI Client* - A python extension installed with Unbound; reads successful DNS query responses and 
transmits resolved IPs and TTLs to the PFUI Server.

*PFUI Server* - A standalone python service; receives data from the PFUI Client and installs the IPs into 
PF Tables (for use with pf.conf).

The PFUI Server also maintains a Redis database, to track and perform IP expiry (TTL expired queries) 
from the PF Tables.

------
### The Challenge;

Traditional firewall setups allow nothing in and everything out by default.
So many environments add DNS-Blacklists (DNSBLs) to company DNS services to filter outbound traffic.

It is common to also block UDP ports 53 and 853 outbound (excluding the internal DNS servers), 
as a means of enforcing the use of the internal DNS, as well as minimising DNS based Data Exfiltration.

However, since DNS-over-HTTPS (DoH) it is no longer possible to separate DNS from HTTPS traffic, 
to block all DNS and enforce the use of corporate DNSBLs.

Additionally, since Bring-Your-Own-Device (BYOD) (where devices have no central device-based
group policies) the use of SSL-terminating web proxies becomes difficult.

------
### A Solution;

**PFUI** changes the traditional filtering method by instead _blocking_ all egress traffic by default 
(disabling DoH, BYOD bypasses, Botnets, Malware, script-kiddies and hampering Hackers etc).

To permit the legitimate traffic, PFUI simply glue's the DNS layer to the Firewall by installing every 
resolved IP address into a PF Table, just in time, before the client connects to the domain.
 
------
### Compatibility;

PFUI Client - Supports any OS Unbound does, and requires Python 2 & 3.

PFUI Server - Supports OpenBSD and FreeBSD, and requires Python 3.

------
### Recommendations;

It is recommended to configure the PF firewall, to only allow connections to the pfui_server port
from the Unbound servers running pfui_client. PFUI does not implement authentication or encyption.

Don't allow all ports out by default.

