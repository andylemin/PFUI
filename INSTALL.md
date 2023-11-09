
## Installing PFUI_Firewall and PFUI_Unbound (Unbound with Python Module support)

PFUI_Firewall runs as a daemon instance on OpenBSD firewall(s) running PF.
PFUI_Firewall listens on the configured network port for messages from PFUI_Unbound (DNS).
Received messages are written directly into the configured PF temporary tables via IOCTL calls.
Messages are also saved into redis for state and expiry tracking, and into a files to be 
read by PF at startup, making it reload safe.

/etc/pf.conf must also be configured with appropriate packet filtering rules. 
PFUI_Firewall simply installs the IP addresses sent to it by PFUI_Unbound (DNS servers) into 
the configured PF tables. PF must then filter against those tables as desired.

#### NOTE: For both the auto and manual methods;
If you want pfui_firewall to start at boot, disable unbound with `rcctl restart pfui_firewall` 
and edit `/etc/rc.conf.local` ensuring the following three lines exist.

```
pfui_firewall=""
pfui_firewall_user="root"
pkg_scripts=redis pfui_firewall pfui_unbound
```

NB; If you want a normal Unbound (for localhost) and a PFUI Unbound (for clients) on the same firewall, 
either configure the default Unbound to only listen on lookback, or use different rdomain per lookup domain/daemon.

If your pkg_scripts already has other options, just add these three to your existing line
TODO: The root user is required only to talk to the /dev/pf IOCTL and to open the configured network listening port 
for receiving messages from all instances of PFUI_Unbound. Set group permissions for _pfui_firewall user, and run pfui_firewall as _pfui_firewall user

## Install
```
export PKG_PATH=http://ftp.openbsd.org/pub/OpenBSD/%v/packages/%a/
pkg_add -i bash

# All edge OpenBSD Firewalls
install_pfui_firewall.sh

# All internal DNS Servers
install_pfui_unbound.sh
```

## Configure
```
OpenBSD PF Firewall(s); Configure PFUI_Firewall `/etc/pfui_firewall.yml`
Unbound DNS Resolver(s); Configure PFUI_Unbound `/var/unbound/etc/pfui_unbound.yml`
```

Warning; UDP mode (`SOCKET_PROTO: UDP`) is _not_ recommended (experimental) as Unbound's Python Module executes every DNS lookup, 
using a unique network socket to PFUI_Firewall for each lookup. With UDP's default timers, the socket 
remains (5mins) after the connection/PFUI_Firewall is updated, thus blocking subsequent connections until timeout.
UDP therefore only supports ~213Qps (~64000ports / 5m / 60s).

Default TCP TIME_WAIT = 60; **~1,066Qps** (~64000 / 60) - per PFUI_Firewall\
TCP TW=10 (`sysctl net.inet.tcp.keepidle=10`); **~6,400qps** (64000 / 10) - per PFUI_Firewall

Even if your use case is <200Qps, UDP is still not recommended as logic to handle high load has not been developed due to the socket
limitation above. One way to solve this could be a UDP proxy, to provide persistent sockets to PFUI_Firewall, however such userland UDP proxy which would negate
any speed advantages of UDP.

Instead, TCP has been optimised to perform within 20% of the theoretical minimum latency of UDP.
Eg, UDP messaging can unblock PFUI_Firewall in ~1000uS (1ms), and TCP can unblock PFUI_Firewall in ~1,200us (1.2ms).
Because PFUI leverages TCP signalling in the kernel network stack, at high load latency does not increase much.\
UDP latency increases more rapidly due to userland CPU contention as load increases.

# Manual Install
The above installation scripts are better maintained than this process below.
It is recommended to review the above install scripts as well.

------------------------------

### PFUI_Unbound - Dependencies
```
export PKG_PATH=http://ftp.openbsd.org/pub/OpenBSD/%v/packages/%a/
pkg_add -i python%3.8
pkg_add -i py3-setuptools
pkg_add -i py3-pip
ln -s `which python3` /usr/local/bin/python
pkg_add -i swig git bash cmake libconfig libiconv bison gawk mawk
```

#### TODO: PFUI_Unbound Dependencies
python3 -m pip install -r ./requirements_unbound.txt

### PFUI_Unbound - Download Unbound source
```
git clone --depth 20 https://github.com/NLnetLabs/unbound.git /tmp/unbound
# --depth 20 helps with shallow clone errors
```

#### Default Unbound build options in OpenBSD port, `unbound -V` (ref only);
```
--enable-allsymbols 
--with-ssl=/usr 
--with-libevent=/usr 
--with-libexpat=/usr 
--without-pythonmodule 
--with-chroot-dir=/var/unbound 
--with-pidfile= 
--with-rootkey-file=/var/unbound/db/root.key 
--with-conf-file=/var/unbound/etc/unbound.conf 
--with-username=_unbound 
--disable-shared 
--disable-explicit-port-randomisation 
--without-pthreads
```

### PFUI_Unbound - Build Unbound with Python Module Support enabled
```
cd /tmp/unbound
./configure --enable-allsymbols \
          --with-ssl=/usr \
          --with-libevent=/usr \
          --with-libexpat=/usr \
          --with-pythonmodule \
          --with-chroot-dir=/var/unbound \
          --with-pidfile="" \
          --with-rootkey-file=/var/unbound/db/root.key \
          --with-conf-file=/var/unbound/etc/pfui_unbound.conf \
          --with-username=_unbound \
          --disable-shared \
          --disable-explicit-port-randomisation \
          --without-pthreads

make && make install
```

#### Copy PFUI_Firewall files
```
cp -f "${DIR}/pfui_firewall.py" /usr/local/sbin/pfui_firewall.py
chmod 755 /usr/local/sbin/pfui_firewall.py

cp -f "${DIR}/pfui_firewall.yml" /etc/pfui_firewall.yml
chmod 644 /etc/pfui_firewall.yml

cp -f "${DIR}/rc.d/pfui_firewall" /etc/rc.d/pfui_firewall
chmod 555 /etc/rc.d/pfui_firewall

cp -f "${DIR}/examples/pf.conf" /etc/pf-pfui-example.conf
```

### Install Python Libraries and Redis
```
python3 -m pip install redis pyyaml service
pkg_add -i redis
rcctl enable redis
rcctl start redis
```
```
chmod 755 ./update_root_servers.sh
chmod 755 ./update_filtered_domains.sh

chmod 555 /etc/rc.d/pfui_unbound

chmod 755 ./update_root_servers.sh
chmod 755 ./update_filtered_domains.sh 
```

#### TODO: Section for Unbound service

#### TODO: Unbound config
A good tool for automatically downloading the latest bad-reputation domains into DNS Blocklists can be found here;
https://www.geoghegan.ca/unbound-adblock.html

#### TODO: Section for Unbound data sources
./update_root_hints.sh  

```
rcctl enable pfui_unbound
rcctl start pfui_unbound
```

### TODO: FreeBSD Section
.

### TODO: Linux Section
.



---

## Installing "PFUI_Firewall" on PF Firewalls

### OpenBSD

#### PFUI_Firewall - Dependencies
```
pkg_add -i python%3
pkg_add -i py3-setuptools
pkg_add -i py3-pip
ln -s `which python3` /usr/local/bin/python
pkg_add -i redis
rcctl enable redis
rcctl restart redis
```

#### PFUI_Firewall - Copy Files (/etc/ & /usr/local/sbin/)
```
cp ./pfui_firewall.py /usr/local/sbin/pfui_firewall.py
chmod 755 /usr/local/sbin/pfui_firewall.py
cp ./pfui_firewall.yml /etc/pfui_firewall.yml
chmod 644 /etc/pfui_firewall.yml 
```

#### PFUI_Firewall - Enable Service
```
rcctl enable pfui_firewall
rcctl start pfui_firewall
```


### TODO: FreeBSD Section

### TODO: PFSense Section

