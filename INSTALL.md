## Installing Unbound DNS (with Python Module support) and PFUI_Client

### OpenBSD

#### Install Packages
```
pkg_add -i python3
pkg_add -i python3-pip
pkg_add -i python
pkg_add -i python-pip

python3 -m pip install ./requirements.txt

git clone https://github.com/NLnetLabs/unbound.git /tmp/

cd  /tmp/unbound
./configure --enable-allsymbols \
            --with-ssl=/usr \
            --with-libevent=/usr \
            --with-libexpat=/usr \
            --with-pythonmodule \
            --with-chroot-dir=/var/unbound \
            --with-pidfile="" \
            --with-rootkey-file=/var/unbound/db/root.key \
            --with-conf-file=/var/unbound/etc/unbound.conf \
            --with-username=_unbound \
            --disable-shared

make && make install
```

#### TODO: Section for Unbound service

#### TODO: Section for Unbound config

### TODO: FreeBSD Section
.

### TODO: Linux Section
.

---

## Installing PFUI_Server on PF Firewalls

### OpenBSD

#### Install Packages
```
pkg_add -i python3
pkg_add -i python3-pip
pkg_add -i python
pkg_add -i python-pip
pkg_add -i redis
rcctl enable redis
rcctl restart redis
```

#### Copy Files

#### PFUI_Server service
```
rcctl enable pfui_server
rcctl start pfui_server
```

### TODO: FreeBSD Section

### TODO: PFSense Section

