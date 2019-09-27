
## Installing PFUI Client and Unbound DNS (with Python Module support)

### OpenBSD


export PKG_PATH=http://ftp.openbsd.org/pub/OpenBSD/%v/packages/%a/
pkg_add -i bash
install_pfui_firewall.sh
install_pfui_unbound.sh




#### Install Packages
```
export PKG_PATH=http://ftp.openbsd.org/pub/OpenBSD/%v/packages/%a/

pkg_add -i python%2
pkg_add -i py-setuptools
pkg_add -i py-pip
ln -s /usr/local/bin/python2 /usr/local/bin/python 

pkg_add -i python%3
pkg_add -i py3-setuptools
pkg_add -i py3-pip

pkg_add -i swig
pkg_add -i git
```

#### Build Unbound with Python Module Support
```
git clone https://github.com/NLnetLabs/unbound.git /tmp/unbound

cd /tmp/unbound
./configure --enable-allsymbols \
            --with-ssl=/usr \
            --with-libevent=/usr \
            --with-libexpat=/usr \
            --with-pythonmodule \
            --with-chroot-dir=/var/unbound \
            --with-pidfile="" \
            --with-rootkey-file=/var/unbound/db/root.key \
            --with-conf-file=/var/unbound/etc/unbound.pfui.conf \
            --with-username=_unbound \
            --disable-shared

make && make install


```

#### TODO: Copy in all PFUI Client files (/var/unbound/etc/)
chmod 755 ./pfui_server.py
chmod 755 ./update_root_servers.sh
chmod 755 ./update_filtered_domains.sh

chmod 555 /etc/rc.d/unbound_pfui

chmod 755 ./update_root_servers.sh
chmod 755 ./update_filtered_domains.sh 

#### TODO: PFUI Client Dependencies
python3 -m pip install -r ./requirements.txt

#### TODO: Section for Unbound service

#### TODO: Section for Unbound config

#### TODO: Section for Unbound data sources
./update_root_servers.sh  
./update_filtered_domains.sh  

```
rcctl enable unbound_pfui
rcctl start unbound_pfui
```

### TODO: FreeBSD Section
.

### TODO: Linux Section
.



---

## Installing "PFUI_Server" on PF Firewalls

### OpenBSD

#### Install Packages
```
pkg_add -i python%2
pkg_add -i py-setuptools
pkg_add -i py-pip

ln -s /usr/local/bin/python2 /usr/local/bin/python 

pkg_add -i python%3
pkg_add -i py3-setuptools
pkg_add -i py3-pip

pkg_add -i redis
rcctl enable redis
rcctl restart redis
```

#### Copy Files (/etc/ & /usr/local/sbin/)
```
cp ./pfui_server.py /usr/local/sbin/pfui_server.py
chmod 755 /usr/local/sbin/pfui_server.py
cp ./pfui_server.yml /etc/pfui_server.yml
chmod 644 /etc/pfui_server.yml 
```

#### Enable PFUI_Server service
```
rcctl enable pfui_server
rcctl start pfui_server
```


### TODO: FreeBSD Section

### TODO: PFSense Section

