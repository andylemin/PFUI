#   PFUI_Unbound build-and-run test container.
#
#   Builds Unbound from source with --with-pythonmodule, the same release and the
#   same flags install-client-unbound.sh uses, then runs PFUI_Unbound inside that
#   resolver against a local authoritative server and a stub PFUI_Firewall.
#
#   This is Debian, not OpenBSD, so it does not prove the OpenBSD build. What it
#   does prove is the part a version bump risks and that nothing else covers:
#   that the Unbound release the installer resolves still configures and builds
#   with the Python module, that its pythonmod interface still calls PFUI's entry
#   points, and that a real resolved answer still reaches the wire as the message
#   PFUI_Firewall expects. Before this existed, "does Unbound still build" was
#   only ever answered on an operator's machine, by the install failing.
#
#   Build context is the repository root; see run.sh.

FROM debian:bookworm-slim

# Which Unbound to build: "latest", "master", or a tag such as release-1.25.2.
# Resolved by the same helper the installer calls, so the two cannot disagree.
ARG UNBOUND_VERSION=latest

ENV DEBIAN_FRONTEND=noninteractive

# python3-yaml and python3-lz4 come from apt rather than pip because the resolver
# imports them through its embedded interpreter, which is the system one - the
# same reason the installer does not use a virtualenv
#
# flex and bison are needed because this builds from the git repository, where
# util/configlexer.c is generated rather than committed. OpenBSD has lex and yacc
# in base, which is why install-client-unbound.sh does not name them.
RUN apt-get update && apt-get install -y --no-install-recommends \
      bison \
      build-essential \
      ca-certificates \
      flex \
      git \
      libevent-dev \
      libexpat1-dev \
      libssl-dev \
      python3 \
      python3-dev \
      python3-lz4 \
      python3-yaml \
      swig \
      nsd \
      dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Mirrors the OpenBSD account Unbound drops to after binding, and the shared group
# install-server-python.sh creates for the local PFUI socket. Unbound really does
# run as _unbound here, so the resolver only reaches the socket if that membership
# and the socket's mode are right - the same thing an operator depends on
RUN id _unbound >/dev/null 2>&1 || useradd -r -s /usr/sbin/nologin _unbound \
 && groupadd -f _pfui \
 && usermod -aG _pfui _unbound

# configure --with-pythonmodule looks for 'python', not 'python3', and fails
# outright without it. install-client-unbound.sh makes the same symlink, so this
# also keeps that step honest
RUN ln -sf "$(command -v python3)" /usr/local/bin/python

COPY client-unbound/tools/unbound_release.sh /src/tools/unbound_release.sh
RUN UNBOUND_REF="$(/src/tools/unbound_release.sh "${UNBOUND_VERSION}")" \
 && echo "${UNBOUND_REF}" > /src/unbound-ref \
 && echo "Building Unbound ${UNBOUND_REF}" \
 && git clone --depth 1 --branch "${UNBOUND_REF}" \
      https://github.com/NLnetLabs/unbound.git /src/unbound

# The installer's flag set, less the flags that name OpenBSD-only paths.
# --with-pythonmodule is the one that matters: it is not enabled in any distro
# package, so a pythonmod build break is invisible until someone installs PFUI.
RUN cd /src/unbound \
 && ./configure --enable-allsymbols \
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
                --without-pthreads \
 && make -j"$(nproc)" \
 && make install

# PFUI_Unbound, laid out as install-client-unbound.sh lays it out: the module and
# the shared protocol module beside the config, which is what pfui_unbound.py's
# sys.path insertion depends on
RUN install -d -m 755 /var/unbound/etc /var/unbound/db
COPY protocol/python/pfui_wire.py /var/unbound/etc/pfui_wire.py
COPY client-unbound/pfui_unbound.py /var/unbound/etc/pfui_unbound.py
COPY client-unbound/tests/container/pfui_unbound.yml /var/unbound/etc/pfui_unbound.yml
COPY client-unbound/tests/container/unbound.conf /var/unbound/etc/pfui_unbound.conf
RUN chmod 644 /var/unbound/etc/*

# Authoritative source for the test zone, so a query really resolves
COPY client-unbound/tests/container/nsd.conf /etc/nsd/nsd.conf
COPY client-unbound/tests/container/pfui-test.zone /etc/nsd/pfui-test.zone

COPY client-unbound/tests/container/verify.py /src/verify.py

CMD ["python3", "/src/verify.py"]
