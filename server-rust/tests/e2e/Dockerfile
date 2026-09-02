# End-to-end variant of the client build-and-run container: the same image
# that builds Unbound with the Python module (see
# ../../../client-unbound/tests/container/Dockerfile), plus Redis and a
# stateful pfctl stub, so the REAL PFUI_Unbound talks to the REAL Rust
# PFUI_Firewall over both transports. The daemon binary is bind-mounted at
# run time by run.sh; build context is this directory.

ARG BASE=pfui-unbound-test:latest
FROM ${BASE}

RUN apt-get update && apt-get install -y --no-install-recommends \
      redis-server \
      redis-tools \
    && rm -rf /var/lib/apt/lists/*

# pfctl at its real absolute path: the daemon execs /sbin/pfctl, and the stub
# keeps per-table state files so the sync loop's reads see its own writes
COPY pfctl-stub.sh /sbin/pfctl
RUN chmod 755 /sbin/pfctl

COPY pfui_firewall.yml /etc/pfui_firewall.yml
COPY verify_daemon.py /src/verify_daemon.py

CMD ["python3", "/src/verify_daemon.py"]
