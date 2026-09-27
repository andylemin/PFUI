#!/bin/sh
#
# End-to-end on a real OpenBSD host: both installers unattended, then the
# installed resolver against the installed daemon over each transport and
# control path, under unveil and pledge. Run by .github/workflows/openbsd.yml;
# runnable by hand as root. Rewrites /etc/pf.conf and both PFUI configs.
#
#   PFUI_SRC_TREE    1 keep /usr/src, 2 signed release sources (default), 3 -current (unsigned)
#   UNBOUND_VERSION  latest (default), master, or a release-* tag

set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FW_YML=/etc/pfui_firewall.yml
RES_DIR=/var/unbound/etc
RES_YML=$RES_DIR/pfui_unbound.yml
RES_CONF=$RES_DIR/pfui_unbound.conf
SOCK=/var/run/pfui/pfui_firewall.sock
PERSIST4=/var/db/pfui/ipv4_domains
PERSIST6=/var/db/pfui/ipv6_domains
TABLE4=pfui_ipv4_domains
TABLE6=pfui_ipv6_domains
DAEMON_LOG=/var/log/daemon
BUILD_ROOT=/usr/local/pfui-build
NAME=one.one.one.one
# Globally routable, so validation accepts it; harmless on a pass-all test host
CRAFTED_IP=192.0.32.10

export PFUI_SRC_TREE="${PFUI_SRC_TREE:-2}"
export UNBOUND_VERSION="${UNBOUND_VERSION:-latest}"
export PFUI_UNBOUND_BUILD=2

MARK=""
PASSES=0

step() { printf '\n==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }

diagnostics() {
	printf '\n--- diagnostics ---\n'
	printf '\n# services\n'
	rcctl check pfui_firewall || true
	rcctl check pfui_unbound || true
	printf '\n# daemon log\n'
	grep pfui_firewall $DAEMON_LOG | tail -60 || true
	printf '\n# resolver log\n'
	grep unbound $DAEMON_LOG | tail -40 || true
	printf '\n# kernel log (a pledge kill names the syscall here)\n'
	dmesg | grep -iE 'pledge|unveil|pfui' | tail -10 || true
	grep -hE 'pledge|unveil|pfui_firewall' /var/log/messages 2>/dev/null | tail -10 || true
	printf '\n# the daemon in the foreground, as its own user, for five seconds\n'
	su -s /bin/sh _pfui_firewall -c 'exec timeout 5 /usr/local/sbin/pfui_firewall -d' \
		> /tmp/pfui-foreground.log 2>&1 || true
	tail -20 /tmp/pfui-foreground.log || true
	printf '\n# PF tables\n'
	pfctl -t $TABLE4 -T show 2>&1 || true
	pfctl -t $TABLE6 -T show 2>&1 || true
	printf '\n# Redis\n'
	rcctl check redis || true
	redis-cli ping || true
	redis-cli dbsize || true
	redis-cli keys '*' || true
	tail -5 /var/redis/log 2>/dev/null || tail -5 /var/log/redis/redis.log 2>/dev/null || true
	printf '\n# persist files\n'
	cat $PERSIST4 2>/dev/null || true
	printf '\n# configurations\n'
	cat $FW_YML 2>/dev/null || true
	cat $RES_YML 2>/dev/null || true
}

fail() {
	printf '\nFAIL: %s\n' "$*" >&2
	diagnostics
	exit 1
}

# retry <tries> <what> <command...>: a second apart, then fail with <what>
retry() {
	retry_n=$1
	retry_what=$2
	shift 2
	retry_i=0
	while [ "$retry_i" -lt "$retry_n" ]; do
		if "$@" >/dev/null 2>&1; then
			return 0
		fi
		retry_i=$((retry_i + 1))
		sleep 1
	done
	fail "$retry_what (after ${retry_n}s)"
}

# Log lines since the pass began; daemon, resolver and marker share /var/log/daemon
mark() {
	MARK="pfui-e2e $1 $(date +%s)"
	logger -p daemon.notice -t pfui-e2e "$MARK"
	sleep 1
}
since_mark() { sed -n "/$MARK/,\$p" $DAEMON_LOG; }
logged() { since_mark | grep -q "$1"; }

redis_up() { [ "$(redis-cli ping 2>/dev/null)" = PONG ]; }

in_table() { pfctl -t "$1" -T show 2>/dev/null | tr -d ' ' | grep -qx "$2"; }
not_in_table() { ! in_table "$@"; }
in_redis() { [ "$(redis-cli exists "$1^$2")" = "1" ]; }
not_in_redis() { ! in_redis "$@"; }
in_persist() { grep -qx "$2" "$1"; }
not_in_persist() { ! in_persist "$@"; }
redis_kind_is() { [ "$(redis-cli hget "$1^$2" kind)" = "$3" ]; }

resolve() {
	dig +short +time=5 +tries=2 @127.0.0.1 "$1" A \
		| grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -1
}

# ------------------------------------------------------------- configuration

# write_daemon_config <tcp|unix|both> <IOCTL|PFCTL> [ttl_multiplier] [af4_table]
write_daemon_config() {
	wd_transport=$1
	wd_ctl=$2
	wd_mult=${3:-4}
	wd_table4=${4:-$TABLE4}
	{
		echo "LOGGING: True"
		echo "LOG_LEVEL: DEBUG"
		if [ "$wd_transport" != unix ]; then
			echo "SOCKET_LISTEN: 127.0.0.1"
		fi
		if [ "$wd_transport" != tcp ]; then
			echo "SOCKET_UNIX: $SOCK"
		fi
		echo "SOCKET_UNIX_GROUP: _pfui"
		echo "SOCKET_PROTO: TCP"
		echo "SOCKET_PORT: 10001"
		echo "SOCKET_TIMEOUT: 3"
		echo "COMPRESS: False"
		echo "MAX_WORKERS: 8"
		echo "REDIS_HOST: 127.0.0.1"
		echo "REDIS_PORT: 6379"
		echo "REDIS_DB: 0"
		# Short: the sync loop must run several times a pass
		echo "SCAN_PERIOD: 5"
		echo "TTL_MULTIPLIER: $wd_mult"
		echo "CTL: $wd_ctl"
		echo "DEVPF: /dev/pf"
		echo "AF4_TABLE: $wd_table4"
		echo "AF4_FILE: $PERSIST4"
		echo "AF6_TABLE: $TABLE6"
		echo "AF6_FILE: $PERSIST6"
	} > $FW_YML
}

# write_resolver_config <tcp|unix|both>
write_resolver_config() {
	{
		echo "LOGGING: True"
		echo "LOG_LEVEL: DEBUG"
		echo "SOCKET_PROTO: TCP"
		echo "SOCKET_TIMEOUT: 3"
		echo "COMPRESS: False"
		echo "BLOCKING: True"
		echo "DEFAULT_PORT: 10001"
		echo "FIREWALLS:"
		if [ "$1" != unix ]; then
			echo "  - HOST: 127.0.0.1"
			echo "    PORT: 10001"
		fi
		if [ "$1" != tcp ]; then
			echo "  - SOCKET: $SOCK"
		fi
	} > $RES_YML
}

# Loopback only, forwarding, python module first. Written once.
write_resolver_conf() {
	cat > $RES_CONF <<EOC
server:
    chroot: ""
    directory: "$RES_DIR"
    username: "_unbound"
    pidfile: ""
    verbosity: 1
    use-syslog: yes
    interface: 127.0.0.1
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 127.0.0.0/8 allow
    do-not-query-localhost: no
    minimal-responses: yes
    module-config: "python iterator"
python:
    python-script: "$RES_DIR/pfui_unbound.py"
forward-zone:
    name: "."
    forward-addr: 1.1.1.1
    forward-addr: 9.9.9.9
EOC
}

# Tables only, pass everything: a default-deny ruleset would sever the runner's session
setup_pf() {
	step "pf.conf: the two tables, pass everything"
	[ -f /etc/pf.conf.pfui-e2e.orig ] || cp /etc/pf.conf /etc/pf.conf.pfui-e2e.orig
	cat > /etc/pf.conf <<EOC
# Written by tests/openbsd/run.sh; the original is /etc/pf.conf.pfui-e2e.orig
set skip on lo
table <$TABLE4> persist file "$PERSIST4"
table <$TABLE6> persist file "$PERSIST6"
pass
EOC
	pfctl -e >/dev/null 2>&1 || true
	pfctl -f /etc/pf.conf || fail "pf.conf did not load"
	pfctl -t $TABLE4 -T show >/dev/null || fail "$TABLE4 is not in the ruleset"
	pfctl -t $TABLE6 -T show >/dev/null || fail "$TABLE6 is not in the ruleset"
}

# --------------------------------------------------------------- lifecycle

stop_all() {
	rcctl stop pfui_unbound >/dev/null 2>&1 || true
	rcctl stop pfui_firewall >/dev/null 2>&1 || true
}

clear_state() {
	stop_all
	# A dead Redis otherwise reads as an empty database, failing every
	# store assertion without saying why
	rcctl check redis >/dev/null 2>&1 || rcctl start redis >/dev/null 2>&1 || true
	retry 15 "Redis is not answering" redis_up
	redis-cli flushdb >/dev/null
	pfctl -t $TABLE4 -T flush >/dev/null 2>&1 || true
	pfctl -t $TABLE6 -T flush >/dev/null 2>&1 || true
	: > $PERSIST4
	: > $PERSIST6
}

# start_daemon <tcp|unix|both>
start_daemon() {
	rcctl start pfui_firewall || fail "pfui_firewall did not start"
	retry 20 "pfui_firewall is not running" rcctl check pfui_firewall
	retry 20 "the daemon did not log that it started" logged "PFUI_Firewall service started"
	if [ "$1" != unix ]; then
		retry 20 "TCP 10001 is not listening" nc -z 127.0.0.1 10001
	fi
	if [ "$1" != tcp ]; then
		retry 20 "$SOCK was not created" test -S $SOCK
	fi
}

start_resolver() {
	rcctl start pfui_unbound || fail "pfui_unbound did not start"
	retry 20 "pfui_unbound is not running" rcctl check pfui_unbound
	# Non-recursive, so the listener is proven without a message to the firewall
	retry 20 "the resolver is not answering" \
		dig +norecurse +time=1 +tries=1 @127.0.0.1 . NS
}

# send_crafted <socket path | host:port> <qname> <ip> <ttl>: one rr message and its ACK
send_crafted() {
	python3 - "$@" <<'EOP'
import socket
import sys

sys.path.insert(0, "/var/unbound/etc")
from pfui_wire import encode  # noqa: E402

target, qname, ip, ttl = sys.argv[1:5]
msg = {"kind": "rr", "qname": qname, "AF4": [{"ip": ip, "ttl": int(ttl)}], "AF6": []}
if target.startswith("/"):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(target)
else:
    host, port = target.rsplit(":", 1)
    s = socket.create_connection((host, int(port)), timeout=5)
s.sendall(encode(msg, compress=False))
s.shutdown(socket.SHUT_WR)
reply = b""
while True:
    chunk = s.recv(64)
    if not chunk:
        break
    reply += chunk
if reply != b"ACKUPDATE":
    sys.exit("the firewall replied %r" % reply)
EOP
}

# ------------------------------------------------------------------ passes

# run_pass <name> <tcp|unix|both> <IOCTL|PFCTL>
run_pass() {
	pass_name=$1
	pass_transport=$2
	pass_ctl=$3
	step "pass $pass_name"
	clear_state
	write_daemon_config "$pass_transport" "$pass_ctl"
	write_resolver_config "$pass_transport"
	mark "$pass_name"
	start_daemon "$pass_transport"
	start_resolver

	ip=$(resolve $NAME)
	[ -n "$ip" ] || fail "no A answer for $NAME"
	note "$NAME -> $ip"

	# All three stores, labelled as a fresh answer
	retry 10 "$ip is not in PF table $TABLE4" in_table $TABLE4 "$ip"
	retry 10 "$ip is not in Redis" in_redis $TABLE4 "$ip"
	[ "$(redis-cli hget "$TABLE4^$ip" qname)" = "$NAME." ] \
		|| fail "Redis holds the wrong qname: $(redis-cli hgetall "$TABLE4^$ip")"
	redis_kind_is $TABLE4 "$ip" rr || fail "the first answer was not recorded as kind rr"
	retry 10 "$ip is not in $PERSIST4" in_persist $PERSIST4 "$ip"

	# The daemon names the peer it heard from
	case $pass_transport in
	tcp) logged "Received .* from 127.0.0.1:" || fail "nothing arrived over TCP" ;;
	unix) logged "Received .* from $SOCK" || fail "nothing arrived over the unix socket" ;;
	both)
		logged "Received .* from 127.0.0.1:" || fail "nothing arrived over TCP (both)"
		logged "Received .* from $SOCK" || fail "nothing arrived over the unix socket (both)"
		;;
	esac
	logged "PFUIDNS: Query Unblocked" || fail "the resolver did not log the unblock"
	logged "PF Table updated for $NAME" || fail "the daemon did not log the table update"

	# A cache hit only resets the TTL and relabels the record
	resolve $NAME >/dev/null
	retry 10 "the Redis record did not flip to kind cache" redis_kind_is $TABLE4 "$ip" cache

	# The sync loop must have read the table by now
	sleep 6
	logged "Scan for expiring $TABLE4" || fail "the sync loop did not run"
	! logged "Failed to read PF table" || fail "the sync loop could not read a table"
	! logged "Failed to install" || fail "a PF install failed"
	! logged "unreachable via CTL" || fail "the control path was reported unreachable"

	PASSES=$((PASSES + 1))
	note "ok"
}

expiry_pass() {
	step "pass expiry: a TTL 1 record leaves every store, and stop leaves no socket"
	clear_state
	write_daemon_config unix IOCTL 1
	mark expiry
	start_daemon unix
	send_crafted $SOCK expiry.pfui-e2e. $CRAFTED_IP 1 || fail "the crafted message was not acknowledged"
	retry 10 "$CRAFTED_IP was not installed" in_table $TABLE4 $CRAFTED_IP
	retry 10 "$CRAFTED_IP was not recorded" in_redis $TABLE4 $CRAFTED_IP
	retry 10 "$CRAFTED_IP was not persisted" in_persist $PERSIST4 $CRAFTED_IP
	# TTL 1 x multiplier 1, SCAN_PERIOD 5: gone within two scans
	retry 30 "$CRAFTED_IP is still in Redis" not_in_redis $TABLE4 $CRAFTED_IP
	retry 30 "$CRAFTED_IP is still in the PF table" not_in_table $TABLE4 $CRAFTED_IP
	retry 30 "$CRAFTED_IP is still in $PERSIST4" not_in_persist $PERSIST4 $CRAFTED_IP
	logged "TTL expired from $TABLE4: $CRAFTED_IP (expiry.pfui-e2e.)" \
		|| fail "the expiry was not logged with its domain"
	rcctl stop pfui_firewall >/dev/null 2>&1 || fail "pfui_firewall did not stop"
	[ ! -e $SOCK ] || fail "$SOCK was left behind after stop"
	note "ok"
}

reload_pass() {
	step "pass reload: pf.conf repopulates the table from the persist file"
	clear_state
	write_daemon_config tcp IOCTL
	mark reload
	start_daemon tcp
	send_crafted 127.0.0.1:10001 reload.pfui-e2e. $CRAFTED_IP 3600 \
		|| fail "the crafted message was not acknowledged"
	retry 10 "$CRAFTED_IP was not installed" in_table $TABLE4 $CRAFTED_IP
	retry 10 "$CRAFTED_IP was not persisted" in_persist $PERSIST4 $CRAFTED_IP
	# Stopped first, so only pf.conf can put the address back
	rcctl stop pfui_firewall >/dev/null 2>&1 || fail "pfui_firewall did not stop"
	pfctl -t $TABLE4 -T flush >/dev/null 2>&1
	not_in_table $TABLE4 $CRAFTED_IP || fail "flush left $CRAFTED_IP in the table"
	pfctl -f /etc/pf.conf || fail "pf.conf did not reload"
	in_table $TABLE4 $CRAFTED_IP || fail "the reload did not restore $CRAFTED_IP from $PERSIST4"
	note "ok"
}

fail_loud_pass() {
	step "pass fail-loud: a table missing from the ruleset refuses to start under IOCTL"
	clear_state
	write_daemon_config tcp IOCTL 4 pfui_not_in_ruleset
	mark fail-loud
	if rcctl start pfui_firewall >/dev/null 2>&1; then
		sleep 2
		! rcctl check pfui_firewall >/dev/null 2>&1 \
			|| fail "the daemon is serving with a table it cannot reach"
	fi
	retry 10 "no refusal in the log" logged "pfui_not_in_ruleset is unreachable via CTL: IOCTL"
	logged "not in the loaded ruleset" || fail "the ESRCH guidance is missing"
	logged "CTL: PFCTL" || fail "the remedy is missing"
	note "ok"
}

# The unix-socket suite as root, and the live ioctl suite against the real
# tables. The installer's build directory is reused.
rust_tests() {
	step "cargo test on the target"
	cd "$ROOT/server-rust"
	export CARGO_HOME=$BUILD_ROOT/cargo
	export CARGO_TARGET_DIR=$BUILD_ROOT/target
	# Streamed and bounded, so a hang is named rather than silent
	{ rc=0; timeout 900 cargo test --release --locked || rc=$?; echo "$rc" > /tmp/rc.cargo; } 2>&1 \
		| grep -vE '^\s+(Compiling|Downloaded|Downloading)' | tee /tmp/cargo-test.log
	[ "$(cat /tmp/rc.cargo)" = 0 ] || fail "cargo test failed (exit $(cat /tmp/rc.cargo); 124 is the timeout)"
	{ rc=0; PFUI_TEST_TABLE4=$TABLE4 PFUI_TEST_TABLE6=$TABLE6 \
		timeout 300 cargo test --release --locked --test pf_ioctl_live -- --ignored --test-threads=1 \
		|| rc=$?; echo "$rc" > /tmp/rc.live; } 2>&1 | tee /tmp/cargo-live.log
	[ "$(cat /tmp/rc.live)" = 0 ] || fail "the live ioctl suite failed (exit $(cat /tmp/rc.live))"
	pfctl -t $TABLE4 -T flush >/dev/null 2>&1 || true
	pfctl -t $TABLE6 -T flush >/dev/null 2>&1 || true
	cd "$ROOT"
}

# Informational: qemu on a shared runner. Only ack-before-total is asserted.
latency_summary() {
	step "latency (informational)"
	grep -h "latency microsecs" $DAEMON_LOG | tail -8 || true
	grep -h "Query Unblocked" $DAEMON_LOG | tail -4 || true
	grep -h "latency microsecs" $DAEMON_LOG | awk '
		/to ack=/ { sub(/.*to ack=/, ""); ack = $1 + 0; have = 1; next }
		/total=/  { if (have) { sub(/.*total=/, ""); if (ack > $1 + 0) bad++; n++; have = 0 } }
		END { printf "    pairs=%d out_of_order=%d\n", n, bad; exit (bad > 0) }' \
		|| fail "an acknowledgement was logged after its total"
}

# ---------------------------------------------------------------- the run

step "host"
uname -a
[ "$(uname)" = OpenBSD ] || { echo "OpenBSD only"; exit 2; }
[ "$(id -u)" -eq 0 ] || { echo "run as root"; exit 2; }
for cmd in bash cargo redis-cli swig git curl python3 dig; do
	command -v "$cmd" >/dev/null \
		|| { echo "missing: $cmd (pkg_add bash rust redis swig git curl py3-lz4 py3-yaml)"; exit 2; }
done
df -h / /usr /usr/local /var 2>/dev/null | sort -u
# The base resolver must not hold port 53
rcctl stop unbound >/dev/null 2>&1 || true
rcctl disable unbound >/dev/null 2>&1 || true

step "install-server-rust.sh (builds with the packaged rustc)"
{ rc=0; bash "$ROOT/install-server-rust.sh" || rc=$?; echo "$rc" > /tmp/rc.server; } 2>&1 | tee /tmp/install-server.log
[ "$(cat /tmp/rc.server)" = 0 ] || fail "install-server-rust.sh failed"
[ -x /usr/local/sbin/pfui_firewall ] || fail "the daemon was not installed"

setup_pf
rust_tests

step "install-client-unbound.sh (PFUI_SRC_TREE=$PFUI_SRC_TREE UNBOUND_VERSION=$UNBOUND_VERSION)"
{ rc=0; bash "$ROOT/install-client-unbound.sh" || rc=$?; echo "$rc" > /tmp/rc.client; } 2>&1 | tee /tmp/install-client.log
[ "$(cat /tmp/rc.client)" = 0 ] || fail "install-client-unbound.sh failed"
/usr/local/sbin/unbound -V | grep -q pythonmodule || fail "the installed Unbound has no Python module"
groupinfo _pfui | grep -qw _unbound || fail "_unbound is not in group _pfui"

write_resolver_conf
rcctl enable pfui_firewall pfui_unbound

for ctl in IOCTL PFCTL; do
	for transport in tcp unix both; do
		run_pass "$transport-$ctl" "$transport" "$ctl"
	done
done
expiry_pass
reload_pass
fail_loud_pass
latency_summary
stop_all

step "complete: $PASSES transport/control passes, expiry, reload and fail-loud all passed"
