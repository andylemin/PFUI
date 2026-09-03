#!/bin/sh
# Stateful pfctl stand-in for the end-to-end container: `-t T -T add|delete`
# maintain /tmp/tbl.T, `show` prints it, so the daemon's sync loop reads back
# exactly what its own pushes wrote. Linux has no PF; this is the CTL: PFCTL
# path with the kernel replaced by a file.
table=$2
verb=$4
shift 4 2>/dev/null || true
state="/tmp/tbl.${table}"
case "$verb" in
  add)
    for ip; do echo "$ip" >> "$state"; done
    ;;
  delete)
    for ip; do
      grep -v "^${ip}\$" "$state" > "${state}.n" 2>/dev/null || true
      mv "${state}.n" "$state"
    done
    ;;
  show)
    cat "$state" 2>/dev/null || true
    ;;
esac
exit 0
