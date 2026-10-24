#!/bin/sh
# Behaviour test for audit-services, disable-services and restore-services in
# a throwaway Debian container (ccdc-test:debian, see testing/README.md). The
# container has no systemd, so this exercises the SysV path against a fake
# service (a perl listener behind /etc/init.d/fakesvc). Upstart, OpenRC and
# systemd are not covered here.
#
#   sh testing/test-services.sh
#
# Scenarios, each checked from the running system:
#   disable   port closes, boot link turns into a K link, restore brings it back
#   protect   the service owns a PROTECT_PORTS port, nothing changes
#   dryrun    not root: nothing changes

IMG="ccdc-test:debian"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "$IMG is not here, nothing was tested: docker build -t $IMG testing/" >&2
  exit 2
fi

T="$(mktemp 2>/dev/null)" || T="/tmp/ccdc-test-services.$$"
trap 'rm -f "$T"' EXIT
trap 'exit 1' HUP INT TERM

cat >"$T" <<'INNER'
yes() { d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ok    $d"; else echo "  FAIL  $d"; fi; }
no() { d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  FAIL  $d"; else echo "  ok    $d"; fi; }
# the way coordinate runs a script: trimmed lines on the stdin of a shell
paste() { sed 's/^[[:space:]]*//; s/[[:space:]]*$//' "$1" | grep -v '^$' | bash 2>&1; }
listening() { grep -i ":1F90 " /proc/net/tcp >/dev/null 2>&1; }   # 0x1F90 = 8080
mk() { # copy of disable-services with DENY and PROTECT_PORTS filled in
  sed "s/^DENY=\".*\"/DENY=\"fakesvc\"/; s/^PROTECT_PORTS=\".*\"/PROTECT_PORTS=\"$1\"/" /w/services/disable-services.tested.sh >/d.sh
}

cat >/etc/init.d/fakesvc <<'EOF2'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          fakesvc
# Required-Start:    $remote_fs
# Required-Stop:     $remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
### END INIT INFO
case "$1" in
  start) perl -MIO::Socket::INET -e '$0="fakesvc"; my $s = IO::Socket::INET->new(Listen=>5,LocalPort=>8080,ReuseAddr=>1) or die; sleep 100000' & echo $! >/var/run/fakesvc.pid ;;
  stop) [ -f /var/run/fakesvc.pid ] && kill "$(cat /var/run/fakesvc.pid)"; rm -f /var/run/fakesvc.pid ;;
esac
exit 0
EOF2
chmod +x /etc/init.d/fakesvc
update-rc.d fakesvc defaults >/dev/null 2>&1
/etc/init.d/fakesvc start; sleep 1
yes "setup: fakesvc listens on 8080" listening

case "$1" in
  disable)
    paste /w/services/audit-services.tested.sh | grep -F ':8080' >/dev/null
    yes "audit sees the listener on 8080" test $? = 0
    mk 22
    paste /d.sh | grep '^SUMMARY: changed=1 ' >/dev/null
    yes "disable reports one change" test $? = 0
    no "port 8080 is closed" listening
    yes "boot link became a K link" sh -c 'ls /etc/rc2.d/K*fakesvc >/dev/null && ! ls /etc/rc2.d/S*fakesvc >/dev/null 2>&1'
    yes "backup state file names the unit" sh -c 'grep " fakesvc " /root/ccdc-services-backup.*/state'
    paste /w/services/restore-services.tested.sh | grep '^SUMMARY: restored=1 ' >/dev/null
    yes "restore reports one entry" test $? = 0
    sleep 1
    yes "port 8080 listens again" listening
    yes "S link is back" sh -c 'ls /etc/rc2.d/S*fakesvc'
    ;;
  protect)
    mk "8080 22"
    paste /d.sh | grep '^SUMMARY: changed=0 skipped=1 ' >/dev/null
    yes "skipped: it owns a protected port" test $? = 0
    yes "still listening" listening
    ;;
  dryrun)
    mk 22
    useradd -m u
    cp /d.sh /home/u/d.sh; chmod 755 /home/u/d.sh
    su u -c 'sh /home/u/d.sh' 2>&1 | grep 'would stop and disable' >/dev/null
    yes "non-root prints what it would do" test $? = 0
    yes "still listening" listening
    yes "S link untouched" sh -c 'ls /etc/rc2.d/S*fakesvc'
    ;;
esac
INNER

for s in disable protect dryrun; do
  echo "== $s =="
  docker run --rm -v "$ROOT:/w:ro" -v "$T:/t.sh:ro" "$IMG" bash /t.sh "$s" 2>&1
done
