#!/bin/sh
# Behaviour test for services/audit-services in a throwaway Debian container
# (ccdc-test:debian, see testing/README.md). Containers have no systemd, so PID 1
# is a plain shell and the script runs in its "none" init mode: this checks the
# part that matters most, finding listeners from /proc and flagging odd ones.
# systemd, Upstart and OpenRC are not covered here.
#
#   sh testing/test-audit-services.sh
#
# Scenarios, each in a fresh container:
#   clean     nothing odd is running, no warning about listeners
#   tmp       a listener whose program sits in /tmp is flagged with its port
#   deleted   a listener whose program file was deleted is flagged
#   inetd     an inetd.conf entry is flagged
#   notroot   not root: warns, still prints a SUMMARY
#   readonly  the audit changes nothing under /etc, /root, /var (its own /var/log/ccdc log aside) and leaves /tmp as it was

IMG="ccdc-test:debian"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="services/audit-services.tested.sh"

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "$IMG is not here, nothing was tested: docker build -t $IMG testing/" >&2
  exit 2
fi

T="$(mktemp 2>/dev/null)" || T="/tmp/ccdc-test-audit-services.$$"
trap 'rm -f "$T"' EXIT
trap 'exit 1' HUP INT TERM

cat >"$T" <<'INNER'
yes() { d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ok    $d"; else echo "  FAIL  $d"; fi; }
no() { d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  FAIL  $d"; else echo "  ok    $d"; fi; }
# the way coordinate runs a script: trimmed lines on the stdin of a shell
paste() { sed 's/^[[:space:]]*//; s/[[:space:]]*$//' "/w/$1" | grep -v '^$' | bash 2>&1; }
# listen PROGRAM PORT : a TCP listener, started from PROGRAM (a copy of perl)
listen() {
  "$1" -MIO::Socket::INET -e '$0="svc"; my $s = IO::Socket::INET->new(Listen=>5,LocalPort=>'"$2"',ReuseAddr=>1) or die; sleep 100000' >/dev/null 2>&1 &
  sleep 1
}
has() { grep -F -e "$1" /out >/dev/null 2>&1; }
SCRIPT="$2"

case "$1" in
  clean)
    paste "$SCRIPT" >/out
    yes "prints a SUMMARY line" has "SUMMARY: "
    no "no warning mentions /tmp" has "/tmp/"
    ;;
  tmp)
    cp /usr/bin/perl /tmp/.x
    listen /tmp/.x 9999
    paste "$SCRIPT" >/out
    yes "the port is reported" has ":9999"
    yes "the program in /tmp is named" has "/tmp/.x"
    yes "it is a warning" sh -c "grep '^\[!\].*9999' /out"
    ;;
  deleted)
    cp /usr/bin/perl /tmp/gone
    listen /tmp/gone 9998
    rm -f /tmp/gone
    paste "$SCRIPT" >/out
    yes "the port is reported" has ":9998"
    yes "the deleted program is noticed" has "(deleted)"
    ;;
  inetd)
    printf 'time stream tcp nowait root internal\n' >/etc/inetd.conf
    paste "$SCRIPT" >/out
    yes "inetd service is flagged" has "inetd serves time"
    ;;
  notroot)
    useradd -m u
    cp "/w/$SCRIPT" /home/u/a.sh; chmod 755 /home/u/a.sh
    su u -c 'sed "s/^[[:space:]]*//; s/[[:space:]]*\$//" /home/u/a.sh | grep -v "^\$" | bash' >/out 2>&1
    yes "warns that results may be incomplete" has "Not running as root"
    yes "still prints a SUMMARY line" has "SUMMARY: "
    ;;
  readonly)
    listen /usr/bin/perl 9997
    snap() { find /etc /root /var -xdev 2>/dev/null | grep -v '^/var/log\(/ccdc\)\{0,1\}$' | grep -v '^/var/log/ccdc/' | sort | xargs ls -ld 2>/dev/null | cksum; }
    before="$(snap)"; tmp_before="$(ls -A /tmp | sort)"
    paste "$SCRIPT" >/out
    yes "nothing under /etc, /root, /var changed" test "$before" = "$(snap)"
    yes "/tmp is as it was" test "$tmp_before" = "$(ls -A /tmp | sort)"
    ;;
esac
INNER

for s in clean tmp deleted inetd notroot readonly; do
  echo "== $s =="
  docker run --rm -v "$ROOT:/w:ro" -v "$T:/t.sh:ro" "$IMG" bash /t.sh "$s" "$SCRIPT" 2>&1
done
