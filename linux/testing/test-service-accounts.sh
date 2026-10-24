#!/bin/sh
# Behaviour test for services/service-accounts in a throwaway Debian container
# (ccdc-test:debian, see testing/README.md). Containers have no systemd, so
# services are grouped by program and session, not by unit; unit files are not
# covered here.
#
#   sh testing/test-service-accounts.sh
#
# Scenarios, each in a fresh container:
#   clean      sshd running as root, stock accounts: no warning at all
#   rootnet    a listener that runs only as root is flagged with its port
#   person     a listener run by a person's account (uid 1000) is flagged
#   accounts   login shell + key, empty password, sudo group, NOPASSWD rule,
#              second uid 0: each is flagged
#   writable   a root service whose script www-data can change is flagged
#   own        a www-data service whose script only www-data owns: a note, no warning
#   notroot    not root: warns, still prints a SUMMARY
#   readonly   the audit changes nothing under /etc, /root, /var (its own log
#              aside) and leaves /tmp as it was

IMG="ccdc-test:debian"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="services/service-accounts.draft.sh"

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "$IMG is not here, nothing was tested: docker build -t $IMG testing/" >&2
  exit 2
fi

T="$(mktemp 2>/dev/null)" || T="/tmp/ccdc-test-service-accounts.$$"
trap 'rm -f "$T"' EXIT
trap 'exit 1' HUP INT TERM

cat >"$T" <<'INNER'
yes() { d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ok    $d"; else echo "  FAIL  $d"; sed 's/^/        /' /out; fi; }
no() { d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  FAIL  $d"; sed 's/^/        /' /out; else echo "  ok    $d"; fi; }
# the way coordinate runs a script: trimmed lines on the stdin of a shell
paste() { sed 's/^[[:space:]]*//; s/[[:space:]]*$//' "/w/$1" | grep -v '^$' | bash 2>&1; }
# PERL : a perl one-liner body that listens on PORT and holds it
listener() { echo 'use IO::Socket::INET; my $s = IO::Socket::INET->new(Listen=>5,LocalPort=>'"$1"',ReuseAddr=>1) or die; sleep 100000;'; }
has() { grep -F -e "$1" /out >/dev/null 2>&1; }
warned() { grep "^\[!\].*$1" /out >/dev/null 2>&1; }
SCRIPT="$2"

case "$1" in
  clean)
    mkdir -p /run/sshd && /usr/sbin/sshd
    sleep 1
    paste "$SCRIPT" >/out
    yes "prints a SUMMARY line" has "SUMMARY: "
    yes "sshd is reported with port 22" has ":22/tcp"
    no "no warning at all" warned ""
    ;;
  rootnet)
    perl -e "$(listener 9999)" >/dev/null 2>&1 &
    sleep 1
    paste "$SCRIPT" >/out
    yes "the port is reported" has ":9999/tcp"
    yes "root-only listener is a warning" warned "every process runs as root"
    ;;
  person)
    useradd -m -u 1000 alice
    su alice -s /bin/sh -c "perl -e '$(listener 7777)' >/dev/null 2>&1 &"
    sleep 1
    paste "$SCRIPT" >/out
    yes "the port is reported" has ":7777/tcp"
    yes "a person's account is flagged" warned "alice, a person's account"
    ;;
  accounts)
    usermod -s /bin/bash www-data
    mkdir -p /var/www/.ssh && echo "ssh-ed25519 AAAA x" >/var/www/.ssh/authorized_keys
    mkdir -p /etc/sudoers.d && echo "www-data ALL=(ALL) NOPASSWD: ALL" >/etc/sudoers.d/web
    usermod -p "" daemon
    usermod -a -G sudo backup
    echo "toor:x:0:0::/root:/bin/bash" >>/etc/passwd
    echo "toor:*:19000:0:99999:7:::" >>/etc/shadow
    paste "$SCRIPT" >/out
    yes "shell plus key can log in" warned "www-data can log in"
    yes "NOPASSWD rule is shown" warned "www-data has sudo: /etc/sudoers.d/web"
    yes "empty password" warned "daemon has an empty password"
    yes "sudo group" warned "backup is in group sudo"
    yes "second uid 0" warned "toor has uid 0"
    no "locked stock accounts are quiet" warned "nobody"
    ;;
  writable)
    mkdir /opt/app && listener 8080 >/opt/app/run.pl && chown -R www-data /opt/app
    perl /opt/app/run.pl >/dev/null 2>&1 &
    sleep 1
    paste "$SCRIPT" >/out
    yes "the script www-data can change is flagged" warned "/opt/app/run.pl can be changed by user:www-data"
    yes "so is its directory" warned "/opt/app can be changed by user:www-data"
    ;;
  own)
    mkdir /opt/own && listener 8081 >/opt/own/run.pl && chown -R www-data /opt/own
    su www-data -s /bin/sh -c "perl /opt/own/run.pl >/dev/null 2>&1 &"
    sleep 1
    paste "$SCRIPT" >/out
    yes "the port is reported" has ":8081/tcp"
    yes "its own script is a note" has "/opt/own/run.pl can be changed by its own account"
    no "and not a warning" warned "/opt/own"
    ;;
  notroot)
    useradd -m u
    cp "/w/$SCRIPT" /home/u/a.sh; chmod 755 /home/u/a.sh
    su u -c 'sed "s/^[[:space:]]*//; s/[[:space:]]*\$//" /home/u/a.sh | grep -v "^\$" | bash' >/out 2>&1
    yes "warns that results may be incomplete" has "Not running as root"
    yes "still prints a SUMMARY line" has "SUMMARY: "
    ;;
  readonly)
    perl -e "$(listener 9997)" >/dev/null 2>&1 &
    sleep 1
    snap() { find /etc /root /var -xdev 2>/dev/null | grep -v '^/var/log\(/ccdc\)\{0,1\}$' | grep -v '^/var/log/ccdc/' | sort | xargs ls -ld 2>/dev/null | cksum; }
    before="$(snap)"; tmp_before="$(ls -A /tmp | sort)"
    paste "$SCRIPT" >/out
    yes "nothing under /etc, /root, /var changed" test "$before" = "$(snap)"
    yes "/tmp is as it was" test "$tmp_before" = "$(ls -A /tmp | sort)"
    ;;
esac
INNER

for s in clean rootnet person accounts writable own notroot readonly; do
  echo "== $s =="
  # real root may read every process fd; docker drops that by default
  docker run --rm --cap-add SYS_PTRACE -v "$ROOT:/w:ro" -v "$T:/t.sh:ro" "$IMG" bash /t.sh "$s" "$SCRIPT" 2>&1
done
