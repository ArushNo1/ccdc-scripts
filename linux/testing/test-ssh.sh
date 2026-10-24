#!/bin/sh
# Behaviour test for the harden-ssh scripts against a real, running sshd in a
# throwaway container (ccdc-test:debian, see testing/README.md). It logs in
# with a key over loopback before and after, so it proves what the running
# daemon does, not what the file says.
#
#   sh testing/test-ssh.sh
#
# Scenarios, each in a fresh container:
#   keep      harden, confirm with the marker, then move the keys
#   revert    harden, do not confirm, the old configuration must come back
#   nobackup  the backup cannot be written, nothing may change
# The 180 second revert timer is shortened to 5 for the test.

IMG="ccdc-test:debian"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if ! docker image inspect "$IMG" >/dev/null 2>&1; then
  echo "$IMG is not here, nothing was tested: docker build -t $IMG testing/" >&2
  exit 2
fi

T="$(mktemp 2>/dev/null)" || T="/tmp/ccdc-test-ssh.$$"
trap 'rm -f "$T"' EXIT
trap 'exit 1' HUP INT TERM

# ---- the part that runs inside the container -------------------------------
cat >"$T" <<'EOF'
yes() { d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  ok    $d"; else echo "  FAIL  $d"; fi; }
no() { d="$1"; shift; if "$@" >/dev/null 2>&1; then echo "  FAIL  $d"; else echo "  ok    $d"; fi; }
# Run a script the way coordinate does: trimmed lines on the stdin of the login shell
paste() {
  { sed 's/^REVERT_SECS=180/REVERT_SECS=5/' "/w/$1" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//' | grep -v '^$'; } | bash 2>&1
}
login() {
  ssh -i /k -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o ConnectTimeout=5 bob@127.0.0.1 true </dev/null
}
eff() { sshd -T 2>/dev/null | sed 's/ *$//' | grep -x "$1"; }
same_pid() { [ "$(cat /run/sshd.pid)" = "$PID" ] && kill -0 "$PID"; }

# A box somebody has been in: a drop-in, a Match block, keys in two places
mkdir -p /run/sshd /etc/ssh/keys
useradd -m -s /bin/bash bob && echo 'bob:pw' | chpasswd
ssh-keygen -q -t ed25519 -N '' -f /k
mkdir -p /home/bob/.ssh && cp /k.pub /home/bob/.ssh/authorized_keys && chown -R bob /home/bob/.ssh
cp /k.pub /etc/ssh/keys/bob
printf 'PermitRootLogin yes\nAuthorizedKeysFile .ssh/authorized_keys /etc/ssh/keys/%%u\n' >/etc/ssh/sshd_config.d/evil.conf
printf 'Match User bob\n  PermitEmptyPasswords yes\n' >>/etc/ssh/sshd_config
cp /etc/ssh/sshd_config /orig
/usr/sbin/sshd && sleep 1
PID="$(cat /run/sshd.pid)"
yes "setup: bob can log in with a key" login

case "$1" in
  keep)
    paste services/ssh-keys.draft.sh >/dev/null
    yes "ssh-keys moves nothing while key logins are on" test -f /home/bob/.ssh/authorized_keys
    paste services/ssh-audit.draft.sh | grep '^SUMMARY: ports=22 sshd_listening=1 key_files=2 ' >/dev/null
    yes "ssh-audit sees the port, the listener and both key files" test $? = 0
    out="$(paste services/ssh-harden.draft.sh)"
    yes "ssh-harden reports installed and reloaded" sh -c 'echo "$1" | grep "^SUMMARY: installed=1 reloaded=1 auto_revert=5s warnings=0"' x "$out"
    no "key login is refused by the running sshd" login
    yes "effective: passwordauthentication yes" eff "passwordauthentication yes"
    yes "effective: permitrootlogin no" eff "permitrootlogin no"
    yes "sshd was reloaded, not restarted" same_pid
    yes "drop-in is in the backup and gone from the config dir" sh -c '[ ! -e /etc/ssh/sshd_config.d/evil.conf ] && [ -f /root/ccdc-ssh-backup.*/sshd_config.d/evil.conf ]'
    no "Match block is gone" grep -i '^Match' /etc/ssh/sshd_config
    yes "ssh-harden leaves the key files alone" test -f /home/bob/.ssh/authorized_keys
    # The confirmation is the check step of the service itself
    check="$(sed -n 's/^[[:space:]]*-[[:space:]]*check:[[:space:]]*"\(.*\)"$/\1/p' /w/playbooks/harden-ssh.yml)"
    yes "the check step of harden-ssh.yml passes and leaves the marker" sh -c "( $check ) && test -e /var/run/ccdc-ssh-ok"
    sleep 8
    no "confirmed: still hardened after the revert window" login
    out="$(paste services/ssh-keys.draft.sh)"
    yes "ssh-keys reports two files moved" sh -c 'echo "$1" | grep "^SUMMARY: key_files=2 moved=2 "' x "$out"
    no "default key file is gone" test -e /home/bob/.ssh/authorized_keys
    no "custom-path key file is gone (path read from the backup)" test -e /etc/ssh/keys/bob
    yes "both key files are in the key backup" sh -c '[ "$(ls /root/ccdc-ssh-keys.*/ | wc -l)" = 2 ]'
    paste persistence/ssh-backdoors.draft.sh | grep '^SUMMARY: pam_lines=[1-9]' >/dev/null
    yes "ssh-backdoors reads the PAM stack" test $? = 0
    ;;
  revert)
    paste services/ssh-harden.draft.sh >/dev/null
    no "key login is refused after hardening" login
    sleep 9
    yes "not confirmed: sshd_config is back, byte for byte" cmp -s /etc/ssh/sshd_config /orig
    yes "not confirmed: the drop-in is back" test -f /etc/ssh/sshd_config.d/evil.conf
    yes "not confirmed: key login works again" login
    yes "sshd was never restarted" same_pid
    ;;
  nobackup)
    rm -rf /root && : >/root
    out="$(paste services/ssh-harden.draft.sh)"
    yes "refuses to change anything" sh -c 'echo "$1" | grep "refusing to change anything"' x "$out"
    yes "sshd_config is untouched" cmp -s /etc/ssh/sshd_config /orig
    yes "the drop-in is untouched" test -f /etc/ssh/sshd_config.d/evil.conf
    yes "key login still works" login
    ;;
esac
EOF

# ---- run each scenario ------------------------------------------------------
FAILS=0
for sc in keep revert nobackup; do
  echo "== $sc =="
  out="$(timeout -s KILL 120 docker run --rm -i --network none -v "$ROOT":/w:ro "$IMG" bash -s "$sc" <"$T" 2>&1)"
  printf '%s\n' "$out" | grep -E '^  (ok|FAIL)  '
  n="$(printf '%s\n' "$out" | grep -c '^  FAIL  ')"
  FAILS=$((FAILS + n))
  # A scenario that printed nothing died on the way: show why
  if ! printf '%s\n' "$out" | grep '^  ok    setup:' >/dev/null; then
    FAILS=$((FAILS + 1))
    printf '%s\n' "$out" | tail -n 15 | sed 's/^/        /'
  fi
done

echo
if [ "$FAILS" -eq 0 ]; then echo "RESULT: all ssh scenarios passed"; else echo "RESULT: $FAILS check(s) failed"; fi
[ "$FAILS" -eq 0 ]
