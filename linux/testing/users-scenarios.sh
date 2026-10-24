#!/bin/sh
# Container-only test driver. Invoked by test-users.sh.
set -eu
# shellcheck disable=SC2016 # generated code runs in the SSH shell
[ -f /.dockerenv ] || exit 2
rc=0
trap 'rc=$?; if [ "$rc" != 0 ] && [ -f /test/err ]; then cat /test/err >&2; fi' EXIT
mkdir -p /run/sshd /test
printf '127.0.0.1 %s\n' "$(hostname)" >>/etc/hosts
printf '%s\n' 'root:rootpw' | chpasswd
for name in alice bob evil scorer; do
useradd -m -s /bin/sh "$name"
printf '%s:%s\n' "$name" initialpw | chpasswd
done
printf '%s\n' 'PermitRootLogin yes' 'PasswordAuthentication no' 'UsePAM yes' 'PidFile /run/sshd.pid' 'AllowUsers root alice bob evil scorer' 'Match User bob' '    X11Forwarding no' >/etc/ssh/sshd_config
/usr/sbin/sshd
# Feed exactly as coordinate does, and verify it can still print its marker.
feed() {
file=$1
prefix=$2
{
printf '%s\n' "$prefix"
sed 's/^[[:space:]]*//; s/[[:space:]]*$//' "$file" | sed '/^$/d'
printf '%s\n' 'echo __USERFLOW_END__'
} | sh >/test/out 2>/test/err
grep '^__USERFLOW_END__$' /test/out >/dev/null || { cat /test/err; return 1; }
}
snapshot() {
for f in passwd shadow group gshadow sudoers; do cp -p "/etc/$f" "/test/before.$f"; done
}
unchanged() {
for f in passwd shadow group gshadow sudoers; do cmp "/etc/$f" "/test/before.$f"; done
}
case "$1" in
controller)
sed 's/PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config >/test/sshd_config
cat /test/sshd_config >/etc/ssh/sshd_config
kill -HUP "$(cat /run/sshd.pid)"
sleep 1
printf 'lab\t127.0.0.1\troot\trootpw\t22\n' >/test/hosts.tsv
printf 'lab\talice\tadmin\nlab\tbob\tuser\nlab\tscorer\tpreserve\n' >/test/authorized.tsv
printf '\n' | script -q -e -c 'env UMDINATE_UNTESTED=1 USERFLOW_HOSTS=/test/hosts.tsv USERFLOW_AUTH=/test/authorized.tsv USERFLOW_RESULTS=/test/results sh /w/users/manage-users.draft.sh >/test/final.tsv 2>/test/controller.err' /dev/null >/test/tty.log 2>&1 || { cat /test/controller.err; cat /test/tty.log; if [ -f /test/results/lab.failure.log ]; then grep -v "$(printf '\t')" /test/results/lab.failure.log; awk -F '\t' 'NF>1 {print "ROW fields=" NF, "host=" $1, "user=" $2, "role=" $3, "enabled=" $4, "flag=" $6}' /test/results/lab.failure.log; fi; exit 1; }
awk -F '\t' 'NF!=8 {bad=1} END {exit bad || NR!=3}' /test/final.tsv
getent passwd "$(hostname)-admin" >/dev/null
[ "$(getent passwd root | cut -d: -f7)" = /usr/sbin/nologin ]
[ "$(stat -c %a /test/results/credentials.tsv)" = 600 ]
;;
backup-failure)
snapshot
mv /var/backups /var/backups.original
: >/var/backups
feed /w/users/ensure-access.draft.sh "USERFLOW_ADMIN='testbox-admin'"
unchanged
if getent passwd testbox-admin >/dev/null; then exit 1; fi
if grep 'success=TRUE' /test/err; then exit 1; fi
;;
existing-admin)
useradd testbox-admin
snapshot
feed /w/users/ensure-access.draft.sh "USERFLOW_ADMIN='testbox-admin'"
unchanged
if grep 'success=TRUE' /test/err; then exit 1; fi
;;
normal|custom-grant)
feed /w/users/ensure-access.draft.sh "USERFLOW_ADMIN='testbox-admin'"
grep 'success=TRUE' /test/err >/dev/null || { cat /test/err; exit 1; }
awk -F '\t' '$2=="testbox-admin" && NF==8 && length($5)>=32 {ok=1} END {exit !ok}' /test/out
pw=$(awk -F '\t' '$2=="testbox-admin" {print $5}' /test/out)
sleep 1
printf "printf '%%s\\n' '%s' | sudo -S -p '' /bin/sh -c 'test \"\$(id -u)\" = 0 && echo SSH_SUDO_OK'\n" "$pw" >/test/proof.sh
/w/coordinate -t 127.0.0.1 -u testbox-admin -p "$pw" -q -y -T 10 /test/proof.sh </dev/null >/test/proof.out 2>&1
grep '^SSH_SUDO_OK' /test/proof.out >/dev/null || { cat /test/proof.out; exit 1; }
scorer=$(getent shadow scorer)
if [ "$1" = custom-grant ]; then
printf '%s\n' 'bob ALL = (ALL) ALL' >/etc/sudoers.d/bob
chmod 440 /etc/sudoers.d/bob
fi
snapshot
feed /w/users/change-credentials.draft.sh "USERFLOW_ADMIN='testbox-admin'; USERFLOW_CONFIRMED=YES; USERFLOW_PLAN='alice:admin:TRUE bob:user:TRUE scorer:preserve:TRUE testbox-admin:admin:TRUE'"
if [ "$1" = custom-grant ]; then
unchanged
if grep 'success=TRUE' /test/err; then exit 1; fi
grep 'custom sudo grant' /test/err >/dev/null
else
grep 'success=TRUE' /test/err >/dev/null || { cat /test/err; exit 1; }
[ "$(getent shadow scorer)" = "$scorer" ]
[ "$(getent passwd root | cut -d: -f7)" = /usr/sbin/nologin ]
[ "$(getent passwd evil | cut -d: -f7)" = /usr/sbin/nologin ]
getent shadow root | grep '^root:!' >/dev/null
getent shadow evil | grep '^evil:!' >/dev/null
id -Gn alice | tr ' ' '\n' | grep '^ccdc_admin$' >/dev/null
if sudo -n -l -U bob 2>/dev/null | grep '^[[:space:]]*(' >/dev/null; then exit 1; fi
awk -F '\t' '$2=="alice" || $2=="bob" {if(NF!=8 || $6!="FALSE" || length($5)<32) exit 1; n++} END {if(n!=2) exit 1}' /test/out
[ "$(awk -F '\t' '$2=="alice" {print $5}' /test/out)" != "$(awk -F '\t' '$2=="bob" {print $5}' /test/out)" ]
# Real reconnect after root's shell and password have been disabled.
/w/coordinate -t 127.0.0.1 -u testbox-admin -p "$pw" -q -y -T 10 /test/proof.sh </dev/null >/test/proof.out 2>&1
grep '^SSH_SUDO_OK' /test/proof.out >/dev/null || { cat /test/proof.out; exit 1; }
feed /w/users/delete-users.draft.sh "USERFLOW_DELETE='evil'"
grep 'success=TRUE' /test/err >/dev/null || { cat /test/err; exit 1; }
if getent passwd evil >/dev/null; then exit 1; fi
[ -d /home/evil ]
fi
;;
*) exit 2 ;;
esac
