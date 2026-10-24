#!/bin/sh
# Offline tests for umdinate using a fake coordinate. Runs nothing on any host.
#   sh testing/test-umdinate.sh
# shellcheck disable=SC2181,SC2015  # "cmd; [ $? ... ] && pass || fail" is the test idiom here
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d 2>/dev/null)" || { T="/tmp/umdinate-test.$$"; mkdir "$T"; }
trap 'rm -rf "$T"' EXIT
FAILS=0
pass() { printf '  ok    %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*"; FAILS=$((FAILS + 1)); }

mkdir "$T/services" "$T/playbooks"
cp "$ROOT/testing/fake-coordinate.sh" "$T/coordinate"; chmod +x "$T/coordinate"
cat > "$T/hosts.yml" <<H
hosts:
  - name: a
    ip: 10.0.0.1
    user: u
    password: "p w#1"
  - name: b
    ip: 10.0.0.2
    user: u
    password: "p w#1"
  - name: c
    ip: 10.0.0.3
    user: root
    password: other
    port: 2222
H
# Steps name a script by its stem; the status suffix is found by umdinate
echo '#!/bin/sh' > "$T/services/one.tested.sh"; echo '#!/bin/sh' > "$T/services/two.draft.sh"
echo '#!/bin/sh' > "$T/services/raw.draft.sh"; echo '#!/bin/sh' > "$T/services/twin.draft.sh"; echo '#!/bin/sh' > "$T/services/twin.tested.sh"
printf 'service: basic\ndescription: the basic one\nsteps:\n  - run: services/one\n  - check: true\n    only: harden\n  - run: services/two\n    only: audit\n' > "$T/playbooks/basic.yml"
printf 'service: untested\nsteps:\n  - run: services/raw\n' > "$T/playbooks/untested.yml"
printf 'service: twins\nsteps:\n  - run: services/twin\n' > "$T/playbooks/twins.yml"
printf 'service: chain\nsteps:\n  - service: basic\n  - check: "false"\n    on_fail: "nope"\n' > "$T/playbooks/chain.yml"
printf 'service: loop\nsteps:\n  - service: loop\n' > "$T/playbooks/loop.yml"
printf 'service: gone\nsteps:\n  - run: services/missing\n' > "$T/playbooks/gone.yml"
printf 'service: bad\nsteps:\n  - run: services/one\n    only: sometimes\n' > "$T/playbooks/bad.yml"

# u [FAKE_FAIL=...] args...   -> output in $T/out, status in $?
u() {
  : >"$T/log"
  env UMDINATE_HOSTS="$T/hosts.yml" UMDINATE_ROOT="$T" UMDINATE_COORDINATE="$T/coordinate" \
    FAKE_LOG="$T/log" "$@" >"$T/out" 2>&1
}
has() { grep -F -- "$1" "$T/out" >/dev/null 2>&1; }
logged() { grep -c -- "$1" "$T/log"; }

echo "== umdinate =="
u sh "$ROOT/umdinate" -t a basic
[ $? = 0 ] && has "mode=audit" && [ "$(logged .)" = 2 ] && has "skipped, only runs in harden" && pass "single host, audit: 2 run calls, harden check skipped" || fail "single host audit"

u sh "$ROOT/umdinate" -t a basic -r
[ $? = 0 ] && grep -F -- '-S' "$T/log" >/dev/null && has "check passed" && has "skipped, only runs in audit" && pass "harden: -S passed, check ran, audit step skipped" || fail "harden mode"

u sh "$ROOT/umdinate" -t a,b basic
[ $? = 0 ] && [ "$(logged .)" = 4 ] && grep -F -- "-t 10.0.0.1" "$T/log" >/dev/null && grep -F -- "-t 10.0.0.2" "$T/log" >/dev/null && pass "comma list: each host runs its own chain, one call per step" || fail "comma list grouping"

u sh "$ROOT/umdinate" -t all basic
[ $? = 0 ] && has "parallel-groups=3" && grep -F -- "-P 2222" "$T/log" >/dev/null && pass "all: one group per host, port passed" || fail "all / groups"

u sh "$ROOT/umdinate" -t nope basic
[ $? != 0 ] && has "unknown target" && has "a (10.0.0.1)" && pass "unknown target lists known hosts" || fail "unknown target"

u sh "$ROOT/umdinate" -t a chain -r
[ $? != 0 ] && has "nope" && has "failed=1" && pass "failing check: on_fail printed, exit non-zero" || fail "failing check"

u env FAKE_FAIL=one.tested.sh sh "$ROOT/umdinate" -t a,c basic
[ $? != 0 ] && has "failed=2" && pass "failing run step fails its group" || fail "failing run step"

u env FAKE_LOGIN_FAIL=10.0.0.2 sh "$ROOT/umdinate" -t a,b basic
[ $? != 0 ] && has "b: step 1" && has "ok=1 failed=1" && pass "login failure (exit 0 + ERROR line) fails only that host" || fail "login failure detection"

u env FAKE_LOGIN_FAIL=10.0.0.1 sh "$ROOT/umdinate" -t a basic
[ $? != 0 ] && has "failed=1" && ! has "ok=1" && pass "login failure on the only host is not reported ok" || fail "login failure single"

u env FAKE_CRIT=10.0.0.2 sh "$ROOT/umdinate" -t a,b basic
[ $? != 0 ] && has "b: step 1" && has "ok=1 failed=1" && pass "timeout or failed sudo (exit 0 + CRIT line) fails only that host" || fail "CRIT detection"

u sh "$ROOT/umdinate" -t a basic
[ $? = 0 ] && grep -F -- 'one.tested.sh' "$T/log" >/dev/null && pass "run: services/one resolves to one.tested.sh" || fail "stem resolution"

u sh "$ROOT/umdinate" -t a twins
[ $? != 0 ] && has "exactly one" && [ "$(logged .)" = 0 ] && pass "stem matching two files rejected" || fail "ambiguous stem"

u sh "$ROOT/umdinate" -t a untested -r
[ $? != 0 ] && has "not tested or stable" && [ "$(logged .)" = 0 ] && pass "draft script refused as root" || fail "status gate"

u sh "$ROOT/umdinate" -t a untested
[ $? = 0 ] && [ "$(logged .)" = 1 ] && pass "draft script runs unprivileged (audit)" || fail "status gate, audit mode"

u env UMDINATE_UNTESTED=1 sh "$ROOT/umdinate" -t a untested -r
[ $? = 0 ] && has "although it is draft" && [ "$(logged .)" = 1 ] && pass "UMDINATE_UNTESTED=1 lets a draft run as root, loudly" || fail "status gate override"

printf 'hosts:\n  - name: a\n    ip: 1.1.1.1\n    user: u\n    password: "a,b"\n' > "$T/comma-hosts.yml"
u env UMDINATE_HOSTS="$T/comma-hosts.yml" sh "$ROOT/umdinate" -t a basic
[ $? != 0 ] && has "comma" && pass "password with a comma rejected (coordinate would split it)" || fail "comma password"

u sh "$ROOT/umdinate" -t a,c basic
[ $? = 0 ] && has "shown as it finishes" && has "group 1" && has "group 2" && pass "parallel groups: both outputs shown" || fail "parallel groups output"

u sh "$ROOT/umdinate" -t a loop
[ $? != 0 ] && has "includes itself" && pass "include cycle rejected" || fail "include cycle"

u sh "$ROOT/umdinate" -t a gone
[ $? != 0 ] && has "run: services/missing" && [ "$(logged .)" = 0 ] && pass "missing script caught before any call" || fail "missing script"

u sh "$ROOT/umdinate" -t a bad
[ $? != 0 ] && has "bad only" && pass "bad only: value rejected" || fail "bad only"

printf 'hosts:\n  - name: a\n    ip: 1.1.1.1\n    user: u\n    nested:\n      x: y\n' > "$T/bad-hosts.yml"
u env UMDINATE_HOSTS="$T/bad-hosts.yml" sh "$ROOT/umdinate" -t a basic
[ $? != 0 ] && has "unknown key" && pass "malformed hosts file rejected with line number" || fail "malformed hosts"

u sh "$ROOT/umdinate" -t a basic -n -r
[ $? = 0 ] && [ "$(logged .)" = 0 ] && has '****' && ! has 'p w#1' && pass "dry run: nothing executed, password masked" || fail "dry run"

u sh "$ROOT/umdinate" -l
[ $? = 0 ] && has "basic" && has "the basic one" && pass "-l lists playbooks with descriptions" || fail "list"

u sh "$ROOT/umdinate" -t a nosuch
[ $? != 0 ] && has "no playbook 'nosuch'" && has "basic" && pass "unknown playbook lists the available ones" || fail "unknown playbook"

u sh "$ROOT/umdinate"
[ $? = 2 ] && has usage && pass "no arguments prints usage" || fail "usage"

u env UMDINATE_HOSTS="$T/none.yml" sh "$ROOT/umdinate" -t a basic
[ $? != 0 ] && has "not found" && pass "missing hosts file" || fail "missing hosts file"

echo
[ "$FAILS" = 0 ] && echo "RESULT: all tests passed" || echo "RESULT: $FAILS test(s) failed"
exit "$FAILS"
