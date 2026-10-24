#!/bin/sh
# Stand-in for ./coordinate in tests. Logs its arguments to $FAKE_LOG, "runs"
# check scripts locally, and fails a run script when its name is in $FAKE_FAIL.
echo "$*" >>"$FAKE_LOG"
for last; do :; done
# Like the real one: a failed login is an [ERROR] line with the ip, exit status 0
targets=""
prev=""
for a in "$@"; do
  [ "$prev" = -t ] && targets="$a"
  prev="$a"
done
case ",$targets," in *",$FAKE_LOGIN_FAIL,"*) hit=1 ;; *) hit=0 ;; esac
if [ -n "$FAKE_LOGIN_FAIL" ] && [ "$hit" = 1 ]; then
  printf '\033[91m[ERROR\033[0m:0:u:\033[92m%s\033[0m] Login failed!\n' "$FAKE_LOGIN_FAIL"
fi
# Like the real one: a failed escalation or a script timeout is a [CRIT line, exit status 0
case ",$targets," in
  *",${FAKE_CRIT:-none},"*) printf '\033[31m[CRIT\033[0m:0@01:02:03PM:u:%s/x.sh\033[31m]\033[0m Script did not finish before timeout!\n' "$FAKE_CRIT" ;;
esac
case "$last" in
  */check.*.sh) sh "$last" ;;
  *)
    case " $FAKE_FAIL " in
      *" ${last##*/} "*) echo "fake: $last failed" >&2; exit 3 ;;
    esac
    echo "fake: ran ${last##*/}"
    ;;
esac
exit 0
