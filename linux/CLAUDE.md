# Writing scripts in this directory

These rules apply to every script you write or change here. Each script does
one core job. The task description comes from the person asking.

Looking, changing and cleaning up are three jobs. Write three scripts and
chain them as steps in `playbooks/<name>.yml` (see `playbooks/harden-ssh.yml`)
instead of one script that does all of it.

The script will be run over SSH on whatever Linux box the user is logged into,
so the distro and age are unknown in advance.

## Requirements

- A single .sh file in strictly POSIX sh (#!/bin/sh). No bashisms: no arrays, [[ ]], mapfile, associative arrays or process substitution. It must work on bash 3, dash, busybox and very old distros.
- Use only old, common tools and flags. Avoid GNU-only options such as stat -c, grep --exclude-dir, sed \r, date %F, and curl --noproxy. If a tool is missing, fall back to another (for example curl, then wget, then nc, then /dev/tcp) and print one warning that says what to install. Don't fail.
- No options or flags. The script does the one core job.
- If it isn't root, print a warning that results may be incomplete and continue. Don't require sudo.
- Cover every case. Don't rely on known program names, because the thing being looked for may be hidden or disguised. Discover it from the system itself (/proc, sockets, processes), then add detail for known cases as a bonus.
- Be fast. Run slow checks (network probes, timeouts) in parallel and skip clearly dead targets quickly. Use short timeouts. Handle legacy TLS by retrying with older settings only when the failure suggests it.
- Be robust to odd cases (empty files, missing tools, processes that vanish mid-scan), but not over-engineered. It should read like a person wrote it: simple, linear, lightly commented, easy to debug. No clever one-liners.
- Never `exit` outside a function. `coordinate` does not execute the file: it trims every line, drops the empty ones, writes the rest to the stdin of the account's login shell, then echoes a marker and waits for it. So an `exit` kills that shell and it waits out its whole timeout (measured: 2s became the full `-T`). If you need early exits, put the body in `main() { ... }` and end the file with `( main )` so `exit` only ends a subshell. `trap ... EXIT` is fine.
- For the same reason: no command may read stdin (it would eat the rest of the script; add `</dev/null` when unsure), nothing may depend on leading whitespace (here-documents, multi-line strings), the shebang does not pick the shell, and no line may start with `#DROP` or contain `#CALLBACK_IP`.
- Clean up temp files with a trap. Don't leave processes running: no background loops, watchers or daemons. The one exception is a revert timer in a `risk: lockout` script: a single `sleep`, then it restores the backup unless a marker file says a new login was confirmed.
- Print a readable report grouped per item, with warnings for suspicious things, and a one-line summary at the end.

## Scripts that change the system

The rules above fit read-and-report scripts. A script that edits configuration,
removes files or reloads services must also:

- Back up everything it will change to a root-only directory first, and refuse to change anything if the backup fails. Move files aside; never delete them.
- Validate a candidate before installing it (for example `sshd -t -f`), and restore the backup automatically if the installed result fails validation.
- Reload instead of restart, and never disconnect other users' sessions.
- When not root, change nothing and report what would change. That is a dry run, not an audit: the audit is its own `risk: none` script, which is safe to run as root and sees more there.
- Check the result from the system afterwards (the effective value, not the line it wrote) and warn on any mismatch.
- Set `risk: lockout` or `risk: service-impact` in the header, and say in the header comment exactly what stops working.
- Keep the scoring service working: do not change ports, host keys, or the login method the scoring engine uses unless the task says so.

## Conventions

- The header comment (`status`, `risk`, `os`, `tested`) and the `name.<status>.sh` file naming are defined in README.md. Start new scripts from `template.wip.sh`.
- The helper block at the top of each script is copied from `utils.sh`; change it there and in the scripts together.
- Run `sh testing/check-syntax.sh` before finishing.
- Playbooks (what `./umdinate` runs) are defined in `playbooks/<name>.yml`; a script never needs to know about modes beyond its own root check. A step names a script as a path from `linux/` without its status suffix (`run: services/ssh-harden`).
- `umdinate -r` only runs scripts whose status is `tested` or `stable`. Do not label a script `tested` yourself: that needs a run on a real host and its date in `# tested:`.

## Before giving the script back

Test it before handing it over. `sh testing/test-scripts.sh` feeds every script to a shell the way coordinate does, in throwaway containers, as root and not root, under bash 3.2, an old busybox and Debian. A script that changes the system also needs scenarios against the real service, like `testing/test-ssh.sh`: the normal case, the weird cases, and the failure that must leave everything untouched. Say honestly what you could not test.
