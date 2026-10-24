# Testing

Run all three from the `linux/` directory. CI runs the same three.

| Command | What it is | Executes scripts? |
|---------|------------|-------------------|
| `sh testing/check-syntax.sh` | Static checks: syntax under every shell, shellcheck, labels, services | No |
| `sh testing/test-scripts.sh` | Every active script, fed to a shell the way coordinate does it | Yes, in containers |
| `sh testing/test-ssh.sh` | The harden-ssh scripts against a real, running sshd | Yes, in a container |

Missing tools and images are printed as `skip`, never as a pass.

## check-syntax.sh

Uses every shell and linter it finds, so the more of them you install, the
more it checks. Beyond syntax it fails on:

- **A `.sh` file with no status suffix.** The exceptions are listed in `LEGACY`
  at the top of the script.
- **A label that is not true to itself.** The suffix must match the `status:`
  header, and a `tested` or `stable` script must name a dated run in `tested:`.
  `broken` and `deprecated` scripts get only this check.
- **`exit` outside a function**, or a function that exits in a file that does
  not end with `( main )`. This is a grep; `test-scripts.sh` is the real test.
- **Bashisms and GNU-only flags** from a short list (`sed -i`, `stat -c`, ...).
  The list cannot be complete; shellcheck and the old shells catch more.
- **coordinate directives** (`#DROP`, `#CALLBACK_IP`) in a script.
- **A helper block that differs from `utils.sh`.**
- **A service step that points at nothing**: every `run:` in `playbooks/*.yml`
  must match exactly one script, every `service:` an existing file.
- **Local tools** (`umdinate`, `testing/*.sh`) get shell syntax and shellcheck only.
- **`testing/test-umdinate.sh`** runs at the end against a fake coordinate.

## test-scripts.sh

coordinate does not execute a script file. It trims every line, drops the
empty ones and writes the rest to the stdin of the account's login shell, then
echoes a marker and waits for it. This test does the same inside throwaway
containers (no network), as root and as an unprivileged user, in bash 3.2, an
old busybox, and Debian with both `sh` and `bash`. Each run must:

- give the end marker back (no top-level `exit`, nothing ate stdin, no hang),
- print a `SUMMARY:` line,
- print the not-root warning when it is not root,
- leave `/tmp` empty.

`broken` and `deprecated` scripts are skipped. Name scripts on the command line
to run only those. `LIMIT=120 sh testing/test-scripts.sh` raises the per-run
time limit (default 60 seconds).

## test-ssh.sh

Starts a real sshd in the Debian container, sets up a drop-in, a `Match` block
and key files in two places, and logs in with a key over loopback before and
after. Three scenarios: the change is confirmed and kept, the change is not
confirmed and reverts by itself, and the backup cannot be written so nothing
may change. The 180 second revert timer is shortened to 5 for the test.

Write a file like this for every script that changes a service.

## check-exit.sh

The same end-marker test without Docker: it runs the scripts on **this
machine**, refuses to run as root, and by default only takes scripts with
`# risk: none`. Use it when Docker is not available.

## Full setup (Debian / Ubuntu / WSL)

```sh
sudo apt update
sudo apt install -y shellcheck dash bash ksh mksh posh busybox docker.io
docker pull bash:3.2
docker pull busybox:1.28
docker build -t ccdc-test:debian testing/
```

| Tool | What it adds |
|------|--------------|
| `shellcheck` | Quoting, unset variable and portability warnings. The biggest single gain. |
| `dash` | The `sh` on Debian/Ubuntu, the strictest common POSIX parser |
| `bash` | Also run as `bash --posix` |
| `ksh`, `mksh` | Commercial UNIX / BSD / Android style shells |
| `posh` | Debian's most pedantic POSIX shell, the best bashism detector |
| `busybox` | Alpine, routers, containers |
| `bash:3.2`, `busybox:1.28` | The old shells CCDC boxes can still have |
| `ccdc-test:debian` | Debian 12 with openssh-server, built from `testing/Dockerfile` |

Other distros: Fedora/RHEL `sudo dnf install ShellCheck dash ksh mksh busybox`
(`posh` is Debian-only), Alpine `apk add shellcheck dash ksh mksh busybox`,
macOS `brew install shellcheck dash ksh93 mksh`.

The tests never pull or build images themselves (slow, needs the network), so
do it once. On WSL the `docker` command can exist as a stub that fails until
WSL integration is enabled; the tests report that as unavailable. If a tag is
no longer published, change `DOCKER_IMAGES` in `check-syntax.sh` and `IMAGES`
in `test-scripts.sh`.

Check it worked. The only `skip` lines left should be for tools you chose not
to install:

```sh
sh testing/check-syntax.sh | grep -E 'skip|RESULT'
```

## What this still cannot test

- **A real host.** A container has no systemd, no SELinux, no socket
  activation and no scoring engine. A script stays `.draft` until it has run
  on a real VM (see the README status table).
- **RHEL-family and Alpine targets.** The only image with a real sshd is
  Debian 12. Add a `Dockerfile` per distro when a script needs it.
- **Real coordinate.** The tests imitate how it feeds a script; they do not
  run it. `fake-coordinate.sh` copies its `[ERROR` and `[CRIT` line formats
  from the source in `/coordinate` at the repo root.

## Before promoting a script

1. `sh testing/check-syntax.sh` has no `FAIL` lines and no `skip` for shells you
   installed.
2. `sh testing/test-scripts.sh` passes on every image, with none skipped.
3. A script that changes a service has its own scenario test, and it passes.
4. The script ran as root and as non-root on at least one real target
   (`UMDINATE_UNTESTED=1 ./umdinate -t <lab host> <service> -r`). Then write
   the OS and date into its `# tested:` header and rename it to `.tested.sh`.
