# Linux

Linux subteam scripts and automation for the UMD-CCDC competition.

## Structure

```text
.
├── CLAUDE.md            # Script specification (strict POSIX sh, single file)
├── utils.sh             # Reference copy of the helper block pasted into scripts
├── umdinate             # Runs a service on hosts via coordinate (see below)
├── coordinate           # Binary built from /coordinate at the repo root
├── hosts.example.yml    # Copy to hosts.yml (gitignored) per competition
├── first15/             # Actions for the first 15 minutes of the competition
│   └── default-creds.draft.sh
├── playbooks/           # What umdinate runs: <name>.yml, one per playbook (./umdinate -l lists them)
├── template.wip.sh      # Start new scripts from this
├── services/            # Service hardening scripts for after the first 15 minutes
│   ├── ssh-audit.draft.sh       # Listeners, effective config, key files (reads only)
│   ├── ssh-harden.draft.sh      # Rewrites sshd_config, reloads, auto-reverts (lockout risk)
│   ├── ssh-keys.draft.sh        # Moves authorized_keys aside once keys are off
│   ├── service-accounts.draft.sh # Who each service runs as, what that account can do (reads only)
│   └── ssh-setup.deprecated.sh  # Older, patch-in-place version
├── persistence/         # Persistence/malware hunting
│   └── ssh-backdoors.draft.sh   # PAM, binaries, rc files, sshd unit (reads only)
├── testing/             # Checks and tests, see testing/README.md
└── CCDC.sh              # Legacy bash menu from before this framework (unchecked)
```

Scripts follow [CLAUDE.md](CLAUDE.md): one self-contained `#!/bin/sh` file,
strict POSIX, no options, warn instead of requiring root.

## Running services on hosts: `umdinate`

```sh
./umdinate -l                                    # list playbooks and what they do
./umdinate -t web01 harden-ssh                   # not root: scripts report, change nothing
./umdinate -t web01,db01 harden-ssh -r  # root (coordinate -S: sudo), scripts apply
./umdinate -t all audit-ssh -r          # root, but only read-only scripts: the full audit
./umdinate -t all harden-ssh -r -n      # -n = dry run, prints coordinate commands
```

- `-t` takes a name or ip from `hosts.yml`, a comma list, or `all`.
- `-r` means "as root". What happens as root depends on the scripts in the
  service: `audit-ssh` holds only `risk: none` scripts, so with `-r` it is a
  complete audit that changes nothing.
- With `-r`, only scripts whose status is `tested` or `stable` run. To run a
  draft on a lab VM, set `UMDINATE_UNTESTED=1`.
- Every host runs its own chain, in parallel with the others (one coordinate call per host per step).
- A playbook is `playbooks/<name>.yml` (format: PLAYBOOKS.md), run by its bare name (`harden-ssh`): a list of steps. `./umdinate -l` prints each name with its `description:` line, so that line is the playbook's documentation. `run: <script>` names a
  script, as a path from `linux/`, without its status suffix (`run: services/ssh-harden` finds
  `ssh-harden.<status>.sh`), so promoting a script does not break the service.
  So `run: first15/default-creds` reaches
  another lane. `check: <command run on the target>` (with `on_fail:` text),
  `service: <other>` to chain. `only: harden|audit` limits a step to one mode;
  scripts choose their own mode from the root check, so umdinate passes no mode
  flag to them.
- A host fails a step when coordinate prints an `[ERROR` or `[CRIT` line for it
  (failed login, failed sudo, script timeout). The rest of the chain is skipped
  for that host.
- Only a small YAML subset is read (list of flat maps, `#` comments); anything else
  is rejected with a line number. Passwords are on coordinate's argv, so they are
  visible in `ps` on your machine. A password with a comma is rejected:
  coordinate would split it.
- Tests: `sh testing/test-umdinate.sh` (uses a fake coordinate, touches no host).

## Script naming and status

Every script is named `name.<status>.sh`. The suffix is the script's maturity
and is the only thing encoded in the filename.

| Suffix | Meaning | Use in competition? |
|--------|---------|---------------------|
| `.wip.sh` | Being written, incomplete | No |
| `.draft.sh` | Feature-complete, passes `dash -n`, never run on a real host | No |
| `.tested.sh` | Ran successfully in a lab VM on at least one target OS | With supervision |
| `.stable.sh` | Tested on all target OSes and re-run since the last edit | Yes |
| `.broken.sh` | Used to work, regressed | No |
| `.deprecated.sh` | Superseded; kept for reference | No |

Promote a script by renaming it with `git mv` when its status changes.

The label is enforced in two places. `umdinate -r` refuses anything that is not
`tested` or `stable`. `check-syntax.sh` fails a `.sh` file with no suffix, a
suffix that disagrees with the `status:` header, and a `tested` or `stable`
script whose `tested:` header names no dated run. `broken` and `deprecated`
scripts are kept for reference: only their label is checked.

Everything else lives in a header comment right under the shebang:

```sh
#!/bin/sh
# status:  draft
# risk:    lockout        # none | lockout | service-impact
# os:      deb rhel
# tested:  ubuntu-24.04 2026-10-12
```

Keep `status:` in sync with the suffix. Anything with `risk:` other than `none`
should be reviewed before it is run during the competition.

## Team and duties

The work is split into three lanes that follow the attack chain:
initial access, then privilege escalation, then persistence.

| Lane | Owner | Focus |
|------|-------|-------|
| A | Praful | Default credentials and identity |
| B | Arush | Services and privilege escalation |
| C | Vishal | Persistence and malware |

### Person A: Praful (default credentials and identity)

Scripts live in `first15/`.

- Research, then write a script that finds and changes default credentials.
- Cover every account scenario: local users, domain-joined users (the box is on
  an Active Directory domain, so SSSD/Kerberos is in play), and others.
- Research and write a script or checklist for malware and vulnerabilities
  related to SSSD, Kerberos, and similar identity services.

### Person B: Arush (services and privilege escalation)

Scripts live in `services/`.

- Research, then harden common services: sshd and equivalents, FTP, cron,
  systemd, SMTP, and similar.
- For each service, understand how it works, its common vulnerabilities, how
  malware would abuse it, and how to spot that.
- Own the privilege escalation category:
  - Kernel vulnerabilities (e.g. DirtyCow, DirtyPipe, PwnKit)
  - sudo/sudoers misconfigurations
  - Vulnerabilities in services, especially ones running with high privileges
  - Open ports
  - Users in privileged groups they shouldn't be in

### Person C: Vishal (persistence and malware)

Scripts live in `persistence/`.

- Research, then write detection and removal tooling for anything that can
  (re)enable initial access or privilege escalation:
  - Cronjobs (e.g. creating a high-privilege user with known creds)
  - System jobs
  - systemd services
  - Web shells
  - Rootkits
  - Other malware
- Some malware is just annoying (random typing, screen animations), but treat
  anything that could restore access as a priority.

## Shared helpers

Scripts are single files and do not source anything. The small helper block
(`header`, `info`, `ok`, `warn`, `check_root`, logging to `/var/log/ccdc/`) is
pasted at the top of each script and the canonical copy is the root
`utils.sh`. If you change a helper there, update the scripts too.

## Testing

Three commands, all described in [testing/README.md](testing/README.md):

```sh
sh testing/check-syntax.sh   # static: shells, shellcheck, labels, services. Seconds.
sh testing/test-scripts.sh   # runs every script in containers the way coordinate does
sh testing/test-ssh.sh       # harden-ssh against a real sshd in a container
```

CI runs all three on every push that touches this directory
(`.github/workflows/linux-scripts.yml` at the repo root). A script should not
be promoted past `.draft` until they pass and it has been run on a real host.

## Competition timeline

1. **First 15 minutes** (`first15/`): change default credentials and get a
   picture of each machine (OS, running services).
2. **After the first 15 minutes** (`services/`): service hardening and
   privilege escalation fixes.
3. **Ongoing** (`persistence/`): hunt for persistence and malware, since it can
   undo the work above.