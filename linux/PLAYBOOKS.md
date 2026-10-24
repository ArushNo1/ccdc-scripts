# Playbook (service) file format

A playbook is what `./umdinate` runs: `playbooks/<name>.yml`, a list of steps.
Run one with `./umdinate -t <hosts> <name> [-r] [-n]` (the bare file name,
without `.yml`). `./umdinate -l` lists every playbook with its description. The parser is a small awk subset of YAML, not
real YAML: anything it does not understand is rejected with the line number.

## Example

```yaml
service: harden-ssh
description: Audit sshd; with -r also rewrite its config and move the keys aside
steps:
  - service: audit-ssh
  - run: services/ssh-harden
    timeout: 60
  # comments and blank lines are fine
  - check: "sshd -T | grep '^pubkeyauthentication no'"
    only: harden
    on_fail: "new sshd config could not be confirmed"
  - run: services/ssh-keys
    timeout: 60
```

## Top level

| Key | Meaning |
|-----|---------|
| `service:` | The playbook's name. Documentation only, not checked against the filename: keep it equal. |
| `description:` | One line saying what it does and what `-r` changes. Shown by `./umdinate -l`, so write it for someone choosing a playbook. |
| `steps:` | The list of steps, run top to bottom. Must be present and non-empty. |

## Steps

Each step starts with `- ` and has exactly one of `run`, `check` or `service`,
plus optional modifiers on the following indented lines.

| Key | Value | Meaning |
|-----|-------|---------|
| `run:` | script path from `linux/`, no status suffix | Run that script on every host still in the chain. `services/ssh-harden` resolves to `ssh-harden.<status>.sh`; zero or several matches is an error. |
| `check:` | a shell command | Run on each host (one coordinate call per host). Exit 0 passes; anything else fails that host. Output is discarded. |
| `service:` | another playbook, by name | Insert that playbook's steps here. Includes nest; a cycle is rejected. `only`/`timeout` on an include line are ignored: set them on the included steps. |
| `only:` | `harden` or `audit` or `both` (default) | Run this step only with `-r` (harden) or only without it (audit). Skipped steps are printed as skipped. |
| `on_fail:` | text | Message printed (and put in the summary) when a `check:` fails. Used for `check:` only. |
| `timeout:` | seconds | Passed to coordinate as `-T`, per script. Default 30. Raise it for slow scripts. |

## Value syntax

- One `key: value` per line. No multi-line values, no lists inside a step.
- A value may be wrapped in `"double"` or `'single'` quotes. Quote anything with
  `#`, a leading quote, or shell punctuation you want kept. There are no escape
  sequences: the value ends at the last matching quote.
- Unquoted values lose a trailing ` # comment`.
- Only the first `:` splits key from value, so `check: a:b` is fine.
- Indent step modifiers with spaces or tabs; only the first line of a step
  carries the `- `.
- Unknown keys, an unknown `only:` value or an unparsable line stop umdinate
  before anything runs.

## How a playbook executes

1. The playbook is flattened (includes expanded) and every `run:` script is
   resolved before any host is touched, so a typo fails fast.
2. With `-r`, every `run:` script that will run as root must have status
   `tested` or `stable` (see README). `UMDINATE_UNTESTED=1` overrides this on a
   lab VM.
3. Each host runs the whole chain on its own, in parallel with the other hosts.
   Steps are sequential within a host.
4. A host that fails a step (login or sudo failure, script timeout, a failed
   `check:`) drops out of the chain; the other hosts continue. The summary
   lists each host as ok or failed with the step that stopped it.
5. In audit mode scripts run unprivileged; with `-r` they run through
   `coordinate -S` (sudo, or `su_password` from `hosts.yml`).
6. `-n` prints the coordinate commands (passwords masked) and runs nothing.

## Writing a new one

- Put audit steps first, then the change, then a `check:` that proves the
  service still works (`only: harden`), then any cleanup that must not happen
  if the check failed. See `playbooks/harden-ssh.yml`.
- Keep looking, changing and cleaning up as separate scripts (see CLAUDE.md).
- Mark change steps `only: harden` when the script has nothing useful to say
  without root.
- `sh testing/test-umdinate.sh` covers the parser; add a case there when you
  add a key.
