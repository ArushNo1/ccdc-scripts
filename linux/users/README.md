# User access workflow

Run `sh users/manage-users.draft.sh` on the controller. It reads the phase
scripts from `services/manage-users.yml` and calls `coordinate` per host and
phase. The controller handles the fresh-login checks, per-host input and
interactive deletion review that a plain umdinate chain cannot supply.

These scripts are **draft**, tested in containers, not competition hosts.
For a lab run set `UMDINATE_UNTESTED=1`. The workflow changes real credentials
on every listed target; run it from an interactive terminal.

## Input

Two UTF-8/ASCII TSV files, with **literal tabs**, no header or blank lines:

`users/hosts.tsv` (one row per box):

```text
label<TAB>address<TAB>ssh_login<TAB>ssh_password<TAB>port
```

`users/authorized.tsv` (one row per authorized or protected local account):

```text
label<TAB>username<TAB>admin
label<TAB>username<TAB>user
label<TAB>scoring_identity<TAB>preserve
```

Labels match the hosts file, rather than the remote hostname. `admin` gets a
personal primary group and the `ccdc_admin` supplementary group, which has
password-authenticated unrestricted sudo. `user` gets a personal primary
group and **no supplementary groups**. Both get `/bin/sh`, a fresh 36-character
random password, and cleared account expiration/inactivity. Existing custom
sudo grants cause rollback when demoting to `user`; review that policy first.
`preserve` leaves that account's shell, password and groups unchanged. Use it
for competition scoring identities and service identities whose credentials
or memberships must remain intact. Root/other UID-0 identities cannot be
allowlisted: disabling root login is an explicit part of this workflow.

The authorized accounts must already exist locally. Directory users appear
in inventory when NSS enumerates them, but password/group changes are local
only. Missing local accounts cause rotation to stop, rather than creating
unexpected identities. Passwords cannot contain commas because coordinate
splits its password argument on commas. Hosts input currently uses password
login, not key-only or separate su credentials. Protect input files with mode
600. Default input/output paths are gitignored.

For example, create lab inputs using actual tabs:

```sh
umask 077
printf 'web\t192.0.2.10\toperator\tinitial-password\t22\n' > users/hosts.tsv
printf 'web\talice\tadmin\nweb\tbob\tuser\nweb\tscorer\tpreserve\n' > users/authorized.tsv
UMDINATE_UNTESTED=1 sh users/manage-users.draft.sh > credentials.tsv
```

Override locations with `USERFLOW_HOSTS`, `USERFLOW_AUTH`, `USERFLOW_RESULTS`,
and optionally `USERFLOW_COORDINATE`. The results directory must not already
exist; use a new directory for each run. Do not rerun the bootstrap against a
host that already has `<hostname>-admin` or `ccdc_admin`: it refuses collisions.

## Sequence and output

1. Inventory enumerates all NSS accounts, including disabled identities, and
   writes eight-column TSV to stdout. Inventory `login enabled` means an
   executable login shell, not a guarantee that PAM, account expiry, SSH
   policy or keys permit a connection. A password lock alone does not block
   SSH keys. Privilege reporting identifies UID 0 and sudo grants; other
   privilege mechanisms, including doas and filesystem grants, need review.
2. The controller saves inventory and prints accounts outside the allowlist.
   Bootstrap creates `<remote-hostname>-admin`, a new sudo group and a scoped
   SSH password rule. It extends global AllowUsers/AllowGroups for that
   identity. Existing deny rules and included/earlier matching policy remain
   authoritative. A fresh SSH login and explicit `sudo /bin/sh` must succeed.
   Unsupported policy stops the chain while the original root access remains.
3. The operator enters any unauthorized usernames safe to delete. Empty input
   keeps all account entries. No terminal stops the chain before rotation.
4. Rotation backs up account databases and locks root and **every** unlisted
   local account, including service identities, setting their shell to nologin
   (or false). It rotates authorized passwords and resets groups as above.
   Root is disabled here, after the new admin login is proven, rather than
   during bootstrap. The rescue admin credential remains unchanged.
5. A fresh admin SSH/sudo check follows. Optional cleanup removes explicitly
   selected, disabled non-system account entries with no running processes.
   It retains home directories and other user-owned files, and backs up the
   account databases first. It does not kill sessions or delete home files.

Final stdout and `results/credentials.tsv` contain only newly issued
credentials, one record per user, in this exact order, with eight columns:

```text
hostname<TAB>username<TAB>privilege<TAB>TRUE<TAB>password<TAB>FALSE<TAB><TAB>
```

Inventory uses an empty password and `TRUE` in column six instead. Protected
identities and disabled accounts have no newly issued credentials and are
not included in the final credential output. Per-host inventory, unauthorized
accounts and issued credentials remain in the protected results directory.
Progress and summaries go to stderr. On partial failure, already issued
credentials are retained and printed, and the controller returns failure.
Treat redirected stdout as sensitive; use `umask 077` before redirecting it.
Coordinate exposes its password argument in the controller's process list,
as it does elsewhere in this repository.

## Supported targets and recovery

Mutation requires root, shadow-utils, OpenSSH and sudo/visudo. Missing tools,
doas-only hosts, invalid existing policy, unsafe names and ambiguous SSH
masters cause a warning and no account changes. Non-root mutation phases
report a dry run. Inventory remains usable without mutation dependencies.
The hostname must form a lowercase username (dots, hyphens and underscores allowed) of at most 32 characters
when suffixed with `-admin`; unsupported hostnames are reported without change.

Changes are backed up under root-only `/var/backups/ccdc-users.*`; the path is
reported in phase diagnostics. Config candidates are validated before install
and again after install. A failed mutation restores its account/policy backup.
SSH is reloaded with HUP; host keys and ports are preserved. Only the default
sshd instance identified through its pidfile and `/proc` is supported. PAM,
LDAP/SSSD policy, custom sudo plugins, arbitrary privileged filesystem access,
and non-OpenSSH servers cannot be repaired automatically by this workflow.
Bootstrap refuses an existing rescue account/group. Successful phases persist
if a later phase fails. There is no automatic undo after a committed phase;
use console access and the reported backups for disaster recovery. SIGKILL
or host power loss cannot run a shell cleanup trap.

Remote diagnostics are in per-host failure logs when a step fails. Backups
remain on the target even after success. Review them from console before
manual recovery; restoring whole account databases would also undo any
concurrent administrator changes made after the snapshot.

## Tests

Build the disposable test image:

```sh
docker build -f testing/users.Dockerfile -t ccdc-test:users testing
```

Run each real-service scenario entirely inside a disposable container:

```sh
docker run --rm --network none --hostname testbox -v "$PWD:/w:ro" ccdc-test:users sh /w/testing/users-scenarios.sh normal
```

Other scenarios are `controller`, `backup-failure`, `custom-grant`, and
`existing-admin`. `controller` runs the real coordinate binary, the terminal
checkpoint, fresh SSH/sudo connections and eight-column result checks.
`sh testing/test-users.sh` is an optional host-side launcher for the same
Docker runs; it performs no account changes on the host. Also run the repo's
`sh testing/check-syntax.sh` and `sh testing/test-scripts.sh` checks.
