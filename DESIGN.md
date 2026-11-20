# remote-sudo-approve: approve each sudo command with a passkey

Status: design v2, for review before implementation. v1 was reviewed
adversarially (findings folded in below, marked [R#]); prior art is in
"Related work".

## Goal

AI agents run as their own unix user (`claude`) on the machines they look
after. (Agents the owner runs under their own account, supervised directly,
are out of scope; see "Scope and trade-off".) That user may run any command as root, but only
after the owner approves that exact command with a passkey. Everything fails
closed: no approval, a bad approval, a timeout, an unreachable service or a
plugin error all mean the command does not run. The owner's own account is
unaffected.

Agents also must not be able to remove or weaken this through configuration:
not by deploying a new NixOS system, and not through the automatic updates.

## Threat model

**Attacker:** the agent and anything it controls. Assume it:

- runs arbitrary code as `claude` (any shell, any timing; can signal, stop and
  resume its own processes; can write its home, /tmp and anything else
  `claude` can write; can build arbitrary Nix store paths);
- holds a Home Assistant **admin** token (read and send any notification,
  fire any event, edit automations; close to code execution inside HA);
- can reach the relay API and every LAN and cluster service;
- can read this repo and every deployed config;
- can push branches to the config repos, but cannot sign commits as the owner.

**Trusted (the trust base):**

1. The passkey and the device(s) holding it.
2. The server that serves the approval page: its code and deployment, and
   whatever gives it its name and certificate (at home: Tailscale). [R5]
3. root on each target, the Nix store's integrity, the running NixOS system.
4. The owner's commit signing key, and the owner's review of what they sign.
5. The browser on the approving device.

## Scope and trade-off

The model is not zero trust. The agent is probably well-behaved but could
go wrong and start trying things; it is not assumed to be a patient expert
attacker with unlimited attempts. Defences that cost the owner convenience or
risk locking them out are weighed against that (decided 2026-11-20).

This protects against the sandboxed agents (any agent using a `claude`
account, such as an always-on agent in a container). It does not protect against agents on
the owner's own machine, which run as the owner with cluster-admin, deploy rights and their
GitHub sign-in, and so could change the trusted parts (the page, the relay,
the config). The owner supervises those sessions directly and accepts that risk
for a home lab: convenience over a stronger guarantee (decided 2026-11-20).

**Goals:**

- G1. No command runs as root for `claude` without a passkey signature, made
  after user verification, over a complete description of that execution.
- G2. What the owner sees is exactly what was signed, and what was signed is
  exactly what runs: the same program file, arguments, environment, working
  directory, user, and other execution settings.
- G3. A signature is good for one execution, once, for a short time.
- G4. A relay that drops, delays or alters what it carries can deny, never
  approve. (A takeover of the server that also serves the page is a
  different matter: see "Why one server".)
- G5. The owner and root are never locked out, and a broken plugin can't block
  them.
- G6. `claude` cannot remove or weaken this system: not by deploying, not
  through automatic updates, not through any other root path (wheel, Nix
  trusted-users, docker, polkit, the owner's account).

## Components

```
 target machine                          the server                  phone
 ┌───────────────────────────────┐       ┌────────────────────┐
 │ sudo (setuid root)            │       │ one process, one   │ web push ┌───────────┐
 │  └ approval plugin (.so)      │ HTTPS │ address:           │─────────▶│ passkey   │
 │     └ exec verifier           │──────▶│  /      the page   │          │ provider  │
 │        reads token, pubkeys,  │◀──────│  /v1/   the relay  │◀─────────│ + browser │
 │        program lists          │       └────────────────────┘  HTTPS   └───────────┘
 └───────────────────────────────┘
```

1. **Approval plugin** (`remote_sudo_approve.so`, Rust, `panic=abort`, minimal).
   See "Plugin".
2. **Verifier** (`remote-sudo-approve-verify`, Rust). Builds the request, applies
   the rules, talks to the relay, verifies the assertion. Its absolute store
   path is a plugin option in /etc/sudo.conf (root-owned, in the Nix store).
3. **The server** (`remote-sudo-approve-server`, Node; one container image). At one
   address it serves:
   - **the approval page** (`/`) and **registration page** (`/register/`):
     static files, no third-party code. The page has no names built in: it
     talks to the server it came from and uses its own host name as the
     passkey's RP ID. This is the part that must not be tampered with.
   - **the relay API** (`/v1/`): holds pending requests and every assertion
     received for them, and sends the web push. Untrusted for decisions: it
     never sees one.

### Why one server, and what that costs

An earlier version ran the page and the relay as separate deployments on
separate names, so that a bug in the relay (which handles input the agent
controls) couldn't alter the page (which must show exactly what is signed).
They are one server now because that is far easier to deploy and to
explain: one image, one address, no cross-origin setup, nothing to
configure in the page.

The cost: G4 holds against a relay that misbehaves as a relay (drops,
delays or alters requests and assertions; the machines' own checks catch
all of that), but not against someone who takes over the server process or
its deployment. They could serve a page that shows one command and signs
another. What stands in the way:

- the page's files are a fixed list read once at startup, served only at
  their exact paths, from a read-only image;
- every `/v1/` response is JSON or empty, with `nosniff` and a CSP of
  `default-src 'none'`, so text the agent sends can't run as a page on this
  origin;
- the server is about 350 lines with one dependency (web-push).

Anyone who wants the stronger separation can run two instances behind two
names and point `relay` at the second; the machines only need the page's
origin for verification.

The registration page sends nothing anywhere and shows a fingerprint of
the new key; machines print the same fingerprint on every approval. [R11]

Notifications use standard Web Push from the server to the page installed
as a web app on the phone. Notification text is untrusted; the page says
so. [R19]

## Plugin

sudo calls `open` and then `check` for every command it runs: `sudo cmd`,
`-i`, `-s` and `-e`/sudoedit (sudo.c: MODE_RUN and MODE_EDIT). `-l`, `-v`, `-k`
and `-V` never run a command.

- **`open` return values are part of the security** [R2]. sudo treats 0 as
  "disable this plugin" and then runs the command unchecked. So `open`
  returns 1 for every gated user in every case, including on internal errors,
  which are reported later by `check` returning 0. It returns 0 only on the
  deliberate fast path for a user that isn't gated, and decides that from the
  uid in `user_info` before any allocation or I/O. [R12]
- **Who is gated:** every user except an explicit allowlist (`root`, `the owner`).
  New accounts are gated by default. [R9]
- **`check`:** spawns the verifier and passes `command_info`, `run_argv` and
  `run_envp` to it with length-prefixed framing, never newline-separated text
  [R8]. Approves only if the verifier exits 0 and a monotonic deadline (125 s; the request itself expires after at most 120 s
  from the start of `check`) hasn't passed when it does [R16]. Any other
  outcome (non-zero, signal, exec failure, EINTR, ECHILD, deadline) is a
  denial.
- **Spawning:** `fork`, then in the child: reset the signal mask and
  handlers, `closefrom(3)`, `chdir("/")`, `umask(077)`, fixed rlimits,
  `setresgid` and `setresuid` to the `remote-sudo-approve` system user so claude
  can't signal or trace it [R15], empty environment, then `execve` the fixed
  verifier path. The broker token is readable only by `remote-sudo-approve`.
- **No unwinding across FFI:** every entry point wraps `catch_unwind`; the
  crate builds with `panic=abort`.

### Why an approval plugin, and its known issues

sudo offers four places to hook in. This tool uses an **approval plugin**
(sudo ≥ 1.9): sudoers still decides who may run what, and the plugin gets a
final yes/no on the exact command, environment and directory sudo is about
to run.

| Option | Sees the exact execution | If it breaks or isn't loaded | Owner's own sudo |
| --- | --- | --- | --- |
| **Approval plugin** (chosen) | yes (`command_info`, `run_argv`, `run_envp`) | the agent's sudoers rule applies **without approval** | untouched (fast path) |
| Policy plugin replacing sudoers | yes | the agent has no rule in sudoers, so it's denied | goes through the plugin too: a bug can lock everyone out |
| PAM module | no (only `SUDO_COMMAND`, not the environment) | denies | goes through PAM's sudo stack |
| Patched sudo | yes | whatever the patch does | a modified sudo to carry and update |

The approval plugin was chosen because it can't affect anyone but the gated
users and needs no change to sudo itself. The cost is that it **fails open**
in a few well-defined ways: the agent's sudoers rule
(`NOPASSWD: NOSETENV: ALL, !sudoedit`) grants root by itself, and the plugin
is the only thing that takes it back.

1. **`/etc/sudo.conf` is optional to sudo.** If the file is missing or can't
   be read, sudo loads no plugins and runs on sudoers alone. See "Known
   limits": not triggered in review, tested with starved fds and memory,
   not patched.
2. **`open` returning 0 disables the plugin** for that invocation (sudo's
   documented behaviour, not an error). Handled by returning 1 for every
   gated user, even on internal errors.
3. **A system with the rule but without the plugin line** (a bad edit, or the
   moment during activation when sudoers is new and sudo.conf old). The
   NixOS module asserts the line is in the final sudo.conf; the activation
   window is accepted.
4. **Other ways to root ignore it.** `doas`, `sudo-rs` (no plugin support),
   polkit admin rights and Nix trusted users are separate paths; the module
   refuses to build if any of them is open to a gated user.
5. **Approval runs before the PAM session.** Anything `pam_env` or a session
   module would add to the environment isn't in what was signed, so the
   module turns off `pam_session` and `pam_setcred` for gated users.

A policy plugin would close 1–3 (the agent fails closed), at the price of
putting every sudo on the machine, the owner's included, behind new code.
That's the right trade if you don't need an untouched sudo for yourself; it
isn't this tool's.

## The request

The verifier builds the request `R` as JSON, ASCII only (every non-ASCII
character `\u`-escaped), fields in a fixed order [R18]:

```json
{"v":2,"id":"<128 random bits, base64url>",
 "host":"office-pi","user":"claude","runas":"root",
 "command":"/nix/store/…-systemd-258/bin/systemctl",
 "argv":["systemctl","restart","nginx"],
 "env":[["HOME","/root"],["LANG","C.UTF-8"],…],
 "cwd":"/","stdin":"null",
 "created":1795100000,"expires":1795100120,
 "change":null,
 "warnings":[]}
```

`C = SHA-256(R)` is the WebAuthn challenge.

### What must hold before a request is even sent (else deny)

**Program** [R3]:

- `command` from `command_info` must be absolute. Its real path must be
  exactly one of the installed programs: the real files behind
  /run/current-system/sw/{bin,sbin}, listed at build time in
  /etc/remote-sudo-approve/programs. Not their dependencies (the whole closure
  had 3648 programs in a test VM; 1282 were installed). Anything `claude`
  copied, symlinked or built itself is refused. `R` shows the real path.
- **Allowlist:** each machine lists the programs the agent uses routinely
  (`allowedPrograms`, by name). A program on it shows normally. Any other
  installed program can still be requested, but the request carries "NOT
  ON THE ALLOWLIST…" as its first warning. A multi-call binary is on the
  list only under the allowed name.
- sudo execs `command` as given, not its real path, so the path is resolved
  one component at a time and every hop must be out of the agent's reach:
  each directory looked in is root-owned and not group- or world-writable
  (except a sticky group-writable directory, i.e. /nix/store, when the entry
  is root's), and each symlink followed is root-owned. Otherwise a symlink
  could be repointed between approval and exec.
- The real path must not be a shell, an interpreter, a launcher or an
  interactive program that can run commands: shells, `python*` `perl` `ruby`
  `node` `lua` `php` `tclsh` `awk` `gawk` `sed` `env` `nice` `nohup`
  `timeout` `xargs` `find` `sudo` `su` `doas` `pkexec` `nix` `nix-*`
  `systemd-run` `busybox` `script` `expect` `gdb` `strace` `ltrace`, and
  editors and pagers (`vi*` `nano` `emacs` `ed` `less` `more` `most` `man`).
  `systemctl edit` and `git` with a pager are covered by the environment
  rules below. [R4]
- The deny list is checked against every name the program is known by:
  the command path, each symlink followed, the real file and argv[0]. On
  NixOS `env`, `touch` and friends are symlinks to one multi-call
  coreutils binary that picks its behaviour from argv[0], so checking only
  the real file's name let `sudo env …` through (found by the VM test).
  `--coreutils-prog` is refused for the same reason.
- `sudoedit` (`sudoedit=true` in `command_info`) is refused, and sudoers
  denies it too. [R6]

**Execution settings** [R7]: `command_info` must contain exactly the
expected keys and values: `runas_uid=0`, `runas_gid=0`, `cwd=/` present,
no `chroot`, no `preserve_groups`, `umask` as configured, no `rlimit_*=user`,
no `execfd`, no `preserve_fds`, and so on. An unknown key is a denial, so a
sudo upgrade that adds one fails closed until the list is reviewed.

**Environment** [R1]: every entry of `run_envp` must be on an exact
allowlist of names, and for most names an exact value (`HOME=/root`,
`USER`/`LOGNAME=root`, `SHELL`, `PATH` equal to the secure path,
`PAGER=cat` and friends from `env_file`, `TERM` and `LANG` from small sets).
The environment is also shown in `R`.

**Size**: at most 64 arguments and 4 KiB in total; argv must be valid UTF-8.

### Warnings (shown in red on the page, part of what's signed)

- Any argument, or any path inside an argument (including after `=`, as in
  `--config=…` or `if=…`), whose real path is writable by `claude` (owner,
  mode or ACL on any component), or that names `/dev/fd`, `/dev/std*`,
  `/proc` or `/run/user`. That file can change after approval. [R7]
- The program isn't on the allowlist (always first).
- Paths are looked for generously: relative to /, after `=`, `:`, `,`, `@`,
  a short option letter or `file://`. A directory the verifier can't look
  into counts as "can't be inspected" unless only root can enter it.

stdin needs no warning: the plugin replaces an approved command's stdin
with /dev/null, and `R` says `"stdin":"null"`. (A terminal can't be trusted
either: the agent can run sudo on a pty it owns.)

## Approval

1. Verifier → relay: `POST /v1/requests` with the per-host bearer token and
   body `R`. The relay stores it and sends a web push: "sudo on
   office-pi" and a link `https://approve.…/#<id>`. Per-host rate limit.
2. The page fetches `R` from the relay as JSON text, decodes it with a fatal
   UTF-8 decoder, checks that re-serialising it gives the same bytes, and
   renders every field with `textContent` only: each argument on its own
   line, escaped, never truncated; warnings in red; the security diff in full.
   It computes `C = SHA-256(bytes)` itself; it never accepts a challenge from
   the relay. [R5, R18]
3. Approve → `navigator.credentials.get({challenge: C, rpId:
   "approve.example.ts.net", userVerification: "required"})`.
4. The page posts the assertion to the relay. The relay keeps every
   assertion it receives for that id [R17].
5. The verifier long-polls for assertions until `expires`, trying each,
   then withdraws the request (`DELETE`) however it ended. It prints the
   approval link on the terminal; ids aren't secret.

### Verification (all must hold)

1. Credential id is one of the pinned ones; use its P-256 public key (ES256
   only).
2. `clientDataJSON`: `type == "webauthn.get"`, `challenge == base64url(C)`
   with `C` from the verifier's own `R`, `origin ==
   "https://approve.example.ts.net"`, `crossOrigin` absent or false,
   no `topOrigin`.
3. `authenticatorData` ≥ 37 bytes, `rpIdHash == SHA-256(rp id)`, flags UP
   and UV set; if the pinned credential is marked device-bound, BE (0x08)
   must be clear. [R10]
4. ECDSA signature over `authenticatorData ‖ SHA-256(clientDataJSON)`.
5. Within `expires`.

Exit 0 only after all five. The verifier keeps no state; each sudo call has a
new random id, so an assertion is never reusable.

## Keeping the system in place (G6)

### Agent accounts

`claude` is a normal user on each machine. NixOS assertions fail the build
if it is in any group outside `allowedGroups` (default: only `users`;
counting its primary group, extraGroups and groups' member lists), if Nix
trusts it (by name, `*` or `@group`, in trusted-users or
extra-trusted-users), if it is a polkit administrator, if `security.doas`
or `security.sudo-rs` is enabled, if the plugin line is missing from the
final /etc/sudo.conf, or if a wheel user is neither gated nor ungated. [R9,
R12] Nothing of the owner's is reachable from it: no shared writable directories,
no the owner ssh key, no the owner group.

sudoers, after every other rule so it is the last match:

```
Defaults:claude env_reset, env_keep = "TERM LANG", runcwd = /, env_file = /etc/remote-sudo-approve/agent.env
Defaults:claude secure_path = "/run/current-system/sw/bin"
Defaults:claude !pam_session, !pam_setcred
Defaults:claude umask = 0022, umask_override
Defaults:claude rlimit_as = "infinity", rlimit_core = "0", … (every rlimit)
claude ALL=(root) NOPASSWD: NOSETENV: ALL, !sudoedit
```

- `NOSETENV` because SETENV is implied for an `ALL` rule and overrides
  `!setenv` [R1]. `!sudoedit` lowercase; `!SUDOEDIT` silently matches
  nothing [R6]. (NixOS checks the file with `visudo -c`, not strict mode;
  the VM test checks the rule as sudo reports it.)
- No PAM session: `pam_env` would add variables after the approval, so the
  command's environment wouldn't be the signed one. The VM test compares
  `printenv` with the signed environment.
- umask and every resource limit are pinned, and the verifier requires
  exactly those values in `command_info`: sudo would otherwise give the
  command the invoking shell's.
- No /run/wrappers/bin in the path: setuid wrappers aren't trusted programs
  and root doesn't need them.
- `agent.env` sets `PAGER=cat SYSTEMD_PAGER=cat GIT_PAGER=cat MANPAGER=cat
  LESSSECURE=1 EDITOR=VISUAL=SYSTEMD_EDITOR=/run/current-system/sw/bin/false`.
  [R4]
- `NOPASSWD` because the passkey is the authentication.

### Deploys by an agent

One command, `sudo remote-sudo-approve-switch /nix/store/<system>` (present when
`deploy.trustedPublicKeys` is set; allowlisted automatically). The agent
fetches the system first (`nix-store --realise`, no root needed).

- The verifier recognises the command and fills `change`: the target and
  the differences, between the running system and the target, in the files
  that decide who gets root (verify/src/change.rs): sudoers and sudoers.d,
  sudo.conf, this tool's config, env file, programs and allowlist, PAM's
  sudo config, sshd config and authorized keys, nix.conf, polkit rules,
  doas.conf, and a summary the module writes of users, groups, Nix trusted
  users, deploy keys and setuid wrappers. Store hashes and version numbers
  are ignored, so an ordinary update shows "No security changes".
- The page shows the diff in red. The check runs from the running system's
  code, so the new system can't disable it.
- After approval the command itself (as root) requires the target to be
  signed by a deploy key (`nix store verify --sigs-needed 1`, without
  `--no-trust`): a system built on the machine doesn't pass. Then it sets
  the system profile and runs `switch-to-configuration switch`.
- Not covered: the summary is written by the module from the NixOS config,
  so a config that overrides the summary itself could hide a new user; the
  list of root services isn't compared. Signed commits are the check for
  those.

### Automatic updates

1. **Signed commits.** The builder only builds commits on `main` whose
   signature verifies against the owner's pinned signing key. Agents push
   branches; the owner reviews and merges with a signed commit.
2. **Security files frozen for auto-update.** The auto-update service
   runs `remote-sudo-approve-diff <target>` (exit 1 on any difference) and refuses
   an update that changes them; those changes need a passkey-approved deploy, which shows
   the diff.

Between them: agents can't change the security files without the passkey,
and can't change anything else without the owner's signed review.

## Names and TLS [R5]

The server needs one HTTPS name that the approving device and the machines
can reach. The passkey is bound to that name (its RP ID), so changing it
means registering a new passkey.

For example `approve.example.ts.net`, through the cluster's
Tailscale ingress: reachable only on the tailnet, no public DNS records, a
certificate provisioned by Tailscale, and a name that follows the service
if addresses change. Tailscale is therefore in the trust base for the
page; it already controls access to everything in the house. The phone
needs Tailscale connected to approve. Whoever can put another device on
the tailnet under the name `approve` could serve a fake page: tailnet admin
rights are the owner's alone.

## Lockout (G5) [R12]

- If the plugin can't load or `open` returns -1, sudo fails for everyone.
  Mitigations: the fast path for allowlisted users does no work; a NixOS VM
  test runs sudo as the owner and as claude with the relay down and with the
  verifier's config missing; a break-glass root login that doesn't use sudo (root ssh
  key held by the owner, or console password).

## Known limits (accepted)

- sudo treats /etc/sudo.conf as optional: if it can't be read, sudo runs
  with the sudoers policy alone, and the gated users' rule is passwordless.
  The file is root-owned, sudo raises its own limits before reading it, and
  the review couldn't trigger a failed read; the VM test tries with starved
  file descriptors and memory. Not patched: it would mean carrying a
  modified sudo, and making the plugin mandatory risks locking the owner out.

- An approved command's stdin is /dev/null, but it keeps the agent's
  controlling terminal: a program that opens /dev/tty itself reads what the
  agent types. Most that do are refused by name (`passwd`, `ssh`, `su`).
- Signal dispositions, nice value and cgroup are inherited from the agent's
  shell (umask and resource limits are pinned). With a delegated user slice
  the agent can freeze or kill an approved command part-way.
- The deny list can't be complete; the allowlist warning is the real
  signal. A program off the allowlist should be approved only when you know
  what it does.

- The owner judges each command. A command can be powerful in plain sight
  (`systemctl stop`, `rm`, `dd of=/dev/…`); the system guarantees only that
  what they approve is what runs.
- A child process of an approved command isn't separately approved. sudo's
  `INTERCEPT` could gate every exec, at one prompt each; off by default,
  available as an option.
- `claude` can stop its own sudo process after approval and resume it
  later; the plugin's deadline only covers the time until approval.
- A file the command reads from a `claude`-writable place can change after
  approval; flagged as a warning, not prevented.

## Related work

- stanleysvk87/sudo-approve: PAM + local WebAuthn verification (v2). Takes
  the command from `SUDO_COMMAND` in the environment; PAM approves a sudo
  login, not a command; the page trusts the backend's description.
- douglasjordan2/sudo-approve: passkey checked only by the hub, which then
  signs directives with its own key, so the hub can approve anything.
- ai-sudo, agent-sudo, sudoplz, sudo-relay, PushGate: wrappers or button
  approvals; the relay or wrapper can be bypassed or approve by itself.
- Duo `pam_duo` with `pushinfo`: shows the command, but PAM and Duo's cloud.
- square/sudo_pair: a Rust sudo plugin (I/O plugin, not approval); reference
  for FFI. JarvisOS #310: the same signing idea, as a proposal.

## Decisions (2026-11-20)

1. **Agent deploys:** builder-signed systems only, so only from commits the owner
   signed. The deploy command refuses anything else.
2. **Passkey:** a synced passkey (e.g. in a password manager). UV required on every approval; BE is not
   checked. Before registering, test that the provider re-prompts (biometric or
   password) for each assertion, on the phone and in the browser extension.
3. **INTERCEPT:** off. One approval per command; hidden-shell programs are
   refused instead.

## To check while implementing

- That the passkey provider sets UV only after a fresh biometric or
  password check, and what it sets BE to.
