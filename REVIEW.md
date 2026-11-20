# Security review of the code, 2026-11-20

Two independent adversarial reviews of commit 252bd67 (A: plugin and
verifier; B: page, relay, NixOS module). Neither found a way to get an
approval without a valid signature or to make the plugin fail open. Findings
below, with status. "VM" = confirmed in a NixOS VM by the reviewer.

Decision: programs are an **allowlist per machine, plus ask-anyway**:
allowlisted programs show normally; any other installed program can still be
requested but with a red "not on the allowlist, may give a root shell"
banner; the deny list still applies.

## Breaks a goal

| # | Finding | Status |
|---|---|---|
| 1 | Hidden root shells pass the deny list: `newgrp` (VM), `sg`, `login`, `sulogin`, `agetty`, `setarch`/`linux64`…, `visudo`, `dc`, `prlimit`, `setsid`, `openvt`, `scriptlive`, `nixos-enter`, `ldd`, `coredumpctl debug`, `ssh-agent`; `passwd` sets root's password. Trusted set is the whole closure (3648 programs in the VM, 1282 installed). | fixed: trusted set = installed programs only; allowlist + warning; names added |
| 2 | Environment differs from the signed one: PAM session (`pam_env`) adds variables and a longer PATH after `check` (VM). | fixed: no PAM session/setcred for gated users; VM asserts env equality |
| 3 | No assertion that the plugin line is in the final sudo.conf; the rule is NOPASSWD so it fails open without it. Possible activation window with rule present and plugin absent. | fixed: assertion on the final sudo.conf (activation window still open) |
| 4 | Root-equivalence assertions bypassable: `users.groups.wheel.members`, primary group, `trusted-users = ["@users"]`, `extra-trusted-users`, groups `nixbld keys input root remote-sudo-approve`, `security.doas`, polkit adminIdentities. | fixed: effective groups vs `allowedGroups`, @group trust, doas, polkit |
| 5 | `stdin: tty` is agent-controlled (a pty it owns); the controlling tty too. | fixed: plugin replaces stdin with /dev/null (controlling tty remains; see DESIGN) |
| 6 | Inherited and unshown: rlimits (absent key = invoker's limits), ignored signals, umask (`def_umask \| user umask`; any octal accepted), nice, cgroup. | fixed for rlimits and umask (pinned + required); ignored signals, nice, cgroup accepted |
| 7 | Path warnings miss `tmp/x`, `--x=tmp/x`, `-f/tmp/x`, `--a=b=/tmp/x`, `@/tmp/x`, `a:/tmp/x`, `file:///tmp/x`; treat EACCES as nonexistent; unescaped real paths in warning text; no warning for store paths outside the system. | fixed except store paths outside the system (open) |
| 8 | Deploys unguarded until the deploy command exists: `nixos-rebuild`, `switch-to-configuration`, `nixos-install`, `nixos-enter`, `nixos-container` not denied. | fixed: denied by name; deploys go through `remote-sudo-approve-switch` with the security diff |
| 9 | Page shows less than it signs: only argv/env values escaped; runs of spaces collapse; warning "argument N" off by one vs the list; a leading BOM is hashed but not parsed. | fixed (needs a look in a real browser) |

## Breaks real use (fails closed)

| # | Finding | Status |
|---|---|---|
| 10 | `SUDO_TTY` not on the env allowlist: every sudo from a terminal refused (VM). | fixed |
| 11 | Programs behind setuid wrappers (`mount`) refused: `/run/wrappers/bin` first in secure_path. | fixed |
| 12 | A wheel user not in `ungatedUsers` is gated without Defaults: denied. More than 7 ungated users silently ignored. | fixed: assertions |
| 13 | Deny prefixes catch `node_exporter` etc. | fixed |

## Hardening

| # | Finding | Status |
|---|---|---|
| 14 | Page: can be framed (frame-ancestors/COOP/HSTS need real headers); request can be swapped by an opener just before the tap; no dwell time. | fixed in the page (frame/opener refusal, 1.5 s dwell, no auto-reload); headers in page/headers.conf must be applied at deploy |
| 15 | Relay origin `api.approve.…` is inside the RP ID; move to a sibling name. Registration page must be on the approve origin or below it: it is part of the trust base. | relay moved to approve-api.…; registration page trust still to document |
| 16 | Wrong key pinned: show a fingerprint at registration and on "approved by". | fixed: fingerprint at registration and on every approval |
| 17 | sudo ignores a failed read of sudo.conf (would run without the plugin); no trigger found. VM-test small `ulimit -n`/`-v` and assert. | accepted (the owner): no sudo patch, no lockout risk; VM test starves fds and memory |
| 18 | Plugin: fixed 125 s deadline vs configurable expiry (expiry now capped at 120 in the module); no rlimits in child; verifier stderr is the agent's fd; `copy_array` truncates silently; `write_all` has no deadline. | partly: expiry capped at 120, child rlimits, no silent truncation; stderr and write_all deadline open |
| 19 | Relay client: `MAX_ASSERTIONS` cap ineffective (relay controls `next`); busy loop on empty replies; 10 MB read before the size check. | fixed |
| 20 | Relay: subscription lost if added during a push; no per-push timeout; setup token reusable, can evict devices and POST to any https endpoint. `relay` option accepts http. | fixed: push-host allowlist, per-push timeout, no lost subscriptions; setup token still reusable (open) |
| 21 | Page setup: Trusted Types policy created per click; no guard for browsers without it; permission request after `prompt()`. | fixed |
| 22 | DESIGN vs code: visudo not strict; verifier path is a sudo.conf option, not compiled in; names (`agent.env`), 125 vs 120 s; VM test claims (relay down for the agent, verifier missing, "last match"); cargo/node tests not in flake checks; no aarch64 check; clock without RTC. | DESIGN brought in line; cargo/node tests in flake checks and an aarch64 run deferred |
| 23 | Tests missing: `Trusted::Closure`, plugin fork/exec path, pty stdin, env equality (`printenv` == signed env), relay `next` rules. | mostly added (pty, env equality, starvation, relay down); plugin fork path and the page in a browser still untested |

## Found sound

FFI layout and signatures against sudo_plugin.h; `open` returns 0 only on
the uid fast path; child setup (close_range, setres*id, empty env);
command_info allowlist for keys that change execution; component-wise path
resolution, no TOCTOU found; frame decoding; canonical form injective, Rust
and JS agree on every tricky input tried; WebAuthn checks (exact origin,
type, challenge, rpIdHash, UP/UV; serde rejects duplicate keys); relay
serves JSON only and can't approve; sw.js has no fetch handler; CSP and
Trusted Types directives used are honoured in `<meta>`.

## Later decision (2026-11-20)

The page and the relay are one server at one address again (finding 5 of the
design review, and 14/15 here, argued for separating them). The owner's reason:
the tool should be easy for other people to adopt, and the separation was
hard to explain and to deploy correctly. DESIGN.md "Why one server" states
what that costs and what guards remain.
