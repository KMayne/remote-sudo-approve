# remote-sudo-approve

Approve every sudo command your AI agent runs with a passkey on your phone.

Give an agent its own Unix account and let it use `sudo`. Each time it does,
your phone shows the exact command (program, arguments, environment) and
you approve it with Face ID or a fingerprint. Your passkey signs exactly
what you saw, and the machine checks that signature itself before sudo runs
anything. Approvals can't be faked or reused, and a command that isn't on
your allowlist is flagged in red.

```
agent$ sudo systemctl restart soloist
remote-sudo-approve: waiting up to 120 s for approval: https://approve.example.ts.net/#Kq3…
```
```
 ┌───────────────────────────────┐
 │ sudo on office-pi             │
 │ claude wants to run, as root: │
 │  0  "systemctl"               │
 │  1  "restart"                 │
 │  2  "soloist"                 │
 │ program  /nix/store/…/systemctl│
 │ [ Approve with passkey ]      │
 └───────────────────────────────┘
```

It is for a home lab or a small fleet where you want an agent to be able to
fix things, but want a person to decide each time it touches root. It is
not a sandbox: once you approve a command, it runs as root. The point is
that what you approve is exactly what runs.

## How it works

1. **On each machine**, a [sudo approval plugin][sudo_plugin] runs a small
   verifier for every command the agent's account runs with sudo. The
   verifier checks the command against a few rules, then builds a
   description of it: the real program file, arguments, environment,
   working directory, host and a fresh random id.
2. **The server** (one small container) holds the request and sends a web
   push to your phone.
3. **The approval page** shows the request. Your passkey signs SHA-256 of
   exactly the bytes the page displays.
4. **The verifier** checks the signature against the public key it has
   pinned, and only then lets sudo run the command.

The server is just a messenger: it never decides anything, and a server
that drops, delays or alters what it carries can only cause a denial.
`DESIGN.md` has the protocol, the threat model and what it doesn't protect
against. `REVIEW.md` is the security review and how each finding was dealt
with.

What it checks before you're even asked:

- The program must be an installed program. Anything the agent copied,
  linked or built itself is refused, as is any path through a directory or
  symlink the agent could change after you approve.
- Shells, interpreters, editors, pagers and other programs that can start a
  root shell without showing it are refused outright (`bash`, `env`,
  `find`, `vim`, `less`, `newgrp`, `passwd`, `nixos-rebuild`…).
- The environment must be exactly what's expected, with no `LD_PRELOAD`,
  `PATH` changes or the like. The umask and resource limits are fixed
  rather than inherited from the agent's shell. The command's stdin is
  `/dev/null`.
- Arguments that name a file the agent can write are flagged, because that
  file can change after you approve.

Deploys go through one command, `remote-sudo-approve-switch <system>`. It only
switches to a NixOS system signed by your build machine, and the approval
shows what the switch changes in anything that decides who gets root.

## Requirements

- **The machines run NixOS.** The module that sets everything up is NixOS
  only. The plugin and verifier are plain Rust and sudo ≥ 1.9, so other
  distributions are possible but not packaged.
- **One HTTPS name** for the server that your phone and your machines can
  reach and that nobody else controls. A [Tailscale][tailscale] name
  (`approve.<tailnet>.ts.net`) is the easiest, since it's private to your
  tailnet and comes with a certificate.
- **A passkey provider** that supports user verification: iCloud Keychain,
  Google Password Manager, Bitwarden, a hardware key.

## Setup

### 1. Run the server

Container image: `ghcr.io/kmayne/remote-sudo-approve`. It listens on port 8080.
Make the secrets with the setup command in the image:

```sh
podman run --rm ghcr.io/kmayne/remote-sudo-approve remote-sudo-approve-setup init > server.env
#   prints a setup token once: keep it, it lets your phone subscribe
podman run --rm ghcr.io/kmayne/remote-sudo-approve remote-sudo-approve-setup host office-pi
#   prints {"office-pi":"<hash>"} for the server and a token for the machine
```

Put each machine's `{"name":"hash"}` into one `tokens.json` object.

- **Kubernetes:** `deploy/kubernetes/remote-sudo-approve.yaml`. Create the Secret
  from `server.env` and `tokens.json`, set `ORIGIN`, pin the image by
  digest, and add an ingress (there's a commented Tailscale example).
- **NixOS:** `nixosModules.server` from this flake, behind an HTTPS proxy
  or `tailscale serve`:

  ```nix
  services.remote-sudo-approve-server = {
    enable = true;
    origin = "https://approve.example.ts.net";
    environmentFile = "/run/secrets/remote-sudo-approve.env";
    hostTokensFile = "/run/secrets/remote-sudo-approve-tokens.json";
  };
  ```

Whoever can change the server's deployment can change the page you approve
on, so treat it like the machines themselves: pin the image, and don't let
the agent deploy it.

### 2. Register a passkey

On your phone, open `https://<your name>/register/`, create the passkey, and
keep the JSON it shows, including the key fingerprint. Then open the
approval page itself, choose **Get notifications on this device** and
enter the setup token. On iPhone, add the page to your home screen first:
iOS only delivers web push to installed web apps.

### 3. Enable it on a machine

```nix
{
  inputs.remote-sudo-approve.url = "github:KMayne/remote-sudo-approve";

  # in the machine's configuration:
  imports = [ inputs.remote-sudo-approve.nixosModules.default ];

  users.users.claude = { isNormalUser = true; uid = 1001; };

  security.remoteSudoApprove = {
    enable = true;
    gatedUsers = [ "claude" ];          # the agent's account
    ungatedUsers = [ "alice" ];         # every wheel user: their sudo is untouched
    origin = "https://approve.example.ts.net";
    tokenFile = "/run/secrets/remote-sudo-approve-token";  # this machine's token
    allowedPrograms = [ "systemctl" "journalctl" "reboot" ];
    credentials = [ {
      name = "phone";
      id = "…";          # from the registration page
      publicKey = "…";
    } ];
    # Optional: guarded deploys of systems signed by your build machine.
    # deploy.trustedPublicKeys = [ "builder-1:…" ];
  };
}
```

The token file must be readable by the `remote-sudo-approve` account only (for
example a sops-nix secret with that owner).

The build fails if anything undermines the setup: the agent in a group that
amounts to root (`wheel`, `docker`…), trusted by Nix, a polkit admin,
`doas` or `sudo-rs` enabled, or the plugin missing from `/etc/sudo.conf`.

Then, as the agent: `sudo -n systemctl status sshd`. Your phone should
light up. After you approve, the machine prints the key's fingerprint:
check it matches the one from registration.

## What it doesn't do

- **It isn't zero trust.** The model is an agent that is probably fine but
  might go wrong and start trying things, not a patient expert attacker.
  Some gaps are accepted rather than closed at the cost of convenience or
  a risk of locking you out; `DESIGN.md` lists them.
- **Programs off the allowlist can still be requested.** They carry a red
  warning: approve them only if you know what they do. No deny list can
  be complete.
- **An approved command keeps the agent's terminal.** A program that opens
  `/dev/tty` itself can read what the agent types.
- **It fails open in a few known ways.** It's a sudo *approval* plugin, so
  the agent's sudoers rule grants root on its own and the plugin is what
  takes it back. If sudo can't read `/etc/sudo.conf`, it runs without the
  plugin (sudo's own behaviour; hard to trigger, tested for, not patched).
  A policy plugin would fail closed, but would put your own sudo behind it
  too. `DESIGN.md` ("Why an approval plugin") lists each case and how it's
  handled.
- **It only covers sudo.** It doesn't stop the agent doing harm with its
  own account's rights.

## Building and testing

```sh
nix build .#default        # the plugin and verifier
nix build .#image          # the server's container image
cargo test                 # rules, request format, WebAuthn checks
(cd server && npm ci && node --test)   # end to end with a simulated passkey
(cd page && node --test)   # the page and the verifier agree byte for byte
nix build .#checks.x86_64-linux.vm -L  # real sudo in a NixOS VM (needs KVM)
```

`nix/test/test-passkey.pem` is a private key for the VM test only. It stands
in for a phone, so never pin it on a real machine.

## Related work

[stanleysvk87/sudo-approve][stanley] and [douglasjordan2/sudo-approve][douglas]
also approve sudo with a passkey. This project differs in that the signature
covers the exact execution as sudo will run it, and it is checked on the
machine itself, not by a central server. `DESIGN.md` has a longer
comparison.

[sudo_plugin]: https://www.sudo.ws/docs/man/sudo_plugin.man/
[tailscale]: https://tailscale.com/kb/1153/enabling-https
[stanley]: https://github.com/stanleysvk87/sudo-approve
[douglas]: https://github.com/douglasjordan2/sudo-approve

## Licence

MIT
