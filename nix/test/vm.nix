# NixOS VM test: the module on a real NixOS with real sudo. The relay runs
# on the machine; an "approver" script stands in for the phone: it fetches
# the request bytes from the relay, hashes them and signs with the test key
# (nix/test/test-passkey.pem), as the page and a passkey would.
{ self, pkgs }:

let
  testKey = ./test-passkey.pem;
  spki = pkgs.lib.removeSuffix "\n" (builtins.readFile ./test-passkey.spki.b64);
  credId = "dGVzdC1wYXNza2V5"; # base64url("test-passkey")
  hostToken = "test-host-token-0123456789abcdef";
  rp = "approve.example.ts.net";

  approver = pkgs.writeText "approve.mjs" ''
    // node approve.mjs <id> [mode]: sign the request like the page does.
    import crypto from "node:crypto";
    import fs from "node:fs";
    const [id, mode = "good"] = process.argv.slice(2);
    const RELAY = "http://127.0.0.1:8080";
    const key = crypto.createPrivateKey(fs.readFileSync("${testKey}"));
    const sha = (b) => crypto.createHash("sha256").update(b).digest();
    let bytes = Buffer.from(await (await fetch(RELAY + "/v1/requests/" + id)).arrayBuffer());
    if (mode === "other") bytes = Buffer.from(bytes.toString().replace("true", "id"));
    const clientData = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: sha(bytes).toString("base64url"), origin: "https://${rp}", crossOrigin: false }));
    const authData = Buffer.concat([sha("${rp}"), Buffer.from([mode === "no-uv" ? 1 : 5, 0, 0, 0, 0])]);
    const sig = crypto.sign("sha256", Buffer.concat([authData, sha(clientData)]), key);
    const r = await fetch(RELAY + "/v1/requests/" + id + "/assertions", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ id: "${credId}", authenticatorData: authData.toString("base64url"), clientDataJSON: clientData.toString("base64url"), signature: sig.toString("base64url") }) });
    console.log("posted", r.status);
  '';

  tokens = pkgs.writeText "tokens.json" (
    builtins.toJSON { machine = builtins.hashString "sha256" hostToken; }
  );
in
pkgs.testers.runNixOSTest {
  name = "remote-sudo-approve";
  nodes.machine =
    { config, ... }:
    {
      imports = [ self.nixosModules.default ];
      virtualisation.memorySize = 1536;
      users.users.alice = {
        isNormalUser = true;
        uid = 1000;
        extraGroups = [ "wheel" ];
      };
      users.users.claude = {
        isNormalUser = true;
        uid = 1001;
      };
      security.sudo.wheelNeedsPassword = false;
      environment.systemPackages = [
        pkgs.nodejs
        pkgs.curl
      ];

      security.remoteSudoApprove = {
        enable = true;
        ungatedUsers = [ "alice" ];
        insecureRelay = true;
        # A made-up builder key: nothing in the VM is signed by it.
        deploy.trustedPublicKeys = [ "test-1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" ];
        allowedPrograms = [
          "touch"
          "true"
          "printenv"
          "cat"
        ];
        host = "machine";
        origin = "https://${rp}";
        relay = "http://127.0.0.1:8080";
        tokenFile = "/run/remote-sudo-approve-token";
        expirySeconds = 20;
        credentials = [
          {
            name = "test phone";
            id = credId;
            publicKey = spki;
          }
        ];
      };

      # A second system to "deploy": it lets the agent run one more program
      # without the warning and adds a user.
      specialisation.other.configuration = {
        security.remoteSudoApprove.allowedPrograms = [ "id" ];
        users.users.mallory = {
          isNormalUser = true;
          uid = 1002;
        };
      };

      systemd.services.remote-sudo-approve-server = {
        wantedBy = [ "multi-user.target" ];
        environment = {
          PORT = "8080";
          ORIGIN = "https://${rp}";
          HOST_TOKENS_FILE = "${tokens}";
          SETUP_TOKEN_SHA256 = builtins.hashString "sha256" "setup-token-0123456789abcdef";
          SUBSCRIPTIONS_FILE = "/var/lib/remote-sudo-approve-server/subs.json";
          # Test-only VAPID keys (no pushes are sent: no subscriptions).
          VAPID_PUBLIC_KEY = "BGDdCo54miN8ropMYxcB68zK-KKGDfW02nsN7swzFecuwZ4KwXBXN2y0OZy-J1g6rgrDQeU8H1-5yVKhAYIzjdU";
          VAPID_PRIVATE_KEY = "WoX2EBffVK6yuhEJyhydpGpivlLP07y8AlITkqUZ8GU";
        };
        serviceConfig = {
          ExecStart = pkgs.lib.getExe self.packages.${pkgs.system}.server;
          StateDirectory = "remote-sudo-approve-server";
          DynamicUser = true;
        };
      };

      systemd.tmpfiles.rules = [
        "f+ /run/remote-sudo-approve-token 0400 remote-sudo-approve remote-sudo-approve - ${hostToken}"
      ];
    };

  testScript = ''
    import json
    import re

    machine.wait_for_unit("multi-user.target")
    machine.wait_for_open_port(8080)

    def as_user(user, cmd):
        return f"su - {user} -c {cmd!r}"

    def approved_run(cmd, mode="good"):
        """Start sudo as claude in the background, approve via the test key.
        Returns (exit code, output, the request as the relay holds it)."""
        machine.succeed("rm -f /tmp/out /tmp/rc")
        # Fully detached, or the test driver waits for it to finish.
        machine.succeed(as_user("claude", f"({cmd}) >/tmp/out 2>&1; echo $? >/tmp/rc") + " </dev/null >/dev/null 2>&1 &")
        machine.wait_until_succeeds("grep -q -e '#' -e denied /tmp/out", timeout=30)
        out = machine.succeed("cat /tmp/out")
        assert "denied" not in out, out
        m = re.search(r"#([A-Za-z0-9_-]{22})", machine.succeed("cat /tmp/out"))
        assert m is not None, machine.succeed("cat /tmp/out")
        rid = m.group(1)
        req = json.loads(machine.succeed(f"curl -sf http://127.0.0.1:8080/v1/requests/{rid}"))
        machine.succeed(f"node ${approver} {rid} {mode}")
        machine.wait_until_succeeds("test -s /tmp/rc", timeout=60)
        return int(machine.succeed("cat /tmp/rc").strip()), machine.succeed("cat /tmp/out"), req

    with subtest("the server serves the page and the API on one address"):
        assert "<title>sudo approval</title>" in machine.succeed("curl -sf http://127.0.0.1:8080/")
        machine.succeed("curl -sf http://127.0.0.1:8080/register/ | grep -q passkey")
        machine.succeed("curl -sf http://127.0.0.1:8080/v1/vapid-public-key | grep -q key")

    with subtest("alice (ungated) is unaffected, even with the relay down"):
        machine.succeed("systemctl stop remote-sudo-approve-server")
        machine.succeed(as_user("alice", "sudo -n true"))
        machine.succeed("systemctl start remote-sudo-approve-server")
        machine.wait_for_open_port(8080)

    with subtest("root is unaffected"):
        machine.succeed("sudo -n true")

    with subtest("claude is denied when nobody approves"):
        machine.fail(as_user("claude", "timeout 40 sudo -n true"))

    with subtest("claude is denied with the relay down"):
        machine.succeed("systemctl stop remote-sudo-approve-server")
        machine.fail(as_user("claude", "timeout 40 sudo -n true"))
        machine.succeed("systemctl start remote-sudo-approve-server")
        machine.wait_for_open_port(8080)

    with subtest("claude with a genuine approval: the command runs as root"):
        rc, out, req = approved_run("sudo -n touch /root/proof")
        assert rc == 0, out
        machine.succeed("test -f /root/proof")
        assert req["warnings"] == [], req
        assert req["stdin"] == "null", req

    with subtest("the environment that runs is exactly the one signed"):
        rc, out, req = approved_run("sudo -n printenv")
        assert rc == 0, out
        ran = {l for l in out.splitlines() if "=" in l and not l.startswith("remote-sudo-approve:")}
        signed = {f"{k}={v}" for k, v in req["env"]}
        assert ran == signed, (ran ^ signed)

    with subtest("the command's stdin is /dev/null, whatever the agent pipes in"):
        rc, out, req = approved_run("echo agent-input | sudo -n cat")
        assert rc == 0, out
        assert "agent-input" not in out, out

    with subtest("sudo from a terminal works, and still gets no agent input"):
        rc, out, req = approved_run("script -qec 'sudo -n true' /dev/null")
        assert rc == 0, out

    with subtest("umask and limits come from sudoers, not the agent's shell"):
        rc, out, req = approved_run("umask 077; ulimit -n 64; ulimit -f 1; sudo -n true")
        assert rc == 0, out

    with subtest("a program off the allowlist is flagged"):
        rc, out, req = approved_run("sudo -n id")
        assert req["warnings"][0].startswith("NOT ON THE ALLOWLIST"), req
        rc, out, req = approved_run("sudo -n mount")
        assert rc == 0, out

    with subtest("an approval without user verification is refused"):
        rc, out, req = approved_run("sudo -n touch /root/no-uv", mode="no-uv")
        assert rc != 0, out
        machine.fail("test -f /root/no-uv")

    with subtest("a signature over a different command is refused"):
        rc, out, req = approved_run("sudo -n true", mode="other")
        assert rc != 0, out

    with subtest("environment can't be smuggled in"):
        out = machine.fail(as_user("claude", "sudo -n LD_PRELOAD=/tmp/x.so true 2>&1"))
        machine.fail(as_user("claude", "sudo -n -E true"))

    with subtest("sudoedit, shells and interpreters are refused before any request"):
        for cmd in ["sudoedit -n /etc/hosts", "sudo -n -s", "sudo -n -i", "sudo -n bash -c id",
                    "sudo -n env id", "sudo -n find / -maxdepth 0 -exec id {} +", "sudo -n python3 -c 1",
                    "sudo -n less /etc/hosts", "sudo -n git status", "sudo -n newgrp", "sudo -n setsid id",
                    "sudo -n passwd", "sudo -n nixos-rebuild switch", "sudo -n visudo"]:
            out = machine.fail(as_user("claude", f"{cmd} 2>&1"))
            assert "waiting" not in out, (cmd, out)

    with subtest("a program the agent owns or links is refused"):
        machine.succeed(as_user("claude", "cp /run/current-system/sw/bin/true ~/t && ln -s /run/current-system/sw/bin/true ~/l"))
        for cmd in ["sudo -n /home/claude/t", "sudo -n /home/claude/l"]:
            out = machine.fail(as_user("claude", f"{cmd} 2>&1"))
            assert "waiting" not in out, (cmd, out)

    with subtest("the sudoers rule is the last match and has NOSETENV"):
        out = machine.succeed(as_user("claude", "sudo -n -l"))
        assert "NOSETENV" in out, out
        assert "!pam_session" in out and "umask_override" in out, out

    with subtest("a deploy shows what it changes in sudo security, and unsigned systems are refused"):
        current = machine.succeed("readlink -f /run/current-system").strip()
        other = machine.succeed("readlink -f /run/current-system/specialisation/other").strip()

        rc, out, req = approved_run(f"sudo -n remote-sudo-approve-switch {other}")
        assert req["change"]["system"] == other, req
        changed = dict(req["change"]["diffs"])
        assert changed["etc/remote-sudo-approve/allowed"] == "+id", changed
        assert "+user mallory" in changed["etc/remote-sudo-approve/summary"], changed
        assert req["warnings"] == [], req
        # Approved, but the system isn't signed by the deploy key.
        assert rc != 0 and "isn't signed" in out, out
        assert machine.succeed("readlink -f /run/current-system").strip() == current

        rc, out, req = approved_run(f"sudo -n remote-sudo-approve-switch {current}")
        assert req["change"]["diffs"] == [], req

        machine.succeed(f"remote-sudo-approve-diff {current}")
        assert "+id" in machine.fail(f"remote-sudo-approve-diff {other}")
        # Not a system path, or more arguments: refused before any request.
        for cmd in ["sudo -n remote-sudo-approve-switch /tmp", f"sudo -n remote-sudo-approve-switch {other} x", "sudo -n remote-sudo-approve-switch"]:
            assert "waiting" not in machine.fail(as_user("claude", f"{cmd} 2>&1"))

    with subtest("starving sudo of resources never runs a command unapproved"):
        for limit in ["ulimit -n 3", "ulimit -n 4", "ulimit -n 6", "ulimit -n 8", "ulimit -v 8000",
                      "ulimit -v 20000", "ulimit -u 1", "ulimit -f 0", "ulimit -s 16"]:
            machine.execute(as_user("claude", f"{limit}; timeout 30 sudo -n touch /root/starved"))
            machine.fail("test -e /root/starved")

    with subtest("a broken verifier denies claude and leaves alice alone"):
        machine.succeed("mount -t tmpfs none /etc/remote-sudo-approve")
        machine.fail(as_user("claude", "timeout 20 sudo -n true"))
        machine.succeed(as_user("alice", "sudo -n true"))
        machine.succeed("umount /etc/remote-sudo-approve")
  '';
}
