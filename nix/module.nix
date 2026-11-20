# NixOS module: every sudo command of the gated users needs a passkey
# approval (DESIGN.md). Root and the ungated users are unaffected.
self:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.security.remoteSudoApprove;
  pkg = cfg.package;
  # No /run/wrappers/bin: setuid wrappers aren't in the trusted set, and
  # root doesn't need them (`mount` resolves to the real one).
  securePath = "/run/current-system/sw/bin";
  agentEnv = "/etc/remote-sudo-approve/agent.env";
  pluginLine = "Plugin remote_sudo_approve ${pkg}/lib/libremote_sudo_approve_plugin.so";

  # Pagers and editors off for gated users: both can run commands.
  envFile = {
    PAGER = "cat";
    SYSTEMD_PAGER = "cat";
    GIT_PAGER = "cat";
    MANPAGER = "cat";
    LESSSECURE = "1";
    EDITOR = "/run/current-system/sw/bin/false";
    VISUAL = "/run/current-system/sw/bin/false";
    SYSTEMD_EDITOR = "/run/current-system/sw/bin/false";
  };

  # What the command's environment may contain, by name and value: what
  # sudoers produces for a gated user with env_reset, env_keep TERM/LANG and
  # the env_file above. Anything else is refused. PAM adds nothing: the
  # gated users' sudo opens no PAM session (see the Defaults below).
  rootShell = config.users.users.root.shell;
  envRules =
    lib.mapAttrs (_: v: { exact = v; }) envFile
    // {
      HOME.exact = "/root";
      USER.exact = "root";
      LOGNAME.exact = "root";
      MAIL.one_of = [
        "/var/mail/root"
        "/var/spool/mail/root"
      ];
      SHELL.one_of = [
        "/run/current-system/sw/bin/bash"
        (if lib.isDerivation rootShell then lib.getExe rootShell else toString rootShell)
      ];
      PATH.exact = securePath;
      TERM = "term";
      LANG = "locale";
      SUDO_USER.one_of = cfg.gatedUsers;
      SUDO_UID.one_of = map (u: toString (uidOf u)) cfg.gatedUsers;
      SUDO_GID = "printable_ascii";
      SUDO_HOME = "printable_ascii";
      SUDO_COMMAND = "printable_ascii";
      SUDO_TTY = "tty";
    };

  # Settings that would otherwise be inherited from the invoking process:
  # pinned in sudoers, and required by the verifier with exactly these
  # values (as sudoers reports them in command_info).
  rlimits = {
    as = "infinity";
    core = "0";
    cpu = "infinity";
    data = "infinity";
    fsize = "infinity";
    locks = "infinity";
    memlock = "infinity";
    nofile = "1024,524288";
    nproc = "infinity";
    rss = "infinity";
    stack = "8388608,infinity";
  };
  requiredInfo = lib.mapAttrs' (k: v: lib.nameValuePair "rlimit_${k}" v) rlimits // {
    umask = "022";
    umask_override = "true";
  };

  uidOf = u: config.users.users.${u}.uid;

  # Every group a user is in: primary, extraGroups, and groups' members.
  groupsOf =
    u:
    lib.unique (
      [ config.users.users.${u}.group ]
      ++ config.users.users.${u}.extraGroups
      ++ lib.attrNames (lib.filterAttrs (_: g: lib.elem u g.members) config.users.groups)
    );
  wheelUsers = lib.filter (u: lib.elem "wheel" (groupsOf u)) (lib.attrNames config.users.users);
  trustedEntries =
    (config.nix.settings.trusted-users or [ ]) ++ (config.nix.settings.extra-trusted-users or [ ]);
  nixTrusts =
    u:
    lib.any (
      e: e == "*" || e == u || (lib.hasPrefix "@" e && lib.elem (lib.removePrefix "@" e) (groupsOf u))
    ) trustedEntries;

  # The real files behind the installed programs: the only things a gated
  # user may ask to run as root. Not their dependencies.
  programs = pkgs.runCommand "remote-sudo-approve-programs" { } ''
    for d in ${config.system.path}/bin ${config.system.path}/sbin; do
      [ -d "$d" ] || continue
      for f in "$d"/*; do
        [ -f "$f" ] && [ -x "$f" ] && realpath "$f"
      done
    done | sort -u > $out
    [ -s $out ]
  '';
  # name<TAB>real path, for the allowlist.
  allowed = pkgs.runCommand "remote-sudo-approve-allowed" { } ''
    : > $out
    for name in ${lib.escapeShellArgs (cfg.allowedPrograms ++ lib.optional deployOn "remote-sudo-approve-switch")}; do
      f=${config.system.path}/bin/$name
      [ -x "$f" ] || { echo "remote-sudo-approve: allowedPrograms: $name is not an installed program" >&2; exit 1; }
      printf '%s\t%s\n' "$name" "$(realpath "$f")" >> $out
    done
  '';

  # The deploy command: switch to a system the builder signed. The verifier
  # recognises it and puts the security diff into the request.
  switch = pkgs.writeShellApplication {
    name = "remote-sudo-approve-switch";
    runtimeInputs = [ config.nix.package ];
    text = ''
      [ $# -eq 1 ] || { echo "usage: remote-sudo-approve-switch /nix/store/<system>" >&2; exit 2; }
      sys=$1
      [[ $sys =~ ^/nix/store/[a-z0-9]{32}-[A-Za-z0-9._+-]+$ ]] || { echo "not a system store path" >&2; exit 2; }
      [ -x "$sys/bin/switch-to-configuration" ] || { echo "$sys isn't a NixOS system here" >&2; exit 2; }
      # Only systems signed by the builder, not ones built on this machine:
      # with --sigs-needed a locally built ("ultimate") path doesn't pass
      # without a signature. Never add --no-trust: it turns this check off
      # (the VM test switched to an unsigned system with it).
      nix --extra-experimental-features nix-command store verify --no-contents \
        --sigs-needed 1 --trusted-public-keys ${lib.escapeShellArg (lib.concatStringsSep " " cfg.deploy.trustedPublicKeys)} "$sys" \
        || { echo "$sys isn't signed by a deploy key" >&2; exit 1; }
      nix-env -p /nix/var/nix/profiles/system --set "$sys"
      exec "$sys/bin/switch-to-configuration" switch
    '';
  };
  switchPath = "${switch}/bin/remote-sudo-approve-switch";
  deployOn = cfg.deploy.trustedPublicKeys != [ ];

  # Who can get root, as configured: compared between systems by the deploy
  # command and the automatic updates (verify/src/change.rs).
  summary = lib.concatStringsSep "\n" (
    [
      "gated: ${toString (lib.sort lib.lessThan cfg.gatedUsers)}"
      "ungated: ${toString (lib.sort lib.lessThan cfg.ungatedUsers)}"
      "wheel needs password: ${lib.boolToString config.security.sudo.wheelNeedsPassword}"
      "nix trusted-users: ${toString (lib.sort lib.lessThan trustedEntries)}"
      "deploy keys: ${toString cfg.deploy.trustedPublicKeys}"
      "setuid/capability wrappers: ${toString (lib.attrNames config.security.wrappers)}"
    ]
    ++ lib.mapAttrsToList (
      n: u: "user ${n}: uid=${toString u.uid} groups=${toString (lib.sort lib.lessThan (groupsOf n))} shell=${
        if lib.isDerivation u.shell then u.shell.pname or u.shell.name else toString u.shell
      } password=${lib.boolToString (u.hashedPassword != null || u.hashedPasswordFile != null || u.password != null || u.initialPassword != null || u.initialHashedPassword != null)}"
    ) (lib.filterAttrs (_: u: u.isNormalUser || u.uid == 0 || lib.elem "wheel" (u.extraGroups)) config.users.users)
  ) + "\n";

  verifierConfig = {
    host = cfg.host;
    rp_id = cfg.rpId;
    origin = cfg.origin;
    relay = cfg.relay;
    token_file = cfg.tokenFile;
    credentials = map (c: {
      inherit (c) name id;
      public_key = c.publicKey;
      device_bound = c.deviceBound;
    }) cfg.credentials;
    trusted.programs_file = "/etc/remote-sudo-approve/programs";
    allowed_file = "/etc/remote-sudo-approve/allowed";
    required_info = requiredInfo;
    env = envRules;
    expiry_seconds = cfg.expirySeconds;
    switch_program = if deployOn then switchPath else null;
  };
in
{
  options.security.remoteSudoApprove = {
    enable = lib.mkEnableOption "passkey approval of every sudo command of the gated users";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
    };
    gatedUsers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "claude" ];
      description = "Users who may sudo, but only with passkey approval of each command.";
    };
    ungatedUsers = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = "Users whose sudo is unaffected (root always is). Need fixed uids. Every wheel user must be listed.";
    };
    allowedPrograms = lib.mkOption {
      type = lib.types.listOf (lib.types.strMatching "[A-Za-z0-9._+-]+");
      default = [ ];
      example = [
        "systemctl"
        "journalctl"
        "reboot"
      ];
      description = ''
        The allowlist: installed programs (names in /run/current-system/sw/bin)
        that gated users request routinely. Any other installed program can
        still be requested, but the approval page shows a red warning.
      '';
    };
    deploy.trustedPublicKeys = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Nix signing keys (name:base64) of the builder. If set, gated users get
        `sudo remote-sudo-approve-switch <system>`: it switches only to a system
        signed by one of these keys, and the approval shows what the switch
        changes in the files that decide who gets root.
      '';
    };
    allowedGroups = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ "users" ];
      description = "Groups a gated user may be in. Anything else fails the build.";
    };
    host = lib.mkOption {
      type = lib.types.str;
      default = config.networking.hostName;
    };
    origin = lib.mkOption {
      type = lib.types.strMatching "https?://[A-Za-z0-9.-]+(:[0-9]+)?";
      example = "https://approve.example.ts.net";
      description = "Where the remote-sudo-approve server is reached: the approval page's origin, and the relay API.";
    };
    rpId = lib.mkOption {
      type = lib.types.str;
      default = lib.head (lib.splitString ":" (lib.last (lib.splitString "://" cfg.origin)));
      defaultText = "the origin's host name";
      description = "The passkey's RP ID.";
    };
    relay = lib.mkOption {
      type = lib.types.str;
      default = cfg.origin;
      defaultText = "the origin";
      description = "The relay API's base URL, if it isn't at the origin.";
    };
    insecureRelay = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = "Allow an http:// relay (tests only: the host token travels in clear).";
    };
    tokenFile = lib.mkOption {
      type = lib.types.str;
      description = "This host's relay token, readable by the remote-sudo-approve account only (e.g. a sops secret).";
    };
    expirySeconds = lib.mkOption {
      # The plugin stops waiting at 125 s.
      type = lib.types.ints.between 10 120;
      default = 120;
    };
    credentials = lib.mkOption {
      description = "Passkeys that may approve (from the registration page).";
      type = lib.types.nonEmptyListOf (
        lib.types.submodule {
          options = {
            name = lib.mkOption { type = lib.types.str; };
            id = lib.mkOption { type = lib.types.str; };
            publicKey = lib.mkOption { type = lib.types.str; };
            deviceBound = lib.mkOption {
              type = lib.types.bool;
              default = false;
            };
          };
        }
      );
    };
  };

  config = lib.mkIf cfg.enable {
    assertions =
      [
        {
          assertion = !(config.security.sudo-rs.enable or false);
          message = "remote-sudo-approve: sudo-rs has no plugins, so the gated users' rule would be plain root.";
        }
        {
          assertion = config.security.sudo.enable;
          message = "remote-sudo-approve needs security.sudo.";
        }
        {
          assertion = !config.security.sudo.execWheelOnly;
          message = "remote-sudo-approve: execWheelOnly would stop the gated users running sudo at all.";
        }
        {
          # The gated users' rule is NOPASSWD: without the plugin it is plain root.
          assertion =
            let
              t = config.environment.etc."sudo.conf".text or null;
            in
            t != null && lib.hasInfix (builtins.unsafeDiscardStringContext pluginLine) (builtins.unsafeDiscardStringContext t);
          message = "remote-sudo-approve: /etc/sudo.conf must load the approval plugin (something overrode it).";
        }
        {
          assertion = !(config.security.doas.enable or false);
          message = "remote-sudo-approve: security.doas is a second way to root that isn't gated.";
        }
        {
          assertion = lib.length cfg.ungatedUsers <= 7;
          message = "remote-sudo-approve: at most 7 ungated users (the plugin reads 8 uids including root).";
        }
        {
          assertion = lib.all (u: lib.elem u cfg.ungatedUsers || lib.elem u cfg.gatedUsers) wheelUsers;
          message = "remote-sudo-approve: every wheel user must be in ungatedUsers, or their sudo is denied: ${toString wheelUsers}";
        }
        {
          assertion = cfg.insecureRelay || lib.hasPrefix "https://" cfg.relay;
          message = "remote-sudo-approve: the relay must be https.";
        }
        {
          assertion = lib.intersectLists cfg.gatedUsers cfg.ungatedUsers == [ ];
          message = "remote-sudo-approve: a user can't be both gated and ungated.";
        }
      ]
      ++ lib.concatMap (u: [
        {
          assertion = config.users.users ? ${u} && uidOf u != null && uidOf u != 0;
          message = "remote-sudo-approve: gated user ${u} must exist with a fixed, non-zero uid.";
        }
        {
          assertion = lib.subtractLists cfg.allowedGroups (groupsOf u) == [ ];
          message = "remote-sudo-approve: gated user ${u} is in groups outside allowedGroups: ${
            toString (lib.subtractLists cfg.allowedGroups (groupsOf u))
          }";
        }
        {
          assertion = !(nixTrusts u);
          message = "remote-sudo-approve: gated user ${u} is a Nix trusted user (root-equivalent).";
        }
        {
          assertion =
            !(lib.any (
              i: i == "unix-user:${u}" || lib.any (g: i == "unix-group:${g}") (groupsOf u)
            ) (config.security.polkit.adminIdentities or [ ]));
          message = "remote-sudo-approve: gated user ${u} is a polkit administrator.";
        }
      ]) cfg.gatedUsers
      ++ map (u: {
        assertion = config.users.users ? ${u} && uidOf u != null;
        message = "remote-sudo-approve: ungated user ${u} must exist with a fixed uid.";
      }) cfg.ungatedUsers;

    users.users.remote-sudo-approve = {
      isSystemUser = true;
      group = "remote-sudo-approve";
      description = "remote-sudo-approve verifier";
    };
    users.groups.remote-sudo-approve = { };

    environment.etc."remote-sudo-approve/config.json" = {
      text = builtins.toJSON verifierConfig;
      mode = "0444";
    };
    environment.etc."remote-sudo-approve/agent.env" = {
      text = lib.concatStrings (lib.mapAttrsToList (k: v: "${k}=${v}\n") envFile);
      mode = "0444";
    };
    environment.etc."remote-sudo-approve/summary".text = summary;
    environment.systemPackages = lib.optional deployOn switch ++ [ pkg ];
    environment.etc."remote-sudo-approve/programs".source = programs;
    environment.etc."remote-sudo-approve/allowed".source = allowed;

    # sudo.conf: the usual sudoers plugins plus the approval plugin.
    environment.etc."sudo.conf".text = ''
      Plugin sudoers_policy sudoers.so
      Plugin sudoers_io sudoers.so
      Plugin sudoers_audit sudoers.so
      ${pluginLine} verifier=${lib.getExe pkg} run_as=remote-sudo-approve ungated_uids=${
        lib.concatMapStringsSep "," toString ([ 0 ] ++ map uidOf cfg.ungatedUsers)
      }
    '';

    # Last in the file, so it's the last match for these users (NixOS puts
    # extraConfig after every rule, including %wheel).
    #  - NOSETENV: SETENV is implied for an ALL rule otherwise.
    #  - no PAM session or setcred: pam_env would add variables after the
    #    approval, so the environment wouldn't be the one that was signed.
    #  - umask and every rlimit pinned: sudo would otherwise restore the
    #    invoking process's.
    security.sudo.extraConfig = lib.mkAfter (
      lib.concatMapStrings (u: ''
        Defaults:${u} env_reset, env_keep = "TERM LANG", runcwd = /, env_file = ${agentEnv}
        Defaults:${u} secure_path = "${securePath}"
        Defaults:${u} !pam_session, !pam_setcred
        Defaults:${u} umask = 0022, umask_override
        Defaults:${u} ${
          lib.concatStringsSep ", " (lib.mapAttrsToList (k: v: ''rlimit_${k} = "${v}"'') rlimits)
        }
        ${u} ALL=(root) NOPASSWD: NOSETENV: ALL, !sudoedit
      '') cfg.gatedUsers
    );
  };
}
