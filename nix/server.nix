# NixOS module: run the remote-sudo-approve server (approval page and relay API) as
# a service. Put an HTTPS reverse proxy or a Tailscale serve in front of it:
# it listens on plain HTTP on localhost.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.remote-sudo-approve-server;
in
{
  options.services.remote-sudo-approve-server = {
    enable = lib.mkEnableOption "the remote-sudo-approve server";
    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.server;
    };
    origin = lib.mkOption {
      type = lib.types.strMatching "https://[A-Za-z0-9.-]+(:[0-9]+)?";
      example = "https://approve.example.ts.net";
      description = "The one public HTTPS origin the server is reached at. The passkey is bound to its host name.";
    };
    port = lib.mkOption {
      type = lib.types.port;
      default = 8377;
    };
    environmentFile = lib.mkOption {
      type = lib.types.path;
      description = "File with VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY and SETUP_TOKEN_SHA256 (from `remote-sudo-approve-setup init`).";
    };
    hostTokensFile = lib.mkOption {
      type = lib.types.path;
      description = "JSON object of machine name to token hash (lines from `remote-sudo-approve-setup host <name>`, merged).";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.systemPackages = [ cfg.package ];
    systemd.services.remote-sudo-approve-server = {
      description = "remote-sudo-approve server (approval page and relay)";
      wantedBy = [ "multi-user.target" ];
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      environment = {
        PORT = toString cfg.port;
        ORIGIN = cfg.origin;
        SUBSCRIPTIONS_FILE = "/var/lib/remote-sudo-approve-server/subscriptions.json";
        HOST_TOKENS_FILE = "%d/tokens";
      };
      serviceConfig = {
        ExecStart = lib.getExe cfg.package;
        EnvironmentFile = cfg.environmentFile;
        LoadCredential = "tokens:${cfg.hostTokensFile}";
        DynamicUser = true;
        StateDirectory = "remote-sudo-approve-server";
        Restart = "on-failure";
        # It needs the network and its state directory, nothing else.
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
        ];
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
        ];
        MemoryMax = "256M";
      };
    };
  };
}
