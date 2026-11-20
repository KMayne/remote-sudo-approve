{
  description = "remote-sudo-approve: approve each sudo command of an agent user with a passkey";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAll = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAll (pkgs: {
        # The sudo plugin (lib/libremote_sudo_approve_plugin.so) and the verifier
        # (bin/remote-sudo-approve-verify).
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "remote-sudo-approve";
          version = "0.1.0";
          src = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./verify
              ./plugin
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          # The policy tests look at the build machine's /usr/bin; the VM
          # test (checks.vm) covers the real thing.
          doCheck = false;
          postInstall = ''
            mkdir -p $out/lib
            cp target/*/release/libremote_sudo_approve_plugin.so $out/lib/ 2>/dev/null \
              || cp target/release/libremote_sudo_approve_plugin.so $out/lib/
          '';
          meta.mainProgram = "remote-sudo-approve-verify";
        };

        # The static pages: the approval page at /, registration at
        # /register/ (a passkey can only be created from the RP's own origin).
        page = pkgs.runCommand "remote-sudo-approve-page" { } ''
          mkdir -p $out/register
          cp ${./page}/{index.html,app.js,canonical.js,sw.js,style.css,manifest.json} $out/
          cp ${./register}/{index.html,register.js,style.css} $out/register/
        '';

        # The server: the pages and the relay API, one process.
        server = pkgs.buildNpmPackage {
          pname = "remote-sudo-approve-server";
          version = "0.1.0";
          src = ./server;
          npmDepsHash = "sha256-MsZzgn9OWFs1hup+k8aZJoYsfdVAZQkUTxAaysFhTMQ=";
          dontNpmBuild = true;
          installPhase = ''
            mkdir -p $out/lib/server $out/bin
            cp -r server.mjs setup.mjs package.json node_modules $out/lib/server/
            cat > $out/bin/remote-sudo-approve-setup <<EOF
            #!${pkgs.runtimeShell}
            exec ${pkgs.nodejs}/bin/node $out/lib/server/setup.mjs "\$@"
            EOF
            chmod +x $out/bin/remote-sudo-approve-setup
            cat > $out/bin/remote-sudo-approve-server <<EOF
            #!${pkgs.runtimeShell}
            export PAGE_DIR=\''${PAGE_DIR:-${self.packages.${pkgs.system}.page}}
            exec ${pkgs.nodejs}/bin/node $out/lib/server/server.mjs
            EOF
            chmod +x $out/bin/remote-sudo-approve-server
          '';
          meta.mainProgram = "remote-sudo-approve-server";
        };

        # Container image: /bin/remote-sudo-approve-server on port 8080.
        image = pkgs.dockerTools.buildLayeredImage {
          name = "ghcr.io/kmayne/remote-sudo-approve";
          tag = "latest";
          contents = [ self.packages.${pkgs.system}.server ];
          config = {
            Cmd = [ "/bin/remote-sudo-approve-server" ];
            User = "65534:65534";
            Env = [ "PORT=8080" ];
            ExposedPorts."8080/tcp" = { };
          };
        };
      });

      # default: gate sudo on a machine. server: run the approval server.
      nixosModules.default = import ./nix/module.nix self;
      nixosModules.server = import ./nix/server.nix self;

      checks = {
        x86_64-linux.vm = import ./nix/test/vm.nix {
          inherit self;
          pkgs = nixpkgs.legacyPackages.x86_64-linux;
        };
      };
    };
}
