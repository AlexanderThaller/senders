{
  description = "senders - end-to-end encrypted file sharing (command-line client)";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
      cargoToml = lib.importTOML ./Cargo.toml;
    in
    {
      packages = forAllSystems (pkgs: {
        senders-cli = pkgs.rustPlatform.buildRustPackage {
          pname = "senders-cli";
          inherit (cargoToml.workspace.package) version;

          # Only the native workspace. Every member has to be present for cargo
          # to load the workspace, so the server comes along even though only
          # the CLI is built; crates/web is a separate workspace and is left out.
          src = lib.fileset.toSource {
            root = ./.;
            fileset = lib.fileset.unions [
              ./Cargo.toml
              ./Cargo.lock
              ./crates/cli
              ./crates/proto
              ./crates/server
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;

          cargoBuildFlags = [ "--package=senders-cli" ];
          cargoTestFlags = [ "--package=senders-cli" ];

          # .cargo/config.toml (deliberately not in the source set above) pins
          # target-cpu=x86-64-v3 for the server image. A package installed
          # through nixpkgs has to run on whatever x86-64 machine it lands on
          # and be substitutable from a binary cache, so it is built for the
          # baseline instead.

          meta = {
            description = "Command-line client for a senders server";
            homepage = cargoToml.workspace.package.repository;
            license = lib.licenses.mit;
            mainProgram = "senders-cli";
          };
        };
        default = self.packages.${pkgs.stdenv.hostPlatform.system}.senders-cli;
      });

      overlays.default = final: _prev: {
        senders-cli = self.packages.${final.stdenv.hostPlatform.system}.senders-cli;
      };

      apps = forAllSystems (pkgs: {
        default = {
          type = "app";
          program = lib.getExe self.packages.${pkgs.stdenv.hostPlatform.system}.senders-cli;
        };
      });

      formatter = forAllSystems (pkgs: pkgs.nixfmt);
    };
}
