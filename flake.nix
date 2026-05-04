{
  description = "kix — secret manager for NixOS";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    inputs@{
      flake-parts,
      self,
      ...
    }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      {
        flake-parts-lib,
        withSystem,
        ...
      }:
      let
        inherit (flake-parts-lib) importApply;
        flakeModules.default = importApply ./flake-module.nix {
          inherit (self) packages;
          inherit withSystem;
        };
      in
      {
        systems = [
          "x86_64-linux"
          "aarch64-linux"
        ];

        perSystem =
          {
            pkgs,
            lib,
            self',
            ...
          }:
          let
            pname = "kix";
            version = "0-unstable";
          in
          {
            apps.default = {
              type = "app";
              program = lib.getExe self'.packages.default;
            };

            packages = rec {
              default = pkgs.buildGoModule {
                inherit pname version;
                src = ./.;
                vendorHash = "sha256-foF4ECTT2j/DPynBKjbYf8hM8OoCxCRRgWjQ4BCUtcs=";
                meta.mainProgram = "kix";
              };
              kix = default;
            };

            devShells.default = pkgs.mkShell {
              buildInputs = with pkgs; [
                go
                golangci-lint
                gotestsum
              ];
            };
          };

        flake = {
          inherit flakeModules;

          nixosModules = rec {
            default =
              { pkgs, ... }:
              {
                imports = [ ./module ];
                kix.package = withSystem pkgs.stdenv.hostPlatform.system ({ config, ... }: config.packages.kix);
              };
            kix = default;
          };
        };
      }
    );
}
