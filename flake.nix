{
  description = "kix — secret manager for NixOS";

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } (
      { flake-parts-lib, ... }:
      let
        inherit (flake-parts-lib) importApply;
        flakeModules.default = importApply ./flake-module.nix { kixSrc = ./.; };
      in
      {
        imports = [ inputs.treefmt-nix.flakeModule ];

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
          {
            packages = rec {
              default = pkgs.callPackage ./package.nix { };
              kix = default;
            };

            apps.default = {
              type = "app";
              program = lib.getExe self'.packages.default;
            };

            devShells.default = pkgs.mkShell {
              packages = with pkgs; [
                go
                golangci-lint
                gotestsum
              ];
            };

            treefmt = {
              projectRootFile = "flake.nix";
              programs.nixfmt.enable = true;
              programs.gofmt.enable = true;
            };

            # `go test ./...` runs as part of the package build (doCheck), so
            # this covers the integration side the unit tests cannot reach.
            checks.nixos = pkgs.testers.runNixOSTest ./tests/deploy.nix;
          };

        flake = {
          inherit flakeModules;

          overlays.default = final: _prev: {
            kix = final.callPackage ./package.nix { };
          };

          # Usable standalone: `kix.package` defaults to a callPackage against
          # whatever nixpkgs the importing configuration already uses.
          nixosModules = rec {
            default = ./module;
            kix = default;
          };
        };
      }
    );
}
