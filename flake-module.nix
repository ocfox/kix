# flake-parts module, imported by consumers as `inputs.kix.flakeModules.default`.
#
# `kixSrc` is applied by kix's own flake via `importApply`, so this module can
# reach kix's source (package.nix, module/) without dragging in kix's nixpkgs.
{ kixSrc }:
{
  lib,
  self,
  config,
  flake-parts-lib,
  ...
}:
let
  inherit (lib) mkOption types;

  cfg = config.flake.kix;

  # Nodes that actually use kix. This forces evaluation of every
  # nixosConfiguration in `nodes`, which is inherent: sealing needs every host's
  # secrets. Narrow `flake.kix.nodes` if that becomes expensive.
  kixNodes = lib.filter (v: v.config ? kix) (lib.attrValues cfg.nodes);

  identity =
    if cfg.identity == null then
      throw "kix: `flake.kix.identity` is unset; set it to the age identity used to decrypt your secrets."
    else
      "${cfg.identity}";
in
{
  options = {
    flake = flake-parts-lib.mkSubmoduleOptions {
      kix = mkOption {
        type = types.submodule (_: {
          options = {
            nodes = mkOption {
              type = types.lazyAttrsOf types.unspecified;
              default = self.nixosConfigurations;
              defaultText = lib.literalExpression "self.nixosConfigurations";
            };
            identity = mkOption {
              type = with types; nullOr path;
              default = null;
              example = "./identity.txt";
              description = "Age identity used to decrypt the source .age files.";
            };
            cache = mkOption {
              type = types.addCheck types.str (s: (builtins.substring 0 1 s) == ".") // {
                description = "path string relative to flake root";
              };
              default = "./secrets/cache";
              defaultText = lib.literalExpression "./secrets/cache";
              description = ''
                Where `seal` writes the per-host sealed secrets, relative to the
                flake root. This directory must be committed: the NixOS module
                locates it inside the flake source in the store.
              '';
            };
            secretsDir = mkOption {
              type = types.path;
              default = self + "/secrets";
              defaultText = lib.literalExpression ''inputs.self + "/secrets"'';
              description = "Directory containing .age secret files.";
            };
            extraRecipients = mkOption {
              type = with types; listOf str;
              default = [ ];
              example = [ "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq" ];
              description = ''
                Additional recipients that `edit` encrypts source .age files to,
                on top of the recipient derived from {option}`flake.kix.identity`.
              '';
            };

            nixosModule = mkOption {
              type = types.unspecified;
              readOnly = true;
              description = ''
                The kix NixOS module, pre-wired with the settings above. Import
                this instead of `inputs.kix.nixosModules.default` so the NixOS
                module never has to reach back into flake outputs.
              '';
              default =
                { ... }:
                {
                  imports = [ (kixSrc + "/module") ];
                  kix.cacheRoot = "${self}/${lib.removePrefix "./" cfg.cache}";
                  kix.secretsDir = cfg.secretsDir;
                };
            };
          };
        });
        default = { };
      };
    };
  };

  config.perSystem =
    { pkgs, ... }:
    let
      kix = pkgs.callPackage (kixSrc + "/package.nix") { };

      manifest = pkgs.writeText "kix-manifest.json" (
        builtins.toJSON {
          inherit identity;
          inherit (cfg) cache extraRecipients;
          profiles = map (n: n.config.kix.profileFile) kixNodes;
        }
      );

      # `flake.kix.cache` is relative to the flake root, so anchor the working
      # directory there rather than relying on where the user happened to run
      # `nix run` from.
      wrapper =
        name: subcommand:
        pkgs.writeShellApplication {
          inherit name;
          runtimeInputs = [ pkgs.git ];
          text = ''
            cd "$(git rev-parse --show-toplevel)"
            exec ${lib.getExe kix} ${subcommand} --manifest ${manifest} "$@"
          '';
        };

      seal = wrapper "kix-seal" "seal";
      edit = wrapper "kix-edit" "edit";
    in
    {
      packages = {
        kix-seal = seal;
        kix-edit = edit;
      };

      apps = {
        kix-seal = {
          type = "app";
          program = lib.getExe seal;
        };
        kix-edit = {
          type = "app";
          program = lib.getExe edit;
        };
      };
    };

  _file = __curPos.file;
}
