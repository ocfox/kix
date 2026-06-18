kixFlake:
{
  lib,
  self,
  config,
  flake-parts-lib,
  ...
}:
let
  inherit (lib) mkOption types;
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
            };
            cache = mkOption {
              type = types.addCheck types.str (s: (builtins.substring 0 1 s) == ".") // {
                description = "path string relative to flake root";
              };
              default = "./secrets/cache";
              defaultText = lib.literalExpression "./secrets/cache";
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
            };
            app = mkOption {
              type = types.lazyAttrsOf (types.lazyAttrsOf types.package);
              readOnly = true;
              default = lib.mapAttrs (
                system: config':
                let
                  pkgs = config'.kix.pkgs;
                  package = kixFlake.packages.${system}.default;
                  inherit (config.flake.kix) nodes identity extraRecipients cache;

                  seal =
                    let
                      profilesArgs = lib.concatStringsSep " " (
                        map (
                          v:
                          "--profile "
                          + (pkgs.writeTextFile {
                            name = "kix-material";
                            text = builtins.toJSON {
                              inherit (v.config.kix) beforeUserborn secrets settings;
                            };
                          })
                        ) (lib.filter (v: v.config ? kix) (lib.attrValues nodes))
                      );
                    in
                    pkgs.writeShellScriptBin "seal" ''
                      ${lib.getExe package} ${profilesArgs} seal --identity ${identity} --cache ${cache}
                    '';

                  edit =
                    let
                      recipientsArg = lib.concatStringsSep " " (
                        map (n: "--recipient ${n}") extraRecipients
                      );
                    in
                    pkgs.writeShellScriptBin "edit-secret" ''
                      ${lib.getExe package} edit --identity ${identity} ${recipientsArg} $1
                    '';
                in
                { inherit seal edit; }
              ) config.allSystems;
            };
          };
        });
        default = { };
      };
    };

    perSystem = flake-parts-lib.mkPerSystemOption (
      { pkgs, ... }:
      {
        options.kix.pkgs = mkOption {
          type = types.unspecified;
          default = pkgs;
        };
      }
    );
  };

  _file = __curPos.file;
}
