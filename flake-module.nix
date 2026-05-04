kixFlake:
{
  lib,
  self,
  config,
  flake-parts-lib,
  ...
}:
let
  inherit (lib)
    mkOption
    types
    ;
in
{
  options = {
    flake = flake-parts-lib.mkSubmoduleOptions {
      kix = mkOption {
        type = types.submodule (submod: {
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
            defaultSecretDirectory = mkOption {
              type = types.addCheck types.str (s: (builtins.substring 0 1 s) == ".") // {
                description = "path string relative to flake root";
              };
              default = "./secrets";
              defaultText = lib.literalExpression "./secrets";
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
                lib.genAttrs
                  [
                    "seal"
                    "edit"
                  ]
                  (
                    app:
                    import ./apps/${app}.nix {
                      inherit (config.flake.kix)
                        nodes
                        identity
                        extraRecipients
                        cache
                        ;
                      inherit lib;
                      pkgs = config'.kix.pkgs;
                      package = kixFlake.packages.${system}.default;
                    }
                  )
              ) config.allSystems;
            };
          };
        });
        default = { };
      };
    };

    perSystem = flake-parts-lib.mkPerSystemOption (
      {
        pkgs,
        lib,
        ...
      }:
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
