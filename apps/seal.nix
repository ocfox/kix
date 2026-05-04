{
  nodes,
  lib,
  pkgs,
  package,
  identity,
  cache,
  ...
}:
let
  inherit (pkgs) writeShellScriptBin;
  inherit (lib)
    concatStringsSep
    attrValues
    filter
    getExe
    ;

  profilesArgs = concatStringsSep " " (
    map (
      v:
      "--profile"
      + " "
      + (pkgs.writeTextFile {
        name = "kix-material";
        text = builtins.toJSON {
          inherit (v.config.kix)
            beforeUserborn
            secrets
            settings
            ;
        };
      })
    ) (filter (v: v.config ? kix) (attrValues nodes))
  );

  sealCmd = "${getExe package} ${profilesArgs} seal --identity ${identity} --cache ${cache}";

in
writeShellScriptBin "seal" ''
  ${sealCmd}
''
