{
  pkgs,
  package,
  identity,
  extraRecipients,
  ...
}:
let
  inherit (pkgs) writeShellScriptBin;
  inherit (pkgs.lib)
    concatStringsSep
    makeBinPath
    getExe
    ;

  recipientsArg = concatStringsSep " " (map (n: "--recipient ${n}") extraRecipients);

in
writeShellScriptBin "edit-secret" ''
  ${getExe package} edit --identity ${identity} ${recipientsArg} $1
''
