# `kixSrc` is applied by kix's own flake via `importApply`, so this module can
# reach kix's source without dragging in kix's nixpkgs.
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

  relativePath = types.addCheck types.str (lib.hasPrefix "./") // {
    description = "path string relative to the flake root, starting with ./";
  };

  # The same directory seen from the two sides: a store path for the NixOS
  # module, which reads the sealed .age files, and a working-tree path for the
  # commands that write them.
  inStore = rel: "${self}/${lib.removePrefix "./" rel}";

  # Where the flake sits inside its own source: empty at the top of a
  # repository, "sub" for a flake in a subdirectory of one. The paths seal
  # resolves are relative to the flake root, and git only knows the repository
  # root, so without this the two disagree for anything but the common case.
  flakeSubdir =
    let
      root = "${self.sourceInfo.outPath}";
    in
    if "${self}" == root then "" else lib.removePrefix "${root}/" "${self}";

  # Forces evaluation of every nixosConfiguration in `nodes`; narrow
  # `flake.kix.nodes` if that gets expensive.
  kixNodes = lib.filter (v: v.config ? kix) (lib.attrValues cfg.nodes);

  # A path written as `inputs.self + "/secrets/x"` or `./secrets/x` has to be
  # committed for the flake to see it, and travels into /nix/store world
  # readable with the rest of the flake source. That is harmless for a plugin
  # identity, which only names a slot on a hardware token, and catastrophic for
  # a bare age key, which is the one thing that decrypts every secret.
  identityIsPlaintextKeyInStore =
    p:
    lib.hasPrefix builtins.storeDir p
    && builtins.pathExists p
    && lib.any (lib.hasPrefix "AGE-SECRET-KEY-") (lib.splitString "\n" (builtins.readFile p));

  identity =
    if cfg.identity == null then
      throw "kix: `flake.kix.identity` is unset; set it to the age identity used to decrypt your secrets."
    else if identityIsPlaintextKeyInStore "${cfg.identity}" then
      throw ''
        kix: `flake.kix.identity` points at a bare age secret key inside the flake source.
        It is therefore committed to your repository and world readable in /nix/store,
        and it decrypts every secret kix manages.

        Point the option at an absolute path outside the flake instead, as a string so
        Nix does not copy it into the store:

            flake.kix.identity = "/home/you/.config/age/kix-identity.txt";

        A plugin identity (AGE-PLUGIN-*) is safe to keep in the flake: it names a slot
        on a hardware token rather than holding key material.
      ''
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
              example = "/home/you/.config/age/kix-identity.txt";
              description = "Age identity used to decrypt the source .age files.";
            };
            cache = mkOption {
              type = relativePath;
              default = "./secrets/cache";
              description = ''
                Where `seal` writes the per-host sealed secrets, relative to the
                flake root. This directory must be committed: the NixOS module
                locates it inside the flake source in the store.
              '';
            };
            secretsDir = mkOption {
              type = relativePath;
              default = "./secrets";
              description = ''
                Directory containing the source .age files, relative to the flake
                root. Relative rather than a store path because `edit` and `seal`
                write to it in your working tree.
              '';
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
                  kix.internal.cacheRoot = inStore cfg.cache;
                  kix.internal.secretsDir = inStore cfg.secretsDir;
                  kix.internal.flakeRoot = "${self}";
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

      repoManifest = {
        inherit identity;
        inherit (cfg) cache secretsDir extraRecipients;
      };

      sealManifest = pkgs.writeText "kix-manifest.json" (
        builtins.toJSON (
          repoManifest // { profiles = map (n: n.config.kix.internal.profileFile) kixNodes; }
        )
      );

      # Without `profiles`, so writing a secret never evaluates a single host.
      # A secret you have declared but not yet created would otherwise fail the
      # eval of the very command that creates it.
      editManifest = pkgs.writeText "kix-manifest.json" (builtins.toJSON repoManifest);

      # `flake.kix.cache` is relative to the flake root, not to $PWD.
      seal = pkgs.writeShellApplication {
        name = "kix-seal";
        runtimeInputs = [ pkgs.git ];
        text = ''
          root="$(git rev-parse --show-toplevel)/${flakeSubdir}"
          # Being in a git repository is not the same as being in this flake's
          # repository, and seal writes to the paths it finds there.
          if [ ! -e "$root/flake.nix" ]; then
            echo "kix: no flake.nix in $root" >&2
            echo "kix: seal resolves its paths against the flake it was built from" >&2
            exit 1
          fi
          cd "$root"
          exec ${lib.getExe kix} seal --manifest ${sealManifest} "$@"
        '';
      };

      # No cd, unlike seal: edit's file argument stays relative to the caller.
      edit = pkgs.writeShellApplication {
        name = "kix-edit";
        text = ''
          exec ${lib.getExe kix} edit --manifest ${editManifest} "$@"
        '';
      };
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
