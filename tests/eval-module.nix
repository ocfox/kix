# Evaluation-only coverage for flake-module.nix, which nothing else exercises:
# the NixOS tests import ../module directly and hand-write the JSON the binary
# reads, so the wiring between the two sides has until now only ever been
# checked by hand.
#
# Nothing here builds or boots anything. The assertions are all about what Nix
# computes, so a failure is an eval error and the derivation is only there to
# give `nix flake check` something to hold.
{
  lib,
  runCommandLocal,
  system,
  flake-parts,
  nixpkgs,
  kixFlakeModule,
}:
let
  # Stands in for a user's flake source: `flakeRoot` becomes this path, so a
  # secret's working tree location is its name underneath it.
  src = ./fixtures/eval-flake;

  # A store path that is deliberately not under `src`, for the one case seal
  # has no writable copy of.
  outsideFlake = builtins.toFile "outside.age" "not-a-real-age-file\n";

  # `self` is a fixpoint in a real flake; rebuild it here so the module sees
  # the same shape, with `outPath` pointing at the fixture rather than at kix.
  #
  # `sourceInfo.outPath` is the repository the flake was fetched from, which is
  # the same path unless the flake lives in a subdirectory of it. Passing the
  # two separately is how that case gets tested at all.
  evalFlakeIn =
    { outPath, sourceOutPath }:
    module:
    let
      inputs = {
        inherit nixpkgs;
        self = flake // {
          inherit outPath;
          sourceInfo.outPath = sourceOutPath;
          # flake-parts reads this to build its `inputs'` argument.
          inherit inputs;
        };
      };
      flake = flake-parts.lib.mkFlake { inherit inputs; } {
        imports = [
          kixFlakeModule
          module
        ];
        systems = [ system ];
      };
    in
    flake;

  evalFlake = evalFlakeIn {
    outPath = src;
    sourceOutPath = src;
  };

  identity = "/nonexistent/kix-eval-check-identity.txt";

  host =
    { config, ... }:
    {
      flake.kix = { inherit identity; };

      flake.nixosConfigurations.testhost = nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          config.flake.kix.nixosModule
          {
            networking.hostName = "testhost";
            system.stateVersion = "24.05";
            boot.loader.grub.devices = [ "/dev/sda" ];
            fileSystems."/" = {
              device = "/dev/sda1";
              fsType = "ext4";
            };

            kix.hostPubkey = "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqs3290gq";
            kix.secrets = {
              # The default: <secretsDir>/<name>.age.
              inSecretsDir = { };
              # Elsewhere in the flake. Still has a working tree copy.
              elsewhere.file = "${src}/nested/elsewhere.age";
              # Outside the flake entirely, so seal must not claim it can
              # rewrite this one.
              outside.file = outsideFlake;
              # Declared but never created. Legal to evaluate; `check` is what
              # reports it.
              missing = { };
            };
          }
        ];
      };
    };

  hostConfig = (evalFlake host).nixosConfigurations.testhost.config;
  profile = hostConfig.kix.internal.adminProfile;

  # A flake whose nodes explode when looked at, to pin down which commands are
  # allowed to look. Editing a secret must not depend on any host evaluating,
  # or a secret that has been declared but not yet created makes the command
  # that creates it fail.
  poisoned = evalFlake {
    flake.kix = {
      inherit identity;
      nodes.boom = throw "kix: a node was evaluated";
    };
  };
  poisonedPackages = poisoned.packages.${system};

  # The same fixture seen as a flake living in a subdirectory of its
  # repository, which is where the flake root and the git root stop agreeing.
  subdirFlake =
    evalFlakeIn
      {
        sourceOutPath = "${./fixtures}";
        outPath = "${./fixtures}/eval-flake";
      }
      {
        flake.kix = {
          inherit identity;
          nodes = { };
        };
      };

  checks = [
    {
      name = "secretsDir secret maps to its working tree path";
      actual = profile.secrets.inSecretsDir.sourcePath;
      expected = "secrets/inSecretsDir.age";
    }
    {
      name = "secret elsewhere in the flake maps to its working tree path";
      actual = profile.secrets.elsewhere.sourcePath;
      expected = "nested/elsewhere.age";
    }
    {
      name = "secret from outside the flake has no working tree path";
      actual = profile.secrets.outside.sourcePath;
      expected = null;
    }
    {
      name = "file is narrowed to a store path holding only itself";
      actual = "${profile.secrets.inSecretsDir.file}";
      expected = "${builtins.path { path = "${src}/secrets/inSecretsDir.age"; }}";
    }
    {
      # The narrowing above must not be read back out for this: a store path
      # holding one file cannot say where in the flake it came from, and a
      # sourcePath of null makes seal treat the secret as someone else's.
      name = "narrowing file does not cost the working tree path";
      actual = profile.secrets.inSecretsDir.sourcePath;
      expected = "secrets/inSecretsDir.age";
    }
    {
      name = "a declared but uncreated secret still evaluates";
      actual = profile.secrets.missing.file;
      expected = "${src}/secrets/missing.age";
    }
    {
      # The source .age files are encrypted to the admin identity, which opens
      # every secret on every host. A host holds nothing that can read one, so
      # naming them here would ship them wherever the closure goes.
      name = "the profile a host installs names no source file";
      actual = lib.attrNames hostConfig.kix.internal.profile.secrets.inSecretsDir;
      expected = [
        "beforeUserborn"
        "group"
        "mode"
        "name"
        "owner"
        "path"
      ];
    }
    {
      name = "nixosModule points the host at the cache in the flake source";
      actual = profile.cacheInStore;
      expected = builtins.path { path = "${src}/secrets/cache/testhost"; };
    }
    {
      name = "edit does not evaluate any host";
      actual = builtins.typeOf poisonedPackages.kix-edit.drvPath;
      expected = "string";
    }
    {
      name = "seal does evaluate the hosts";
      actual = (builtins.tryEval poisonedPackages.kix-seal.drvPath).success;
      expected = false;
    }
  ];

  failed = lib.filter (c: c.actual != c.expected) checks;

  report = lib.concatMapStringsSep "\n" (c: ''
    ${c.name}
      expected: ${lib.generators.toPretty { } c.expected}
      actual:   ${lib.generators.toPretty { } c.actual}'') failed;
in
if failed != [ ] then
  throw "kix eval check: ${toString (lib.length failed)} of ${toString (lib.length checks)} failed\n\n${report}\n"
else
  runCommandLocal "kix-eval-module" { } ''
    echo "${toString (lib.length checks)} eval assertions passed" > "$out"

    # The assertion above says the projection names no source file; this one
    # says the file a host actually installs does not, however it was built.
    if grep -q '\.age' ${hostConfig.kix.internal.profileFile}; then
      echo "the profile installed on a host names a source .age file:" >&2
      grep -o '[^"]*\.age' ${hostConfig.kix.internal.profileFile} >&2
      exit 1
    fi
    echo "the installed profile names no source file" >> "$out"

    # A wrapper's text can only be read once it is built, so this one cannot
    # live with the assertions above.
    script=${subdirFlake.packages.${system}.kix-seal}/bin/kix-seal
    if ! grep -q 'toplevel)/eval-flake' "$script"; then
      echo "seal does not cd into the subdirectory the flake lives in:" >&2
      grep -n 'rev-parse' "$script" >&2
      exit 1
    fi
    echo "seal resolves against the flake subdirectory" >> "$out"
  ''
