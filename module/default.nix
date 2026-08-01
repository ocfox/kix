{
  config,
  options,
  pkgs,
  lib,
  ...
}:
let
  inherit (lib)
    all
    elem
    types
    mkOption
    isPath
    readFile
    hasAttr
    literalMD
    warn
    literalExpression
    mkIf
    ;

  cfg = config.kix;
  # `config.users.users`, not `config.users`: the latter is the option tree
  # (users/groups/mutableUsers), so the group default never resolved and every
  # secret silently ended up group-root.
  users = config.users.users;

  settingsType = types.submodule {
    options = {
      cacheInStore = mkOption {
        type = types.path;
        readOnly = true;
        default =
          let
            path = "${cfg.cacheRoot}/${config.networking.hostName}";
          in
          if cfg.cacheRoot == null then
            throw ''
              kix: `kix.cacheRoot` is unset, so the sealed secrets cannot be located.
              Import the module through `config.flake.kix.nixosModule` (which sets it
              from `flake.kix.cache`), or set `kix.cacheRoot` by hand.
            ''
          else if builtins.pathExists path then
            # Import only this host's subdirectory rather than referring to
            # "${self}/..." directly, so the derivation does not depend on the
            # whole flake source.
            builtins.path { inherit path; }
          else
            warn ''
              kix: cache path not found: ${path}; run `seal` first, or the build will fail.
            '' pkgs.emptyDirectory;
        defaultText = literalExpression "path in store";
        description = "Secrets re-encrypted by host public key. In nix store.";
      };

      # `str`, not `path`: these live on the target machine, never in the store,
      # and a bare Nix path literal here would import the runtime directory.
      decryptedDir = mkOption {
        type = types.str;
        default = "/run/kix";
        description = "Folder where secrets are symlinked to.";
      };

      decryptedDirForUser = mkOption {
        type = types.str;
        default = "/run/kix-for-user";
        description = "Folder where secrets for early (pre-userborn) deployment are symlinked to.";
      };

      decryptedMountPoint = mkOption {
        type = types.str;
        default = "/run/kix.d";
        description = "Where secrets are created before being symlinked to {option}`kix.settings.decryptedDir`.";
      };

      hostKeys = mkOption {
        type = lib.types.listOf lib.types.attrs;
        default = config.services.openssh.hostKeys;
        defaultText = literalExpression "config.services.openssh.hostKeys";
        description = "Ed25519 host private SSH key used for decrypting secrets while deploying.";
      };

      hostIdentifier = mkOption {
        type = types.str;
        default = config.networking.hostName;
        defaultText = literalExpression "config.networking.hostName";
        readOnly = true;
        description = "Host identifier.";
      };

      hostPubkey = mkOption {
        type = with types; coercedTo path (x: if isPath x then readFile x else x) str;
        example = literalExpression "./secrets/host1.pub";
        description = ''
          str or path containing the host public key.
          e.g. "ssh-ed25519 AAAAC3Nz..." or "age1qyqsz..."
        '';
      };
    };
  };

  secretType = types.submodule (submod: {
    options = {
      name = mkOption {
        type = types.str;
        default = submod.config._module.args.name;
        defaultText = literalExpression "the attribute name";
        description = "Filename when deployed to {option}`kix.settings.decryptedDir`.";
      };

      file = mkOption {
        type = types.path;
        default =
          let
            name = submod.config._module.args.name;
          in
          if cfg.secretsDir == null then
            throw ''
              kix: `kix.secretsDir` is unset, so the .age file for secret ${name} cannot be
              located. Import the module through `config.flake.kix.nixosModule` (which sets
              it from `flake.kix.secretsDir`), or set `kix.secrets.${name}.file` explicitly.
            ''
          else
            let
              path = cfg.secretsDir + "/${name}.age";
            in
            lib.throwIfNot (builtins.pathExists path) "kix: secret file not found: ${path}" path;
        defaultText = literalExpression ''config.kix.secretsDir + "/''${name}.age"'';
        description = "Age file the secret is loaded from.";
      };

      path = mkOption {
        type = types.str;
        default =
          if elem submod.config._module.args.name cfg.beforeUserborn then
            "${cfg.settings.decryptedDirForUser}/${submod.config.name}"
          else
            "${cfg.settings.decryptedDir}/${submod.config.name}";
        defaultText = literalExpression ''"''${cfg.settings.decryptedDir}/''${config.name}"'';
        description = "Path where the decrypted secret is installed.";
      };

      mode = mkOption {
        type = types.str;
        default = "0400";
        description = "Permissions mode of the decrypted secret.";
      };

      owner = mkOption {
        type = types.str;
        default = "root";
        description = "User of the decrypted secret.";
      };

      group = mkOption {
        type = types.str;
        default = users.${submod.config.owner}.group or "root";
        defaultText = literalExpression ''users.''${config.owner}.group or "root"'';
        description = "Group of the decrypted secret.";
      };

    };
  });
in
{
  options.kix = {
    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ../package.nix { };
      defaultText = literalMD "`kix` built from this flake's source with your own nixpkgs";
      description = "The kix package used at build and activation time.";
    };

    cacheRoot = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = literalExpression ''"''${inputs.self}/secrets/cache"'';
      description = ''
        Directory holding the per-host sealed secrets, as a string pointing into
        the flake source. Normally set for you by {option}`flake.kix.nixosModule`.
      '';
    };

    secretsDir = mkOption {
      type = types.nullOr types.path;
      default = null;
      example = literalExpression ''inputs.self + "/secrets"'';
      description = ''
        Directory containing the source .age files, used to derive the default of
        {option}`kix.secrets.<name>.file`. Normally set for you by
        {option}`flake.kix.nixosModule`.
      '';
    };

    settings = mkOption {
      type = settingsType;
      default = { };
      description = "Settings attrset.";
    };

    secrets = mkOption {
      type = types.attrsOf secretType;
      default = { };
      description = "Attrset of secrets.";
    };

    beforeUserborn = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "IDs of secrets to deploy before user init.";
    };

    # The wire format between Nix and the kix binary. Written out explicitly
    # rather than serialising `cfg` wholesale, so that adding an option above
    # changes neither the on-disk format nor every host's profile hash.
    profile = mkOption {
      internal = true;
      readOnly = true;
      type = types.attrs;
      default = {
        settings = {
          inherit (cfg.settings)
            cacheInStore
            decryptedDir
            decryptedDirForUser
            decryptedMountPoint
            hostIdentifier
            hostPubkey
            ;
          hostKeys = map (k: { inherit (k) path; }) cfg.settings.hostKeys;
        };
        secrets = lib.mapAttrs (_: s: {
          inherit (s)
            name
            file
            path
            mode
            owner
            group
            ;
        }) cfg.secrets;
        inherit (cfg) beforeUserborn;
      };
    };

    profileFile = mkOption {
      internal = true;
      readOnly = true;
      type = types.package;
      default = pkgs.writeText "kix-profile-${cfg.settings.hostIdentifier}.json" (
        builtins.toJSON cfg.profile
      );
    };
  };

  config =
    let
      # Fails the build if any secret is unsealed, so `nixos-rebuild` stops here
      # rather than producing a system whose kix-activate fails at boot. Built
      # with pkgsBuildHost because it executes on the build machine.
      checkSealed =
        pkgs.pkgsBuildHost.runCommandLocal "kix-seal-check-${cfg.settings.hostIdentifier}" { }
          "${
            lib.getExe (pkgs.pkgsBuildHost.callPackage ../package.nix { })
          } check --profile ${cfg.profileFile} > $out";
    in
    {
      assertions = [
        {
          assertion =
            options.systemd ? sysusers && (config.systemd.sysusers.enable || config.services.userborn.enable);
          message = "kix requires `systemd.sysusers` or `services.userborn` to be enabled.";
        }
        {
          assertion = all (b: b) (map (i: hasAttr i cfg.secrets) cfg.beforeUserborn);
          message = "one or more element of `beforeUserborn` not found in secrets.";
        }
      ];

      # `system.checks` gates the build without pulling the report into the
      # system closure, which the old SEAL_CHECK environment variable did.
      system.checks = [ checkSealed ];

      systemd.services.kix-activate = {
        wantedBy = [ "sysinit.target" ];
        after = [ "systemd-sysusers.service" ];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${lib.getExe cfg.package} deploy --profile ${cfg.profileFile}";
          RemainAfterExit = true;
        };
      };

      systemd.services.kix-activate-before-user = mkIf (cfg.beforeUserborn != [ ]) {
        wantedBy = [ "systemd-sysusers.service" ];
        before = [ "systemd-sysusers.service" ];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${lib.getExe cfg.package} deploy --profile ${cfg.profileFile} --early";
          RemainAfterExit = true;
        };
      };
    };
}
