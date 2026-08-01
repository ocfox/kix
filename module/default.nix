{
  config,
  options,
  pkgs,
  lib,
  ...
}:
let
  inherit (lib)
    types
    mkOption
    isPath
    readFile
    literalMD
    warn
    literalExpression
    mkIf
    ;

  cfg = config.kix;
  users = config.users.users;

  # Secrets deployed before sysusers get their own tree, because a separate
  # unit deploys them at a point where the users owning the rest do not exist
  # yet. Derived rather than configurable: it is never independently useful.
  dirForUser = "${cfg.dir}-for-user";

  hasEarly = lib.any (s: s.beforeUserborn) (lib.attrValues cfg.secrets);

  secretType = types.submodule (submod: {
    options = {
      name = mkOption {
        type = types.str;
        default = submod.config._module.args.name;
        defaultText = literalExpression "the attribute name";
        description = "Filename the secret is deployed under.";
      };

      file = mkOption {
        type = types.path;
        default =
          let
            name = submod.config._module.args.name;
          in
          if cfg.internal.secretsDir == null then
            throw ''
              kix: `flake.kix.secretsDir` is unset, so the .age file for secret ${name}
              cannot be located. Import the module through `config.flake.kix.nixosModule`,
              or set `kix.secrets.${name}.file` explicitly.
            ''
          else
            let
              path = cfg.internal.secretsDir + "/${name}.age";
            in
            lib.throwIfNot (builtins.pathExists path) "kix: secret file not found: ${path}" path;
        defaultText = literalExpression "<flake.kix.secretsDir>/\${name}.age";
        description = "Age file the secret is loaded from.";
      };

      beforeUserborn = mkOption {
        type = types.bool;
        default = false;
        description = ''
          Deploy this secret before users are created, for secrets that are
          needed by user creation itself. Such secrets can only be owned by
          root, since no other user exists yet.
        '';
      };

      path = mkOption {
        type = types.str;
        readOnly = true;
        default =
          if submod.config.beforeUserborn then
            "${dirForUser}/${submod.config.name}"
          else
            "${cfg.dir}/${submod.config.name}";
        defaultText = literalExpression ''"''${config.kix.dir}/''${name}"'';
        description = ''
          Where the decrypted secret can be read. Read-only: point consumers at
          this rather than hardcoding a path.
        '';
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
        defaultText = literalExpression ''the owner's primary group, or "root"'';
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

    hostPubkey = mkOption {
      type = with types; coercedTo path (x: if isPath x then readFile x else x) str;
      example = literalExpression "./secrets/host1.pub";
      description = ''
        str or path containing the host public key that secrets are sealed to.
        e.g. "ssh-ed25519 AAAAC3Nz..." or "age1qyqsz..."
      '';
    };

    hostKeys = mkOption {
      type = types.listOf types.attrs;
      default = config.services.openssh.hostKeys;
      defaultText = literalExpression "config.services.openssh.hostKeys";
      description = ''
        Host private SSH keys tried when decrypting at activation time.
        Only the `path` attribute of each entry is read.
      '';
    };

    # `str`, not `path`: these are runtime paths on the target, and `path`
    # would import the directory into the store.
    dir = mkOption {
      type = types.str;
      default = "/run/kix";
      description = ''
        Directory the decrypted secrets are reachable under. Secrets deployed
        before users exist use "''${dir}-for-user".
      '';
    };

    mountPoint = mkOption {
      type = types.str;
      default = "/run/kix.d";
      description = "Where the ramfs holding the decrypted secrets is mounted.";
    };

    secrets = mkOption {
      type = types.attrsOf secretType;
      default = { };
      description = "Attrset of secrets.";
    };

    internal = {
      cacheRoot = mkOption {
        internal = true;
        type = types.nullOr types.str;
        default = null;
        description = "Set from `flake.kix.cache` by `flake.kix.nixosModule`.";
      };

      secretsDir = mkOption {
        internal = true;
        type = types.nullOr types.path;
        default = null;
        description = "Set from `flake.kix.secretsDir` by `flake.kix.nixosModule`.";
      };

      cacheInStore = mkOption {
        internal = true;
        readOnly = true;
        type = types.path;
        default =
          let
            path = "${cfg.internal.cacheRoot}/${config.networking.hostName}";
          in
          if cfg.internal.cacheRoot == null then
            throw ''
              kix: `flake.kix.cache` is unset, so the sealed secrets cannot be located.
              Import the module through `config.flake.kix.nixosModule`.
            ''
          else if builtins.pathExists path then
            # Imports just this host's subdirectory, so the derivation does not
            # depend on the whole flake source.
            builtins.path { inherit path; }
          else
            warn ''
              kix: cache path not found: ${path}; run `seal` first, or the build will fail.
            '' pkgs.emptyDirectory;
      };

      # The wire format read by the kix binary. An explicit projection, so
      # adding an option above does not change it.
      profile = mkOption {
        internal = true;
        readOnly = true;
        type = types.attrs;
        default = {
          hostName = config.networking.hostName;
          inherit (cfg) hostPubkey dir mountPoint;
          inherit dirForUser;
          inherit (cfg.internal) cacheInStore;
          hostKeys = map (k: { inherit (k) path; }) cfg.hostKeys;
          secrets = lib.mapAttrs (_: s: {
            inherit (s)
              name
              file
              path
              mode
              owner
              group
              beforeUserborn
              ;
          }) cfg.secrets;
        };
      };

      profileFile = mkOption {
        internal = true;
        readOnly = true;
        type = types.package;
        default = pkgs.writeText "kix-profile-${config.networking.hostName}.json" (
          builtins.toJSON cfg.internal.profile
        );
      };
    };
  };

  config =
    let
      profileFile = cfg.internal.profileFile;

      # Fails the build if any secret is unsealed, rather than at boot. Runs
      # cfg.package on the builder, so it does not survive cross-compilation.
      checkSealed =
        pkgs.runCommandLocal "kix-seal-check-${config.networking.hostName}" { }
          "${lib.getExe cfg.package} check --profile ${profileFile} > $out";
    in
    {
      assertions = [
        {
          assertion =
            options.systemd ? sysusers && (config.systemd.sysusers.enable || config.services.userborn.enable);
          message = "kix requires `systemd.sysusers` or `services.userborn` to be enabled.";
        }
        {
          assertion = lib.all (s: !s.beforeUserborn || s.owner == "root") (lib.attrValues cfg.secrets);
          message = ''
            A secret with `beforeUserborn = true` is deployed before users exist, so it
            can only be owned by root.
          '';
        }
      ];

      # Gates the build without entering the system closure.
      system.checks = [ checkSealed ];

      systemd.services.kix-activate = {
        wantedBy = [ "sysinit.target" ];
        after = [ "systemd-sysusers.service" ];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${lib.getExe cfg.package} deploy --profile ${profileFile}";
          RemainAfterExit = true;
        };
      };

      systemd.services.kix-activate-before-user = mkIf hasEarly {
        wantedBy = [ "systemd-sysusers.service" ];
        before = [ "systemd-sysusers.service" ];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${lib.getExe cfg.package} deploy --profile ${profileFile} --early";
          RemainAfterExit = true;
        };
      };
    };
}
