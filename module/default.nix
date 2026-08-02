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
            # Deliberately not checked for existence here: a secret you have
            # declared but not yet created is a legal intermediate state, and
            # `check` reports it at build time. Asserting it during eval would
            # break every command that reads the configuration, including the
            # one that creates the file.
            cfg.internal.secretsDir + "/${name}.age";
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

      # Caught here rather than at activation, and capped at 0777 because
      # setuid, setgid and sticky cannot survive the trip to the file.
      mode = mkOption {
        type = types.strMatching "0?[0-7]{3}";
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
      # A trailing slash or a relative path here only fails later, inside
      # mount(2), where the message says nothing about which option was wrong.
      type = types.addCheck types.str (s: lib.hasPrefix "/" s && !lib.hasSuffix "/" s) // {
        description = "absolute path without a trailing slash";
      };
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

      flakeRoot = mkOption {
        internal = true;
        type = types.nullOr types.str;
        default = null;
        description = ''
          The flake source in the store, used to map a secret's `file` back to
          the working tree copy that `seal` rewrites. Set by
          `flake.kix.nixosModule`.
        '';
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
      #
      # This is the half that travels to the host, so it names no source .age
      # file. Those are encrypted to the admin identity, which decrypts every
      # secret on every host, and a host holds nothing that could read one:
      # they would be along purely to name a cache entry, and would go wherever
      # the system closure goes, a binary cache included.
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
              path
              mode
              owner
              group
              beforeUserborn
              ;
          }) cfg.secrets;
        };
      };

      # The same profile with the source .age files named, for the commands
      # that run where the admin identity already is: `seal` on their machine
      # and `check` on the builder. Never referenced by anything the host
      # installs -- `system.checks` are build dependencies and stay out of the
      # closure, which is the whole reason check may read these at all.
      adminProfile = mkOption {
        internal = true;
        readOnly = true;
        type = types.attrs;
        default = cfg.internal.profile // {
          secrets = lib.mapAttrs (
            name: s:
            let
              f = toString s.file;
              prefix = "${cfg.internal.flakeRoot}/";
              inFlake = cfg.internal.flakeRoot != null && lib.hasPrefix prefix f;
            in
            cfg.internal.profile.secrets.${name}
            // {
              # Just this file, never the tree it sits in: a subpath of the
              # flake source carries the whole source as its context.
              #
              # Narrowed here and not in the `file` option itself: `sourcePath`
              # below reads the path as written, and a store path holding one
              # file no longer says where in the flake it came from. A path
              # outside the store is left alone, so pointing `file` there fails
              # where it always did rather than during evaluation.
              file =
                if lib.hasPrefix builtins.storeDir f && builtins.pathExists f then
                  builtins.path { path = f; }
                else
                  f;

              # Where `file` lives in the working tree, so seal can rewrite it
              # when the recipient set changes. Anywhere in the flake will do,
              # not just secretsDir: a path literal in the flake is a subpath of
              # the flake source, so the working tree copy is the same name under
              # the flake root. Null for a file that came from somewhere else --
              # another flake's secrets are someone else's to re-encrypt.
              sourcePath = if inFlake then lib.removePrefix prefix f else null;
            }
          ) cfg.secrets;
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

      adminProfileFile = mkOption {
        internal = true;
        readOnly = true;
        type = types.package;
        default = pkgs.writeText "kix-admin-profile-${config.networking.hostName}.json" (
          builtins.toJSON cfg.internal.adminProfile
        );
      };
    };
  };

  config =
    let
      profileFile = cfg.internal.profileFile;

      # Fails the build if any secret is unsealed, rather than at boot. Runs
      # cfg.package on the builder, so it does not survive cross-compilation.
      #
      # Reads the admin profile, and may: `system.checks` are build
      # dependencies whose output nothing installs, so the source .age files
      # this names never reach the host.
      checkSealed =
        pkgs.runCommandLocal "kix-seal-check-${config.networking.hostName}" { }
          "${lib.getExe cfg.package} check --profile ${cfg.internal.adminProfileFile} > $out";
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

      # Both names on purpose: only one of the two units exists on any given
      # host, and referring to an absent unit is a no-op. Naming only
      # systemd-sysusers.service meant nothing pulled this in under userborn,
      # so `beforeUserborn` secrets were silently never deployed there.
      systemd.services.kix-activate-before-user = mkIf hasEarly {
        wantedBy = [
          "systemd-sysusers.service"
          "userborn.service"
        ];
        before = [
          "systemd-sysusers.service"
          "userborn.service"
        ];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          ExecStart = "${lib.getExe cfg.package} deploy --profile ${profileFile} --early";
          RemainAfterExit = true;
        };
      };
    };
}
