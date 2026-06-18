{
  config,
  options,
  pkgs,
  lib,
  ...
}@args:
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

  self = args.self or args.inputs.self;
  cfg = config.kix;
  users = config.users;

  settingsType = types.submodule {
    options = {
      cacheInStore = mkOption {
        type = types.path;
        readOnly = true;
        default =
          let
            cache = lib.removePrefix "./" (self.kix.cache or "./secrets/cache");
            path = "${self}/${cache}/${config.networking.hostName}";
          in
          if builtins.pathExists path then
            builtins.path { inherit path; }
          else
            warn ''
              kix: cache path not found: ${path}; run `seal` first, or the build will fail.
            '' pkgs.emptyDirectory;
        defaultText = literalExpression "path in store";
        description = "Secrets re-encrypted by host public key. In nix store.";
      };

      decryptedDir = mkOption {
        type = types.path;
        default = "/run/kix";
        defaultText = literalExpression "/run/kix";
        description = "Folder where secrets are symlinked to.";
      };

      decryptedDirForUser = mkOption {
        type = types.path;
        default = "/run/kix-for-user";
        defaultText = literalExpression "/run/kix-for-user";
        description = "Folder where secrets for early (pre-userborn) deployment are symlinked to.";
      };

      decryptedMountPoint = mkOption {
        type =
          types.addCheck types.str (
            s: (builtins.match "[ \t\n]*" s) == null && (builtins.match ".+/" s) == null
          )
          // {
            description = "${types.str.description} (with check: non-empty without trailing slash)";
          };
        default = "/run/kix.d";
        defaultText = literalExpression "/run/kix.d";
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
      id = mkOption {
        type = types.str;
        default = submod.config._module.args.name;
        readOnly = true;
        description = "Secret identifier (the attrset key in `kix.secrets`).";
      };

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
            path = self.kix.secretsDir + "/${name}.age";
          in
          lib.throwIfNot (builtins.pathExists path)
            "kix: secret file not found: ${path}"
            path;
        defaultText = literalExpression ''self.kix.secretsDir + "/''${name}.age"'';
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
      defaultText = literalMD "`packages.kix` from this flake";
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
  };

  options.kix-debug = mkOption {
    type = types.unspecified;
    default = cfg;
  };

  config =
    let
      mkProfile =
        partial:
        pkgs.writeTextFile {
          name = "secret-meta-${config.networking.hostName}";
          text = builtins.toJSON partial;
        };

      profile = mkProfile cfg;

      # Forces `kix check` to pass at build time — if any secrets are unsealed,
      # nixos-rebuild fails here rather than silently deploying an incomplete set.
      # The SEAL_CHECK env var is never read at runtime; it exists only so Nix
      # treats this derivation as a build dependency of the systemd service.
      checkSealedReport =
        pkgs.runCommandLocal "kix-seal-check-${config.networking.hostName}" { }
          "${lib.getExe cfg.package} -p ${profile} check > $out";

      deployEnv = [ "SEAL_CHECK=${checkSealedReport}" ];
    in
    {
      assertions = [
        {
          assertion = options.systemd ? sysusers && (config.systemd.sysusers.enable || config.services.userborn.enable);
          message = "kix requires `systemd.sysusers` or `services.userborn` to be enabled.";
        }
        {
          assertion = all (b: b) (map (i: hasAttr i cfg.secrets) cfg.beforeUserborn);
          message = "one or more element of `beforeUserborn` not found in secrets.";
        }
      ];

      systemd.services.kix-activate = {
        wantedBy = [ "sysinit.target" ];
        after = [ "systemd-sysusers.service" ];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          Environment = deployEnv;
          ExecStart = "${lib.getExe cfg.package} -p ${profile} deploy";
          RemainAfterExit = true;
        };
      };

      systemd.services.kix-activate-before-user = mkIf (cfg.beforeUserborn != [ ]) {
        wantedBy = [ "systemd-sysusers.service" ];
        before = [ "systemd-sysusers.service" ];
        unitConfig.DefaultDependencies = "no";
        serviceConfig = {
          Type = "oneshot";
          Environment = deployEnv;
          ExecStart = "${lib.getExe cfg.package} -p ${profile} deploy --early";
          RemainAfterExit = true;
        };
      };
    };
}
