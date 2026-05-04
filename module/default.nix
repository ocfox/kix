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
    types
    mkOption
    isPath
    readFile
    hasAttr
    literalMD
    warn
    literalExpression
    mkIf
    assertMsg
    ;

  self = args.self or args.inputs.self;

  cfg = config.kix;

  users = config.users;

  sysusers = assertMsg (
    options.systemd ? sysusers && (config.systemd.sysusers.enable || config.services.userborn.enable)
  ) "`systemd.sysusers` or `services.userborn` must be enabled.";

  settingsType = types.submodule {
    options = {
      cacheInStore = mkOption {
        type = types.path;
        readOnly = true;
        default =
          let
            path = lib.concatMapStrings (x: "/" + x) [
              self
              self.kix.cache or "./secrets/cache"
              config.networking.hostName
            ];
          in
          if builtins.pathExists path then
            builtins.path {
              inherit path;
            }
          else
            warn ''
              path not exist: ${path}; Will auto create if you're running `seal`, else the build will fail.
            '' pkgs.emptyDirectory;
        defaultText = literalExpression "path in store";
        description = ''
          Secrets re-encrypted by each host public key. In nix store.
        '';
      };

      decryptedDir = mkOption {
        type = types.path;
        default = "/run/kix";
        defaultText = literalExpression "/run/kix";
        description = ''
          Folder where secrets are symlinked to.
        '';
      };

      decryptedDirForUser = mkOption {
        type = types.path;
        default = "/run/kix-for-user";
        defaultText = literalExpression "/run/kix-for-user";
        description = ''
          Folder where decrypted secrets for user are symlinked to.
          Secrets for user means it decrypt and extract before users
          created.
        '';
      };

      decryptedMountPoint = mkOption {
        type =
          types.addCheck types.str (
            s:
            (builtins.match "[ \t\n]*" s) == null
            && (builtins.match ".+/" s) == null
          )
          // {
            description = "${types.str.description} (with check: non-empty without trailing slash)";
          };
        default = "/run/kix.d";
        defaultText = literalExpression "/run/kix.d";
        description = ''
          Where secrets are created before they are symlinked to {option}`kix.settings.decryptedDir`
        '';
      };

      hostKeys = mkOption {
        type = lib.types.listOf lib.types.attrs;
        default = config.services.openssh.hostKeys;
        defaultText = literalExpression "config.services.openssh.hostKeys";
        description = ''
          Ed25519 host private ssh key (identity) path that used for decrypting secrets while deploying.
          Default is `config.services.openssh.hostKeys`.

          Default format:
          ```nix
          [
            {
              path = "/path/to/ssh_host_ed25519_key";
              type = "ed25519";
            }
          ]
          ```
        '';
      };

      hostIdentifier = mkOption {
        type = types.str;
        default = config.networking.hostName;
        defaultText = literalExpression "config.networking.hostName";
        readOnly = true;
        description = ''
          Host identifier
        '';
      };

      hostPubkey = mkOption {
        type = with types; coercedTo path (x: if isPath x then readFile x else x) str;
        example = literalExpression "./secrets/host1.pub";
        description = ''
          str or path that contains host public key.
          example:
          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI....."
          "age1qyqszqgpqyqszqgpqyqszqgpqyqszqgpq....."
          "/etc/ssh/ssh_host_ed25519_key.pub"
        '';
      };
    };
  };

  inherit
    (import ./secretType.nix {
      inherit
        lib
        cfg
        users
        self
        ;
    })
    secretType
    ;
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
      description = ''
        Attrset of settings.
      '';
    };

    secrets = mkOption {
      type = types.attrsOf secretType;
      default = { };
      description = ''
        Attrset of secrets.
      '';
    };

    beforeUserborn = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = ''
        List of id of items needed before user init
      '';
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

      checkSealedReport =
        pkgs.runCommandLocal "secret-check-report" { }
          "${lib.getExe cfg.package} -p ${mkProfile cfg} check > $out";
    in
    mkIf sysusers (
      let
        deployRequisites = [
          ("CACHE=" + cfg.settings.cacheInStore)
          ("CHECK_RESULT=" + checkSealedReport)
        ];
      in
      {
        systemd.services.kix-activate = {
          wantedBy = [ "sysinit.target" ];
          after = [ "systemd-sysusers.service" ];
          unitConfig.DefaultDependencies = "no";
          serviceConfig = {
            Type = "oneshot";
            Environment = deployRequisites;
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
            Environment = deployRequisites;
            ExecStart = "${lib.getExe cfg.package} -p ${profile} deploy --early";
            RemainAfterExit = true;
          };
        };

        assertions = [
          {
            assertion = all (b: b) (
              map (i: hasAttr i cfg.secrets) cfg.beforeUserborn
            );
            message = "one or more element of `beforeUserborn` not found in secrets.";
          }
        ];
      }
    );
}
