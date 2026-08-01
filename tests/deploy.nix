# End-to-end test: seal a secret at build time, then boot a machine that
# deploys it. Keys under ./fixtures are throwaway test material, generated once
# and committed so everything below is available at evaluation time.
{ lib, ... }:
let
  hostPubkey = builtins.readFile ./fixtures/ssh_host_ed25519_key.pub;
  secretFile = ./fixtures/test.age;
  payload = "s3cr3t-payload";
in
{
  name = "kix-deploy";

  nodes.machine =
    { config, pkgs, ... }:
    let
      kix = config.kix.package;

      # Sealing needs only the host recipient and the source .age file, so this
      # profile is written by hand rather than taken from config.kix.profile —
      # the latter depends on cacheRoot, which is what we are producing here.
      sealProfile = pkgs.writeText "seal-profile.json" (
        builtins.toJSON {
          settings = {
            hostIdentifier = "machine";
            inherit hostPubkey;
          };
          secrets.test = {
            name = "test";
            file = secretFile;
            path = "/run/kix/test";
            mode = "0400";
            owner = "kixtest";
            group = "kixtest";
          };
          beforeUserborn = [ ];
        }
      );

      sealedCache = pkgs.runCommand "kix-test-cache" { } ''
        mkdir -p "$out"
        cat > manifest.json <<EOF
        {
          "identity": "${./fixtures/id.txt}",
          "cache": "$out",
          "extraRecipients": [],
          "profiles": ["${sealProfile}"]
        }
        EOF
        ${lib.getExe kix} seal --manifest manifest.json
      '';
    in
    {
      imports = [ ../module ];

      services.userborn.enable = true;

      users.users.kixtest = {
        isSystemUser = true;
        group = "kixtest";
      };
      users.groups.kixtest = { };

      environment.etc."ssh/ssh_host_ed25519_key" = {
        source = ./fixtures/ssh_host_ed25519_key;
        mode = "0600";
      };

      kix = {
        cacheRoot = "${sealedCache}";
        settings = {
          inherit hostPubkey;
          hostKeys = [
            {
              path = "/etc/ssh/ssh_host_ed25519_key";
              type = "ed25519";
            }
          ];
        };
        secrets.test = {
          file = secretFile;
          owner = "kixtest";
          mode = "0400";
        };
      };
    };

  testScript = ''
    machine.wait_for_unit("kix-activate.service")

    # Decrypted with the host key and placed at the configured path.
    machine.succeed("test -f /run/kix/test")
    assert machine.succeed("cat /run/kix/test") == "${payload}"

    # Ownership and mode come from the profile, not from the process umask.
    # Mode from the profile, owner from `owner`, group from the owner's primary
    # group (the default, not set explicitly below).
    assert machine.succeed("stat -c %U:%G:%a /run/kix/test").strip() == "kixtest:kixtest:400"

    # /run/kix is a symlink into the generation directory, which lives on ramfs.
    machine.succeed("test -L /run/kix")
    machine.succeed("stat -f -c %T /run/kix.d | grep -q ramfs")
  '';
}
