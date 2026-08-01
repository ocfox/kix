# Seals a secret at build time, then boots a machine that deploys it.
# ./fixtures holds throwaway keys, committed so they are readable at eval time.
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

      # Hand-written rather than config.kix.profile: that depends on cacheRoot,
      # which is what this produces.
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

    machine.succeed("test -f /run/kix/test")
    assert machine.succeed("cat /run/kix/test") == "${payload}"

    # group is the owner's primary group, i.e. the default, not set below.
    assert machine.succeed("stat -c %U:%G:%a /run/kix/test").strip() == "kixtest:kixtest:400"

    machine.succeed("test -L /run/kix")
    machine.succeed("stat -f -c %T /run/kix.d | grep -q ramfs")

    # Restarting the unit repeatedly must keep /run/kix pointing at a usable
    # generation. The ENOENT watcher is opportunistic: it cannot report a false
    # positive, but the window it looks for is far too narrow for a shell loop
    # to hit reliably, so it is not a regression test for the atomic swap --
    # verified by confirming it still passes against the racy version.
    machine.succeed("""
      rm -f /tmp/enoent /tmp/stop
      ( until test -e /tmp/stop; do cat /run/kix/test >/dev/null 2>&1 || touch /tmp/enoent; done ) &
      reader=$!
      for _ in 1 2 3; do systemctl restart kix-activate.service; done
      touch /tmp/stop
      wait $reader
      test ! -e /tmp/enoent
    """)

    assert machine.succeed("cat /run/kix/test") == "${payload}"
  '';
}
