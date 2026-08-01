# A token whose PIN policy is "always" is asked once per unwrap, and seal
# unwraps once per distinct secret. Without a cache that is one prompt per
# secret; the point of this test is that the user is asked exactly once.
{
  lib,
  runCommand,
  buildGoModule,
  jq,
  kix,
}:
let
  plugin = buildGoModule {
    pname = "age-plugin-kixtest";
    version = "0";

    src = lib.fileset.toSource {
      root = ../.;
      fileset = lib.fileset.unions [
        ../go.mod
        ../go.sum
        ./fixtures/age-plugin-kixtest
      ];
    };

    vendorHash = "sha256-6JBArN7ee+wSgk9MDs5L5yHDjoabkYexkCL4GFQ//Nc=";
    subPackages = [ "tests/fixtures/age-plugin-kixtest" ];
  };

  hostPubkey = lib.removeSuffix "\n" (builtins.readFile ./fixtures/ssh_host_ed25519_key.pub);
  pin = "123456";
  secrets = [
    "alpha"
    "beta"
    "gamma"
    "delta"
  ];
in
runCommand "kix-pin-asked-once"
  {
    nativeBuildInputs = [
      kix
      plugin
      jq
    ];
  }
  ''
    set -euo pipefail
    export HOME=$PWD

    age-plugin-kixtest -keygen 0000000000000000000000000000000000000000000000000000000000000001 > id.txt

    mkdir -p secrets cache bin

    # Stands in for pinentry, and records every time it is run.
    cat > bin/pinentry <<EOF
    #!/bin/sh
    echo asked >> $PWD/prompts
    printf 'OK ready\n'
    while IFS= read -r line; do
      case "\$line" in
        GETPIN*) printf 'D ${pin}\nOK\n' ;;
        BYE*) printf 'OK\n'; exit 0 ;;
        *) printf 'OK\n' ;;
      esac
    done
    EOF
    chmod +x bin/pinentry
    export PATH=$PWD/bin:$PATH

    cat > write-payload <<'EOF'
    #!/bin/sh
    printf 'payload' > "$1"
    EOF
    chmod +x write-payload

    export KIXTEST_PIN=${pin}

    for name in ${lib.concatStringsSep " " secrets}; do
      EDITOR=$PWD/write-payload kix edit -i id.txt secrets/$name.age
    done

    printf '%s\n' ${lib.concatStringsSep " " secrets} \
      | jq -R . \
      | jq -s --arg dir "$PWD" --arg pubkey '${hostPubkey}' '{
          hostName: "machine",
          hostPubkey: $pubkey,
          secrets: (map({
            key: .,
            value: {
              file: "\($dir)/secrets/\(.).age",
              sourcePath: "\($dir)/secrets/\(.).age"
            }
          }) | from_entries)
        }' > profile.json

    cat > manifest.json <<EOF
    {
      "identity": "$PWD/id.txt",
      "cache": "$PWD/cache",
      "extraRecipients": [],
      "profiles": ["$PWD/profile.json"]
    }
    EOF

    echo "--- seal decrypts every secret, but must ask for the PIN once"
    : > prompts
    kix seal --manifest manifest.json

    asked=$(wc -l < prompts)
    echo "sealed ${toString (builtins.length secrets)} secrets, asked for the PIN $asked time(s)"
    if [ "$asked" -ne 1 ]; then
      echo "FAIL: expected 1 prompt, got $asked" >&2
      exit 1
    fi

    touch $out
  ''
