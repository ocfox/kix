# Rotating flake.kix.identity between two plugin identities. Needs no VM: the
# whole path under test is seal's, and a fake plugin stands in for the token.
{
  lib,
  runCommand,
  buildGoModule,
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
  payload = "rotate-me";
in
runCommand "kix-rotate-plugin-identity"
  {
    nativeBuildInputs = [
      kix
      plugin
    ];
  }
  ''
    set -euo pipefail
    export HOME=$PWD

    age-plugin-kixtest -keygen 0000000000000000000000000000000000000000000000000000000000000001 > idA.txt
    age-plugin-kixtest -keygen 0000000000000000000000000000000000000000000000000000000000000002 > idB.txt

    mkdir -p secrets cache

    cat > write-payload <<'EOF'
    #!/bin/sh
    printf '%s' "${payload}" > "$1"
    EOF
    chmod +x write-payload

    cat > dump <<'EOF'
    #!/bin/sh
    cp "$1" "$DUMP_TO"
    EOF
    chmod +x dump

    EDITOR=$PWD/write-payload kix edit -i idA.txt secrets/test.age

    manifest() {
      cat > manifest.json <<EOF
    {
      "identity": "$1",
      "cache": "$PWD/cache",
      "extraRecipients": [],
      "profiles": ["$PWD/profile.json"]
    }
    EOF
    }

    cat > profile.json <<EOF
    {
      "hostName": "machine",
      "hostPubkey": "${hostPubkey}",
      "secrets": {
        "test": {
          "file": "$PWD/secrets/test.age",
          "sourcePath": "$PWD/secrets/test.age"
        }
      }
    }
    EOF

    echo "--- first seal records the identity"
    manifest idA.txt
    kix seal --manifest manifest.json
    grep -q '^identity plugin:kixtest:' cache/.recipients

    echo "--- rotating without --old-identity is refused"
    manifest idB.txt
    if kix seal --manifest manifest.json 2> rotate.err; then
      echo "FAIL: seal accepted a rotated plugin identity" >&2
      exit 1
    fi
    grep -q -- '--old-identity' rotate.err

    echo "--- rotating with --old-identity re-encrypts the source"
    kix seal --manifest manifest.json --old-identity idA.txt

    DUMP_TO=$PWD/out EDITOR=$PWD/dump kix edit -i idB.txt secrets/test.age
    [ "$(cat out)" = "${payload}" ]

    if EDITOR=$PWD/dump DUMP_TO=$PWD/stale kix edit -i idA.txt secrets/test.age 2> /dev/null; then
      echo "FAIL: the old identity still reads the source secret" >&2
      exit 1
    fi

    echo "--- a legacy stamp is upgraded rather than refused"
    printf 'identity <identity-based recipient>\n' > cache/.recipients
    kix seal --manifest manifest.json
    grep -q '^identity plugin:kixtest:' cache/.recipients

    touch $out
  ''
