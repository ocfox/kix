# kix

Experiment

Uses `filippo.io/age` with Yubikey plugin. Same workflow: `edit` → `seal` → `deploy`.

## Usage

In your flake:

```nix
{
  imports = [ inputs.kix.flakeModules.default ];
  flake.kix.identity = inputs.self + "/secrets/identity.txt";
}
```

In each host, import the pre-wired module rather than `nixosModules.default`,
so `secretsDir` and `cacheRoot` are filled in for you:

```nix
{
  imports = [ config.flake.kix.nixosModule ];
  kix.settings.hostPubkey = "ssh-ed25519 AAAAC3Nz...";
  kix.secrets.my-secret = { };
}
```

Then:

```
nix run .#kix-edit -- secrets/my-secret.age   # create or edit a secret
nix run .#kix-seal                            # re-encrypt for every host
```

`seal` writes to `flake.kix.cache` (default `./secrets/cache`). **That
directory must be committed**: the NixOS module locates it inside the flake
source in the store, and for a git flake uncommitted files are not there.
`nixos-rebuild` fails via `system.checks` if anything is unsealed.

Thanks [vaultix](https://github.com/milieuim/vaultix)
