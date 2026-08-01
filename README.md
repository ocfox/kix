# kix

Experiment

Uses `filippo.io/age` with Yubikey plugin. Same workflow: `edit` → `seal` → `deploy`.

## Usage

In your flake:

```nix
{
  imports = [ inputs.kix.flakeModules.default ];
  flake.kix.identity = "/home/you/.config/age/kix-identity.txt";
}
```

`identity` is the key that decrypts every secret kix manages. Give it an
absolute path **as a string**, so it stays outside the flake. A path written as
`./secrets/identity.txt` or `inputs.self + "/secrets/identity.txt"` has to be
committed for the flake to see it at all, and travels into `/nix/store` world
readable along with the rest of your flake source. kix refuses to evaluate if
it finds a bare age key there.

A plugin identity is the exception and can live in the flake, since
`AGE-PLUGIN-*` only names a slot on a hardware token and holds no key material:

```nix
flake.kix.identity = inputs.self + "/secrets/age-yubikey-identity-abcd1234.txt";
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
