# kix

Experiment. A secret manager for NixOS built on `filippo.io/age`, with Yubikey
plugin support.

## How it works

Secrets live in your repository as `.age` files encrypted to **you**. Hosts
never hold your identity, so they cannot read those directly. `seal` decrypts
each one and re-encrypts it to each **host's** public key, into a cache that is
committed alongside them. At activation a host decrypts its own cache entries
with its SSH host key.

The point of the cache is that your identity is only needed when secrets
change, not when a machine boots or rebuilds. The cost is a second copy of
every secret in the repository.

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

In each host, import the pre-wired module rather than `nixosModules.default`:

```nix
{
  imports = [ config.flake.kix.nixosModule ];
  kix.hostPubkey = "ssh-ed25519 AAAAC3Nz...";
  kix.secrets.my-secret = { };
}
```

Reference a secret through its `path`, which is read-only:

```nix
services.foo.environmentFile = config.kix.secrets.my-secret.path;
```

## Commands

```
nix run .#kix-edit -- secrets/my-secret.age   # create or edit a secret
nix run .#kix-seal                            # re-encrypt for every host
```

`seal` writes `flake.kix.cache` (default `./secrets/cache`). **That directory
must be committed**: the NixOS module locates it inside the flake source in the
store, and for a git flake an uncommitted file is not there. `nixos-rebuild`
fails via `system.checks` if anything is unsealed.

### Changing recipients

Adding to `extraRecipients` does not by itself reach the secrets you already
have: recipients are only applied when a file is written, and `edit` does
nothing when the content has not changed.

`seal` handles that for you. It records the recipient set it last wrote in
`<cache>/.recipients`, and when that no longer matches the manifest it
re-encrypts every source secret before sealing. There is no separate command
and nothing to remember.

The stamp is needed because an age file does not say who it is encrypted to —
the header holds one opaque stanza per recipient, so the set has to be
remembered rather than derived. It contains public keys and fingerprints only,
and is committed with the cache it describes.

### Rotating the identity

Changing `flake.kix.identity` is the one case `seal` cannot do on its own: the
existing files are encrypted to the key you are replacing, so re-encrypting
them needs both. `seal` recognises this and asks for the old one:

```
nix run .#kix-seal -- --old-identity /path/to/old-identity.txt
```

You must still hold the old identity. Nothing else can read those files — not
the hosts, which only ever get their own sealed copies.

## Where things live

| | in git | in /nix/store | on the host |
|---|---|---|---|
| source `.age` | yes | yes, world readable, encrypted to you | no |
| sealed cache | yes | yes, world readable, encrypted to the host | yes |
| identity | **no** | **no** | no |
| host private key | no | no | yes |
| plaintext | no | no | ramfs under `kix.mountPoint`, mode from the secret |

Both encrypted forms are world readable in the store; that is what encryption
is for. The two things that must not be there are your identity and the
plaintext, and neither is.

Plaintext lands on ramfs rather than tmpfs because tmpfs pages can be swapped
out. Only the current generation is kept; older ones are removed after the
symlink is swapped.

## Requirements

`systemd.sysusers` or `services.userborn` must be enabled, so that the users
owning secrets exist by the time they are deployed.

Thanks [vaultix](https://github.com/milieuim/vaultix)
