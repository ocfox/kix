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

## Requirements

`systemd.sysusers` or `services.userborn` must be enabled, so that the users
owning secrets exist by the time they are deployed. Secrets needed by user
creation itself can be deployed earlier with `beforeUserborn`.

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

The identity can be an age key or an OpenSSH private key, and either may be
protected by a passphrase — an `age -p` file or an encrypted OpenSSH key. kix
asks for the passphrase through `pinentry` if one is on `PATH`, and reads from
the terminal otherwise. There is no setting for which
pinentry to use: put the one you want earlier on `PATH`, the same way
`pinentry-curses` and the usual wrapper scripts are already selected. A
hardware token's PIN goes to the same prompt.

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

  kix.secrets.my-secret = {
    owner = "nginx";
    mode = "0440";
  };
}
```

A secret takes its file from its attribute name: `kix.secrets.my-secret` reads
`<flake.kix.secretsDir>/my-secret.age`, so `./secrets/my-secret.age` by default.
Evaluation fails if that file does not exist. Set `file` to point somewhere
else, keeping in mind that `seal` only re-encrypts sources inside `secretsDir`.

The default owner is `root` and the default mode `0400`, which a service running
as its own user cannot read — set `owner` to the user that needs it.

Reference a secret through its `path`, which is read-only:

```nix
services.foo.environmentFile = config.kix.secrets.my-secret.path;
```

## Options

`flake.kix.*`, once per flake:

| | default | |
|---|---|---|
| `identity` | — | Age identity that decrypts the source `.age` files. |
| `secretsDir` | `./secrets` | Source `.age` files, relative to the flake root. |
| `cache` | `./secrets/cache` | Where `seal` writes the sealed secrets. Must be committed. |
| `extraRecipients` | `[ ]` | Further recipients the sources are encrypted to, on top of your identity's own. |

`kix.*`, once per host:

| | default | |
|---|---|---|
| `hostPubkey` | — | Public key the host's secrets are sealed to. A string, or a path to read it from. |
| `hostKeys` | `config.services.openssh.hostKeys` | Private keys tried when decrypting at activation. |
| `dir` | `/run/kix` | Where decrypted secrets are reachable. |
| `mountPoint` | `/run/kix.d` | Where the ramfs holding them is mounted. |
| `secrets` | `{ }` | The secrets themselves. |

`kix.secrets.<name>.*`:

| | default | |
|---|---|---|
| `owner` | `root` | User of the decrypted secret. |
| `group` | the owner's primary group | Group of the decrypted secret. |
| `mode` | `0400` | Permissions of the decrypted secret. |
| `file` | `<secretsDir>/<name>.age` | Source the secret is loaded from. |
| `name` | the attribute name | Filename the secret is deployed under. |
| `beforeUserborn` | `false` | Deploy before users are created. Such a secret can only be owned by `root`, since no other user exists yet, and lands under `<dir>-for-user`. |
| `path` | read-only | Where the decrypted secret can be read. Point consumers at this. |

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

Both the source `.age` files and the sealed cache are committed, and both end
up world readable in `/nix/store` — that is what encryption is for. The source
is encrypted to you, the cache to each host, and only the cache reaches the
host.

Your identity and the plaintext are the two things that are in neither git nor
the store. Plaintext exists only on ramfs under `kix.mountPoint`, with the mode
and owner the secret declares — ramfs rather than tmpfs because tmpfs pages can
be swapped out. Only the current generation is kept; older ones are removed
after the symlink is swapped.

On your own machine, `edit` decrypts into `$XDG_RUNTIME_DIR`, or `/dev/shm` if
that is unset, so the plaintext stays in memory rather than landing somewhere a
delete would only unlink. It warns and falls back to a temporary directory if
neither is memory backed.

### Your editor writes to disk, and kix cannot stop it

`edit` only controls the file it hands over. Editors keep their own notes about
what you were editing — swap files, undo history, backups, `viminfo`/`shada` —
and those land wherever the editor puts them, usually under your home
directory. Any of them can hold part of a secret.

`$EDITOR` is whatever you make it, so kix cannot turn these off for you.

Thanks [vaultix](https://github.com/milieuim/vaultix).
