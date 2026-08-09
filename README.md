# kix

Experiment. A secret manager for NixOS built on `filippo.io/age`, with Yubikey
plugin support.

Secrets live in your repository as `.age` files encrypted to **you**. `seal`
re-encrypts each one to every **host's** public key, into a cache committed
alongside the sources; at activation a host decrypts its own entries with its
SSH host key. Your identity is only needed when secrets change.

Requires [flake-parts](https://flake.parts), and `systemd.sysusers` or
`services.userborn`.

## Usage

Create an identity, outside the flake:

```
age-keygen -o ~/.config/age/kix-identity.txt              # an age key
age-keygen | age -p -o ~/.config/age/kix-identity.txt     # the same, behind a passphrase
age-plugin-yubikey                                        # a Yubikey slot
```

An OpenSSH private key you already have works too, ed25519 or RSA.

Then in your flake, inside `mkFlake`:

```nix
{
  imports = [ inputs.kix.flakeModules.default ];

  flake.kix = {
    identity = "/home/you/.config/age/kix-identity.txt";  # absolute, and a string
    secretsDir = "./secrets";       # sources, relative to the flake root
    cache = "./secrets/cache";      # sealed output, commit it
    extraRecipients = [ ];          # further recipients for the sources
  };
}
```

A path literal like `./secrets/identity.txt` would be committed and land world
readable in `/nix/store`, so kix refuses to evaluate on a bare age key inside
the flake. A plugin identity is the exception, since `AGE-PLUGIN-*` only names
a slot on a token:

```nix
flake.kix.identity = inputs.self + "/secrets/age-yubikey-identity-abcd1234.txt";
```

That identity is the only key that reads the sources, and the sealed copies
cannot stand in for it: each one is encrypted to a single host, and a host can
open nothing but its own. Lose the identity with `extraRecipients` empty and
every secret has to be generated again. A second key belongs there — one
identity file holds one identity, and kix refuses a file with more.

In each host, import the pre-wired module — the bare `nixosModules.default`
throws:

```nix
{
  imports = [ config.flake.kix.nixosModule ];

  kix.hostPubkey = "ssh-ed25519 AAAAC3Nz...";  # /etc/ssh/ssh_host_ed25519_key.pub
  kix.dir = "/run/kix";             # where decrypted secrets are readable
  kix.mountPoint = "/run/kix.d";    # ramfs holding them
  kix.hostKeys = config.services.openssh.hostKeys;

  kix.secrets.my-secret = {
    owner = "nginx";                # default root
    group = "nginx";                # default: the owner's primary group
    mode = "0440";                  # default 0400
    file = ./secrets/my-secret.age; # default <secretsDir>/<name>.age
    name = "my-secret";             # default: the attribute name
    beforeUserborn = false;         # deploy before users exist: root-only, under <dir>-for-user
  };
}
```

The defaults are `root` and `0400`, which a service running as its own user
cannot read. A `file` from outside the flake is read but never rewritten.
Consumers read `path`:

```nix
services.foo.environmentFile = config.kix.secrets.my-secret.path;
```

## Commands

The flake module adds these to your own flake:

```
nix run .#kix-edit -- secrets/my-secret.age   # create or edit a secret
nix run .#kix-seal                            # re-encrypt for every host
```

`seal` reads the sources from your working tree. Sources and cache both have to
be committed before `nixos-rebuild`, which fails via `system.checks` if
anything is unsealed. `seal` re-encrypts every source when `extraRecipients`
changes, and asks for the old key when `identity` does:

```
nix run .#kix-seal -- --old-identity /path/to/old-identity.txt
```

## Where things live

Sources and cache are both committed and both world readable in `/nix/store`.
Plaintext only ever exists on ramfs under `kix.mountPoint`, and `edit` decrypts
into `$XDG_RUNTIME_DIR` or `/dev/shm`. kix cannot stop your editor writing to
disk: swap files, undo history and backups land wherever it puts them, and any
of them can hold part of a secret.

Thanks [vaultix](https://github.com/milieuim/vaultix).
