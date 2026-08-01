# Changelog

## Unreleased

Everything below predates any tagged release. There are no compatibility
aliases: kix has had no release to be compatible with.

### Breaking

- Import `config.flake.kix.nixosModule` instead of
  `inputs.kix.nixosModules.default`. The NixOS module no longer reaches back
  into flake outputs, so the values it used to read from `self` are passed to
  it instead. `nixosModules.default` still works standalone if you set
  `kix.internal.secretsDir` and `kix.internal.cacheRoot` yourself.
- `kix.settings.*` is flattened to `kix.*`. `kix.settings.hostPubkey` becomes
  `kix.hostPubkey`, `decryptedDir` becomes `kix.dir`, `decryptedMountPoint`
  becomes `kix.mountPoint`.
- `kix.beforeUserborn = [ "name" ]` becomes
  `kix.secrets.name.beforeUserborn = true`.
- `kix.secrets.<name>.path` is read-only. It previously doubled as "write the
  plaintext here instead", which silently placed it outside the ramfs.
- `kix.settings.hostIdentifier` and `kix.settings.decryptedDirForUser` are
  gone. The first was read-only and always equal to `networking.hostName`; the
  second is derived from `kix.dir`.
- `flake.kix.secretsDir` is a path relative to the flake root (`"./secrets"`)
  rather than a store path, because `edit` and `rekey` write to your working
  tree.
- `flake.kix.identity` pointing at a bare age key inside the flake source is
  now an evaluation error. Such a key is committed to your repository and world
  readable in `/nix/store`. Use an absolute path outside the flake, as a string.
  Plugin identities are unaffected.

### Behaviour changes to check after upgrading

- A secret's default group is the owner's primary group. It was always `root`,
  because the module indexed `config.users` rather than `config.users.users`,
  so the documented default never applied. Secrets with a non-root owner and a
  group-readable mode change ownership on the next rebuild.
- A failed owner or group lookup is an error instead of a warning followed by
  silently deploying as `root`. `root` itself is resolved without consulting
  NSS, since the pre-userborn deployment runs before `/etc/passwd` exists.
- `beforeUserborn` secrets are actually deployed under `services.userborn`. The
  unit was only pulled in by `systemd-sysusers.service`, which does not exist
  there, so they were silently skipped.
- Hosts mixing `beforeUserborn` and ordinary secrets no longer fail at boot.
  Each unit deployed every secret, and in the early run the ordinary ones
  pointed into a directory that did not exist yet.

### Added

- `seal` re-encrypts source secrets when the recipient set changes, which
  nothing could do before: `extraRecipients` only applied to newly written
  files, and `edit` returns early when content is unchanged, so a secret that
  already existed kept its old recipients forever. The set last written is
  recorded in `<cache>/.recipients`, because an age file does not say who it is
  encrypted to.
- `seal --old-identity` rotates `flake.kix.identity`. This is the one case that
  cannot be automatic, since decrypting the existing files needs the key being
  replaced; `seal` detects it specifically and says so rather than failing on
  a decryption error.
- `packages.kix-{seal,edit}` and matching `apps`, so `nix run .#kix-seal`
  works. These used to be `flake.kix.app`, which `nix run` could not reach.
- `overlays.default`, and a NixOS module that builds kix with your own nixpkgs
  instead of the one pinned in this flake.
- A NixOS VM test, treefmt, and CI running `nix flake check`.

### Fixed

- The secrets symlink is swapped atomically. Removing and recreating it left a
  window where a service reading its secret during a `nixos-rebuild switch` got
  ENOENT.
- The ramfs mount is detected with `statfs` rather than by testing whether the
  mount point directory exists. A directory left behind by a failed mount meant
  secrets landed on the swappable `/run` tmpfs instead.
- Superseded generation directories are removed. Each held a full set of
  plaintext on ramfs, which is never reclaimed, so every rebuild pinned another
  copy in RAM for the rest of the boot.
- `seal` decrypts each secret once rather than once per host, and no longer
  runs plugin sessions concurrently. Concurrent `Unwrap` calls share one
  unsynchronised `ClientUI` and spawn one plugin process each, so a cold cache
  meant several processes contending for one hardware token and one terminal.
- A host key mismatch reports which recipient the secret was sealed to and
  which key files were tried, instead of only "no host key can decrypt".
