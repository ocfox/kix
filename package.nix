{
  lib,
  buildGoModule,
}:

buildGoModule {
  pname = "kix";
  version = "0-unstable-2026-08-01";

  # Narrow the source so unrelated files (README, LICENSE, flake plumbing)
  # do not invalidate the build.
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./go.mod
      ./go.sum
      ./main.go
      ./cmd
      ./manifest
      ./profile
      ./secure
    ];
  };

  vendorHash = "sha256-foF4ECTT2j/DPynBKjbYf8hM8OoCxCRRgWjQ4BCUtcs=";

  ldflags = [
    "-s"
    "-w"
  ];

  meta = {
    description = "Secret manager for NixOS";
    homepage = "https://github.com/ocfox/kix";
    license = lib.licenses.asl20;
    mainProgram = "kix";
  };
}
