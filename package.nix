{
  lib,
  buildGoModule,
}:

let
  version = "0.1.2";
in
buildGoModule {
  pname = "kix";
  inherit version;

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

  vendorHash = "sha256-WEZhTcRl2tJLktBjjv7aFSpE0+LbkIS2MygB94Cb2vE=";

  ldflags = [
    "-s"
    "-w"
    "-X main.version=${version}"
  ];

  meta = {
    description = "Secret manager for NixOS";
    homepage = "https://github.com/ocfox/kix";
    license = lib.licenses.mit;
    mainProgram = "kix";
  };
}
