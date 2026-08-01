package main

import (
	"log/slog"
	"os"

	"github.com/ocfox/kix/cmd"
)

// version is set by the Nix build; a plain `go build` reports dev.
var version = "dev"

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	cmd.Execute(version)
}
