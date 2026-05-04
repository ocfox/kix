package main

import (
	"log/slog"
	"os"

	"github.com/ocfox/kix/cmd"
)

func main() {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})))
	cmd.Execute()
}
