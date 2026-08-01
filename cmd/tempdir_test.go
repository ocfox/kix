package cmd

import (
	"path/filepath"
	"slices"
	"testing"
)

// memoryOnly reports the given paths as memory backed and everything else as
// disk, standing in for the statfs check.
func memoryOnly(paths ...string) func(string) bool {
	return func(p string) bool { return slices.Contains(paths, p) }
}

func TestPickPlaintextDirPrefersThePrivateRuntimeDir(t *testing.T) {
	got, onDisk := pickPlaintextDir("/run/user/1000", memoryOnly("/run/user/1000", "/dev/shm"))

	if onDisk {
		t.Error("reported the runtime dir as being on disk")
	}
	if got != "/run/user/1000" {
		t.Errorf("picked %q, want the runtime dir", got)
	}
}

// /dev/shm is world writable, so it is second choice, not first.
func TestPickPlaintextDirFallsBackToSharedMemory(t *testing.T) {
	got, onDisk := pickPlaintextDir("", memoryOnly("/dev/shm"))

	if onDisk {
		t.Error("reported /dev/shm as being on disk")
	}
	if got != "/dev/shm" {
		t.Errorf("picked %q, want /dev/shm", got)
	}
}

// A runtime dir that is not memory backed is no better than /tmp.
func TestPickPlaintextDirSkipsARuntimeDirOnDisk(t *testing.T) {
	got, onDisk := pickPlaintextDir("/run/user/1000", memoryOnly("/dev/shm"))

	if onDisk {
		t.Error("reported /dev/shm as being on disk")
	}
	if got != "/dev/shm" {
		t.Errorf("picked %q, want /dev/shm", got)
	}
}

// The caller has to be told, because the whole point is that the plaintext
// must not reach a disk without the user knowing.
func TestPickPlaintextDirReportsWhenOnlyDiskIsLeft(t *testing.T) {
	got, onDisk := pickPlaintextDir("", memoryOnly())

	if !onDisk {
		t.Error("did not report falling back to disk")
	}
	if got != "" {
		t.Errorf("picked %q, want the empty default", got)
	}
}

func TestPlaintextFileIsPrivate(t *testing.T) {
	dir := t.TempDir()

	f, err := createPlaintextFile(dir)
	if err != nil {
		t.Fatalf("createPlaintextFile: %v", err)
	}
	defer f.Close()

	if filepath.Dir(f.Name()) != dir {
		t.Errorf("created %q, want it under %q", f.Name(), dir)
	}
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("created with mode %04o, want 0600", perm)
	}
}
