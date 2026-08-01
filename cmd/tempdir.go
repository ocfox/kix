package cmd

import (
	"log/slog"
	"os"

	"golang.org/x/sys/unix"
)

// Plaintext must not reach a disk. The deployed secrets live on ramfs for this
// reason; the file an editor works on deserves the same care, and $TMPDIR is
// commonly a real filesystem where a delete only unlinks.
//
// tmpfs can be swapped out, unlike the ramfs used on a host, but it is the
// best a plain user process can ask for without mounting anything.
// tmpfsMagic is TMPFS_MAGIC from linux/magic.h; ramfsMagic is next to the
// ramfs mount it belongs to, in deploy.go.
const tmpfsMagic = 0x01021994

// pickPlaintextDir returns the directory to hold decrypted plaintext, and
// whether the search had to settle for the disk. An empty directory means the
// system default.
func pickPlaintextDir(runtimeDir string, isMemory func(string) bool) (string, bool) {
	// The runtime dir belongs to one user and is mode 0700; /dev/shm is
	// world writable, so it is only the fallback.
	for _, dir := range []string{runtimeDir, "/dev/shm"} {
		if dir != "" && isMemory(dir) {
			return dir, false
		}
	}
	return "", true
}

// plaintextDir picks a directory and warns if the plaintext has to touch disk.
func plaintextDir() string {
	dir, onDisk := pickPlaintextDir(os.Getenv("XDG_RUNTIME_DIR"), memoryBacked)
	if onDisk {
		slog.Warn("no memory backed directory for the decrypted file, falling back to a temporary directory on disk",
			"tried", "$XDG_RUNTIME_DIR, /dev/shm")
	}
	return dir
}

// memoryBacked reports whether path lives on a filesystem that never writes to
// a disk.
func memoryBacked(path string) bool {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return false
	}
	switch int64(st.Type) {
	case tmpfsMagic, ramfsMagic:
		return true
	}
	return false
}

// createPlaintextFile opens a private file for one secret's plaintext.
func createPlaintextFile(dir string) (*os.File, error) {
	return os.CreateTemp(dir, "kix-edit-*")
}
