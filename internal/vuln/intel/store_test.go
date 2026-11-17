package intel

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// The cache is a map of every host in the estate, its packages and its problems. It must
// not be readable by another account on the same machine.
func TestStoreFilesArePrivateToTheServiceAccount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intel.db")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	defer st.Close()
	// Force the WAL to exist so its permissions are checked too.
	if err := st.AppendAudit(context.Background(), AuditEntry{At: "2026-01-01T00:00:00Z", Action: "test"}); err != nil {
		t.Fatalf("AppendAudit: %v", err)
	}
	for _, f := range []string{path, path + "-wal", path + "-shm"} {
		info, err := os.Stat(f)
		if err != nil {
			continue // -shm is created lazily
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("%s is %#o, want 0600", filepath.Base(f), perm)
		}
	}
}

// A pre-existing world-readable database is repaired on open, because deployments that
// started before this check existed would otherwise stay exposed.
func TestOpenStoreRepairsLoosePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "intel.db")
	st, err := OpenStore(path)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	st.Close()
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	st2, err := OpenStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer st2.Close()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("mode = %#o after reopen, want 0600", perm)
	}
}
