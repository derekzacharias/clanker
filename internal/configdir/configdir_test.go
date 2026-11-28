package configdir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The bug: a container has no writable home, so os.UserConfigDir() yields "/.config" and the
// feature store fails with "mkdir /.config: permission denied". Resolution must test candidates.
func TestResolvePrefersTheMountedConfigRoot(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CLANKER_GUARD_CONFIG_DIR", root)
	t.Setenv("CLANKER_AI_DIR", "")
	got := Resolve("ai", "CLANKER_AI_DIR")
	if got != filepath.Join(root, "ai") {
		t.Fatalf("Resolve = %q, want %q", got, filepath.Join(root, "ai"))
	}
	if info, err := os.Stat(got); err != nil || !info.IsDir() {
		t.Fatalf("directory was not created: %v", err)
	}
}

// With no config root, the directory the deployment already uses for auth is the next best place.
func TestResolveFallsBackToTheAuthDirectory(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "auth.json")
	if err := os.WriteFile(authFile, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CLANKER_GUARD_CONFIG_DIR", "")
	t.Setenv("CLANKER_AI_DIR", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	home := t.TempDir() // overwrite HOME with something writable so UserConfigDir wins first
	t.Setenv("HOME", home)
	t.Setenv("CLANKER_GUARD_AUTH_FILE", authFile)

	got := Resolve("automation", "CLANKER_AUTOMATION_DIR")
	// Either the user config dir (HOME is writable) or the auth directory is acceptable; what
	// matters is that it is absolute, writable and not "/.config".
	if !filepath.IsAbs(got) || strings.HasPrefix(got, "/.config") {
		t.Fatalf("Resolve = %q", got)
	}
	if err := EnsureDir(got); err != nil {
		t.Fatalf("resolved directory is not writable: %v", err)
	}
}

// An explicit per-feature environment variable always wins.
func TestResolveHonoursTheFeatureOverride(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "custom-ai")
	t.Setenv("CLANKER_AI_DIR", dir)
	if got := Resolve("ai", "CLANKER_AI_DIR"); got != dir {
		t.Fatalf("Resolve = %q, want %q", got, dir)
	}
}

// Errors must name the path and the way out, not just "permission denied".
func TestEnsureDirErrorIsActionable(t *testing.T) {
	err := EnsureDir("/proc/clanker-guard-should-not-exist")
	if err == nil {
		t.Fatal("expected an error for an unwritable location")
	}
	msg := err.Error()
	if !strings.Contains(msg, "CLANKER_GUARD_CONFIG_DIR") || !strings.Contains(msg, "/proc/") {
		t.Fatalf("error is not actionable: %s", msg)
	}
}
