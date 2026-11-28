// Package configdir resolves a writable directory for Clanker Guard's own state.
//
// The obvious answer — os.UserConfigDir() — is wrong in a container: with HOME unset it errors,
// and with HOME="/" it returns "/.config", which a non-root process cannot create. Both used to
// surface as "create AI config dir: mkdir /.config: permission denied" on a page that could not
// otherwise be used.
//
// The order here is deliberate: an explicit environment override wins, then the config root the
// deployment already mounted for auth and integration files, then the user's config directory,
// and only then a temporary location — with the promise that every candidate is *checked* for
// writability rather than assumed.
package configdir

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Resolve returns a writable directory for the named feature ("ai", "automation").
//
// Each candidate is attempted with MkdirAll; the first that works wins. The returned string is
// always absolute, so an error later names a real path instead of ".config".
func Resolve(feature string, featureEnv string) string {
	for _, candidate := range candidates(feature, featureEnv) {
		if candidate == "" || !filepath.IsAbs(candidate) {
			continue
		}
		if err := os.MkdirAll(candidate, 0o700); err == nil {
			return candidate
		}
	}
	// Nothing worked. Return an absolute path under the temp directory so the failure the
	// caller reports is honest and actionable rather than a stray relative directory.
	return filepath.Join(os.TempDir(), "clanker-guard", feature)
}

func candidates(feature, featureEnv string) []string {
	var out []string
	if featureEnv != "" {
		if v := strings.TrimSpace(os.Getenv(featureEnv)); v != "" {
			out = append(out, v)
		}
	}
	if root := strings.TrimSpace(os.Getenv("CLANKER_GUARD_CONFIG_DIR")); root != "" {
		out = append(out, filepath.Join(root, feature))
	}
	if dir, err := os.UserConfigDir(); err == nil && dir != "" {
		out = append(out, filepath.Join(dir, "clanker-guard", feature))
	}
	// The files this deployment already writes (auth, GitLab integration) live in the mounted
	// config directory; a feature directory beside them inherits the same permissions.
	for _, envKey := range []string{"CLANKER_GUARD_AUTH_FILE", "CLANKER_GUARD_GITLAB_FILE"} {
		if p := strings.TrimSpace(os.Getenv(envKey)); p != "" {
			out = append(out, filepath.Join(filepath.Dir(p), feature))
		}
	}
	if home := strings.TrimSpace(os.Getenv("HOME")); home != "" && home != "/" {
		out = append(out, filepath.Join(home, ".config", "clanker-guard", feature))
	}
	return out
}

// EnsureDir creates dir if needed and reports an actionable error naming the path.
func EnsureDir(dir string) error {
	if strings.TrimSpace(dir) == "" {
		return fmt.Errorf("no directory configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot create %s: %w — set CLANKER_GUARD_CONFIG_DIR to a writable directory, "+
			"or mount one for this feature", dir, err)
	}
	return nil
}
