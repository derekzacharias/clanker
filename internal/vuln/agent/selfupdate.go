package agent

// Self-update.
//
// The agent can replace itself, but only along one carefully bounded path:
//
//   - updates come exclusively from the pinned release origin (the same
//     GitHub releases directory the installers download from). The server is
//     never part of the update path: it cannot ask the endpoint to update,
//     and it cannot serve an update.
//   - every update is verified twice: the SHA256SUMS manifest must carry a
//     valid Ed25519 signature from the pinned public key, and the downloaded
//     binary must match the SHA-256 published for this platform.
//   - any failed step leaves the running version in place and records why.
//   - automatic updates are opt-in per endpoint (AutoUpdate in the agent
//     config, set at enroll time). `clanker-guard-agent update` always works
//     when an operator asks.
//   - the swap is atomic where the OS allows it (rename), and on Windows a
//     detached helper performs the rename after the running process exits.

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/version"
)

// DefaultReleaseBase is where release artifacts are published. Forks override
// it at build time: -ldflags "-X github.com/bgdnvk/clanker/internal/vuln/agent.DefaultReleaseBase=...".
var DefaultReleaseBase = "https://github.com/derekzacharias/clanker-guard-agent/releases"

// currentVersion is the build's own version, injected by the release build
// (main.version at build time). "dev" builds are never older than a release
// and therefore never self-update.
var currentVersion = "dev"

// pinnedReleasePubKey is the public half of the release signing key. It is
// public by definition, safe to embed, and it is what makes a compromised
// release origin unable to swap both the artifacts and their checksums.
const pinnedReleasePubKey = "MCowBQYDK2VwAyEAddak3m8jw7qjzUpeyOrogWrFP6NxuF5MHv7Dj56fqx8="

// Updater downloads and verifies a newer agent release.
type Updater struct {
	HTTP *http.Client
	// ReleaseBase overrides the pinned origin (default DefaultReleaseBase).
	ReleaseBase string
	// Version is the running version (default currentVersion).
	Version string
	// PubKey overrides the pinned verification key (tests).
	PubKey string
	// githubAPI overrides the GitHub API base (tests).
	githubAPI string
	// OS/Arch override the build platform (tests).
	OS, Arch string
	// Logf receives progress lines (default: discard).
	Logf func(format string, args ...any)
	// RestartWatch restarts the watcher after a successful swap (defaults to
	// a detached start on this platform).
	RestartWatch func(exePath, configPath string) error
	// Swapper replaces the running binary (platform-specific).
	Swapper func(temp, target string) error
}

// UpdateResult reports what one update attempt did.
type UpdateResult struct {
	// Updated is true when a newer version was installed.
	Updated bool
	// Current is the previously running version.
	Current string
	// Latest is the newest published version ("" when it could not be
	// resolved).
	Latest string
	// Reason explains a no-op or failure in operator terms.
	Reason string
}

func (u *Updater) logf(format string, args ...any) {
	if u.Logf != nil {
		u.Logf(format, args...)
	}
}

func (u *Updater) base() string {
	if strings.TrimSpace(u.ReleaseBase) != "" {
		return strings.TrimRight(strings.TrimSpace(u.ReleaseBase), "/")
	}
	return strings.TrimRight(DefaultReleaseBase, "/")
}

func (u *Updater) runningVersion() string {
	if strings.TrimSpace(u.Version) != "" {
		return strings.TrimSpace(u.Version)
	}
	return currentVersion
}

func (u *Updater) client() *http.Client {
	if u.HTTP != nil {
		return u.HTTP
	}
	return &http.Client{Timeout: 60 * time.Second}
}

// assetName is the artifact name for this platform.
func (u *Updater) assetName() string {
	name := fmt.Sprintf("clanker-guard-agent_%s_%s", u.os(), u.arch())
	if u.os() == "windows" {
		name += ".exe"
	}
	return name
}

func (u *Updater) os() string {
	if u.OS != "" {
		return u.OS
	}
	return runtime.GOOS
}

func (u *Updater) arch() string {
	if u.Arch != "" {
		return u.Arch
	}
	return runtime.GOARCH
}

// releaseInfo is the part of GitHub's release JSON the updater reads.
type releaseInfo struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name               string `json:"name"`
		BrowserDownloadURL string `json:"browser_download_url"`
	} `json:"assets"`
}

// latestRelease resolves the newest published release for the pinned origin.
func (u *Updater) latestRelease(ctx context.Context) (releaseInfo, error) {
	base := u.base()
	// The base is https://github.com/<owner>/<repo>/releases[/download/...];
	// parse it as a URL so a self-hosted mirror keeps the same shape.
	idx := strings.Index(base, "://")
	rest := base
	if idx >= 0 {
		rest = base[idx+3:]
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[i+1:]
	}
	parts := strings.Split(rest, "/")
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return releaseInfo{}, fmt.Errorf("release base %q is not a GitHub releases URL", base)
	}
	owner, repo := parts[0], parts[1]
	apiBase := u.githubAPI
	if apiBase == "" {
		apiBase = "https://api.github.com"
	}
	api := fmt.Sprintf("%s/repos/%s/%s/releases/latest", apiBase, owner, repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, api, nil)
	if err != nil {
		return releaseInfo{}, err
	}
	req.Header.Set("User-Agent", "clanker-guard-agent/selfupdate")
	res, err := u.client().Do(req)
	if err != nil {
		return releaseInfo{}, fmt.Errorf("could not reach the release origin: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return releaseInfo{}, fmt.Errorf("release lookup returned HTTP %d", res.StatusCode)
	}
	var info releaseInfo
	if err := json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&info); err != nil {
		return releaseInfo{}, fmt.Errorf("release lookup returned invalid JSON: %w", err)
	}
	if info.TagName == "" {
		return releaseInfo{}, errors.New("release lookup returned no tag")
	}
	return info, nil
}

// downloadURL builds the download URL for one asset of the latest release.
func (u *Updater) downloadURL(tag, asset string) string {
	return fmt.Sprintf("%s/download/%s/%s", u.base(), tag, asset)
}

func (u *Updater) get(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "clanker-guard-agent/selfupdate")
	res, err := u.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("download failed: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download of %s returned HTTP %d", url, res.StatusCode)
	}
	return io.ReadAll(io.LimitReader(res.Body, 128<<20))
}

// verifyManifest checks the Ed25519 signature over SHA256SUMS.
func (u *Updater) verifyManifest(manifest, sig []byte) error {
	keyB64 := pinnedReleasePubKey
	if strings.TrimSpace(u.PubKey) != "" {
		keyB64 = strings.TrimSpace(u.PubKey)
	}
	rawKey, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return fmt.Errorf("pinned release key is invalid: %w", err)
	}
	if len(rawKey) != ed25519.PublicKeySize {
		return errors.New("pinned release key has the wrong size")
	}
	if !ed25519.Verify(ed25519.PublicKey(rawKey), manifest, sig) {
		return errors.New("SHA256SUMS signature verification failed; refusing the update")
	}
	return nil
}

// checksumFor extracts the published SHA-256 for this platform's asset.
func (u *Updater) checksumFor(manifest []byte) (string, error) {
	want := u.assetName()
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[1] != want {
			continue
		}
		sum, err := hex.DecodeString(fields[0])
		if err != nil || len(sum) != sha256.Size {
			continue
		}
		return strings.ToLower(fields[0]), nil
	}
	return "", fmt.Errorf("the manifest does not list %s; this platform may not be published", want)
}

// Check resolves the latest version and reports whether an update exists.
func (u *Updater) Check(ctx context.Context) (UpdateResult, error) {
	res := UpdateResult{Current: u.runningVersion()}
	if res.Current == "dev" {
		res.Reason = "dev build; self-update is disabled"
		return res, nil
	}
	info, err := u.latestRelease(ctx)
	if err != nil {
		return res, err
	}
	res.Latest = strings.TrimPrefix(info.TagName, "v")
	cmp, err := version.Compare("", res.Current, res.Latest)
	if err != nil {
		res.Reason = fmt.Sprintf("versions are not comparable (%s vs %s)", res.Current, res.Latest)
		return res, nil
	}
	if cmp >= 0 {
		res.Reason = fmt.Sprintf("already on %s (latest published: %s)", res.Current, res.Latest)
		return res, nil
	}
	return res, nil
}

// Update runs the full update flow and swaps the binary when a verified
// newer release exists.
func (u *Updater) Update(ctx context.Context, targetExe, configPath string) (UpdateResult, error) {
	res := UpdateResult{Current: u.runningVersion()}
	if res.Current == "dev" {
		res.Reason = "dev build; self-update is disabled"
		return res, nil
	}
	info, err := u.latestRelease(ctx)
	if err != nil {
		return res, err
	}
	res.Latest = strings.TrimPrefix(info.TagName, "v")
	cmp, err := version.Compare("", res.Current, res.Latest)
	if err != nil {
		res.Reason = fmt.Sprintf("versions are not comparable (%s vs %s)", res.Current, res.Latest)
		return res, nil
	}
	if cmp >= 0 {
		res.Reason = fmt.Sprintf("already on %s (latest published: %s)", res.Current, res.Latest)
		return res, nil
	}

	u.logf("update: %s -> %s", res.Current, res.Latest)
	manifest, err := u.get(ctx, u.downloadURL(info.TagName, "SHA256SUMS"))
	if err != nil {
		return res, err
	}
	sig, err := u.get(ctx, u.downloadURL(info.TagName, "SHA256SUMS.sig"))
	if err != nil {
		return res, err
	}
	if err := u.verifyManifest(manifest, sig); err != nil {
		return res, err
	}
	wantSum, err := u.checksumFor(manifest)
	if err != nil {
		return res, err
	}

	var binaryURL string
	for _, a := range info.Assets {
		if a.Name == u.assetName() {
			binaryURL = a.BrowserDownloadURL
		}
	}
	if binaryURL == "" {
		// The release may serve assets outside the API listing; fall back to
		// the predictable download URL.
		binaryURL = u.downloadURL(info.TagName, u.assetName())
	}
	// Mirrors may publish relative asset URLs; resolve them against the
	// release origin (GitHub itself always returns absolute URLs).
	if !strings.HasPrefix(binaryURL, "http://") && !strings.HasPrefix(binaryURL, "https://") {
		if parsed, err := url.Parse(u.base()); err == nil {
			binaryURL = parsed.Scheme + "://" + parsed.Host + "/" + strings.TrimLeft(binaryURL, "/")
		}
	}
	binary, err := u.get(ctx, binaryURL)
	if err != nil {
		return res, err
	}
	sum := sha256.Sum256(binary)
	if hex.EncodeToString(sum[:]) != wantSum {
		return res, fmt.Errorf("downloaded binary does not match its published SHA-256; refusing the update")
	}

	if err := u.swap(binary, targetExe, configPath); err != nil {
		return res, err
	}
	res.Updated = true
	u.logf("update: replaced %s with %s", targetExe, res.Latest)
	return res, nil
}

// RunSwapHelper performs the deferred rename the Windows updater needs: the
// running executable is locked, so the staged binary runs this loop until the
// previous process has exited and the rename succeeds. It is invoked as
// `clanker-guard-agent update-swap --from staged --to target`.
func RunSwapHelper(from, to string) error {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		err := os.Rename(from, to)
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("could not replace %s within 2 minutes: %v", to, err)
		}
		time.Sleep(time.Second)
	}
}

// swap writes the verified binary next to the running one and replaces it.
func (u *Updater) swap(binary []byte, targetExe, configPath string) error {
	dir := filepath.Dir(targetExe)
	tmp, err := os.CreateTemp(dir, ".clanker-guard-agent-update-*")
	if err != nil {
		return fmt.Errorf("stage update: %w", err)
	}
	tmpName := tmp.Name()
	if err := tmp.Chmod(0o755); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return err
	}
	if _, err := tmp.Write(binary); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("stage update: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}

	swapper := u.Swapper
	if swapper == nil {
		swapper = defaultSwapper
	}
	if err := swapper(tmpName, targetExe); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("replace the running binary: %w", err)
	}

	restart := u.RestartWatch
	if restart == nil {
		restart = RestartWatcherDetached
	}
	if err := restart(targetExe, configPath); err != nil {
		u.logf("update: the new binary is in place but the watcher did not restart: %v", err)
	}
	return nil
}
