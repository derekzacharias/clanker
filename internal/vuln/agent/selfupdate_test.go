package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestRelease serves a fake GitHub release API + download directory.
func newTestRelease(t *testing.T, version string, assets map[string][]byte, key ed25519.PrivateKey) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/repos/acme/clanker-guard-agent/releases/latest", func(w http.ResponseWriter, r *http.Request) {
		var names []map[string]any
		for name := range assets {
			names = append(names, map[string]any{
				"name": name, "browser_download_url": "/dl/" + version + "/" + name,
			})
		}
		fmt.Fprintf(w, `{"tag_name": %q, "assets": %v}`, version, mustJSON(names))
	})

	serve := func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		name := parts[len(parts)-1]
		if data, ok := assets[name]; ok {
			w.Write(data)
			return
		}
		http.NotFound(w, r)
	}
	mux.HandleFunc("/dl/", serve)
	mux.HandleFunc("/acme/clanker-guard-agent/releases/download/", serve)

	srv := httptest.NewServer(mux)
	return srv, srv.URL + "/repos"
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// signedManifest builds SHA256SUMS + a valid signature for the assets.
func signedManifest(t *testing.T, key ed25519.PrivateKey, assets map[string][]byte) (manifest, sig []byte) {
	t.Helper()
	var b strings.Builder
	for name, data := range assets {
		sum := sha256.Sum256(data)
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), name)
	}
	manifest = []byte(b.String())
	sig = ed25519.Sign(key, manifest)
	return manifest, sig
}

func testUpdater(srv *httptest.Server, key ed25519.PrivateKey) *Updater {
	pub, _ := key.Public().(ed25519.PublicKey)
	return &Updater{
		HTTP:        srv.Client(),
		ReleaseBase: srv.URL + "/acme/clanker-guard-agent/releases",
		Version:     "0.2.4",
		OS:          "linux",
		Arch:        "amd64",
		PubKey:      base64.StdEncoding.EncodeToString(pub),
		githubAPI:   srv.URL,
		Logf:        func(string, ...any) {},
		RestartWatch: func(exePath, configPath string) error {
			return nil
		},
		Swapper: func(temp, target string) error {
			return os.Rename(temp, target)
		},
	}
}

func TestUpdaterInstallsVerifiedRelease(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("#!/bin/sh\necho new agent\n")
	assets := map[string][]byte{"clanker-guard-agent_linux_amd64": binary}
	manifest, sig := signedManifest(t, priv, assets)
	assets["SHA256SUMS"] = manifest
	assets["SHA256SUMS.sig"] = sig
	srv, _ := newTestRelease(t, "v0.2.5", assets, priv)
	defer srv.Close()

	target := filepath.Join(t.TempDir(), "clanker-guard-agent")
	up := testUpdater(srv, priv)
	res, err := up.Update(context.Background(), target, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Updated || res.Latest != "0.2.5" {
		t.Fatalf("update result: %+v", res)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(binary) {
		t.Fatalf("target not replaced: %v %q", err, got)
	}
	// No staging files may remain.
	entries, _ := os.ReadDir(filepath.Dir(target))
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".clanker-guard-agent-update-") {
			t.Fatalf("staging file left behind: %s", e.Name())
		}
	}
}

func TestUpdaterRefusesTamperedManifest(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("malicious")
	assets := map[string][]byte{"clanker-guard-agent_linux_amd64": binary}
	manifest, _ := signedManifest(t, priv, assets)
	// Tamper with the manifest AFTER signing.
	tampered := []byte(strings.Replace(string(manifest), "a", "b", 1))
	assets["SHA256SUMS"] = tampered
	assets["SHA256SUMS.sig"], _ = signedManifest(t, priv, assets)
	assets["SHA256SUMS.sig"] = ed25519.Sign(priv, manifest) // the OLD signature
	srv, _ := newTestRelease(t, "v0.2.5", assets, priv)
	defer srv.Close()

	up := testUpdater(srv, priv)
	res, err := up.Update(context.Background(), filepath.Join(t.TempDir(), "agent"), "")
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("tampered manifest must be refused: %v", err)
	}
	if res.Updated {
		t.Fatal("nothing may be installed on a failed verification")
	}
}

func TestUpdaterRefusesMismatchedBinary(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	binary := []byte("the real binary")
	assets := map[string][]byte{"clanker-guard-agent_linux_amd64": binary}
	manifest, sig := signedManifest(t, priv, assets)
	assets["SHA256SUMS"] = manifest
	assets["SHA256SUMS.sig"] = sig
	// Serve a DIFFERENT binary under the same name.
	evil := map[string][]byte{"clanker-guard-agent_linux_amd64": []byte("swapped by the origin")}
	evil["SHA256SUMS"] = manifest
	evil["SHA256SUMS.sig"] = sig
	srv, _ := newTestRelease(t, "v0.2.5", evil, priv)
	defer srv.Close()

	up := testUpdater(srv, priv)
	_, err = up.Update(context.Background(), filepath.Join(t.TempDir(), "agent"), "")
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("mismatched binary must be refused: %v", err)
	}
}

func TestUpdaterSkipsWhenCurrentIsNewer(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	srv, _ := newTestRelease(t, "v0.2.4", nil, priv)
	defer srv.Close()
	up := testUpdater(srv, priv)
	up.Version = "0.2.5"
	res, err := up.Check(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Reason, "already on") {
		t.Fatalf("newer running version must skip: %+v", res)
	}
}

func TestUpdaterDevBuildsNeverUpdate(t *testing.T) {
	up := &Updater{Version: "dev"}
	res, err := up.Check(context.Background())
	if err != nil || !strings.Contains(res.Reason, "dev build") {
		t.Fatalf("dev builds must not self-update: %+v %v", res, err)
	}
}

func TestChecksumForWrongPlatformRefuses(t *testing.T) {
	up := &Updater{OS: "windows", Arch: "amd64"}
	manifest := []byte("abc123  clanker-guard-agent_linux_amd64\n")
	if _, err := up.checksumFor(manifest); err == nil {
		t.Fatal("a manifest without this platform's asset must be refused")
	}
}
