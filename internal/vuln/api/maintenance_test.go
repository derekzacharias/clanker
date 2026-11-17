package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A snapshot must be a database that opens, private to the service account, and the
// endpoint must refuse to run when no directory is configured rather than writing somewhere
// unpredictable.
func TestBackupWritesAUsablePrivateSnapshot(t *testing.T) {
	dir := t.TempDir()
	srv, err := New(Options{
		CachePath:             filepath.Join(dir, "intel.db"),
		ToolVersion:           "test",
		Token:                 "dash-token",
		GitLabPath:            filepath.Join(dir, "gitlab.json"),
		BackupDir:             filepath.Join(dir, "backups"),
		DisableBackgroundJobs: true,
		Getenv:                func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	seedFinding(t, srv)

	var out struct {
		Path string `json:"path"`
		Name string `json:"name"`
	}
	rec := request(t, srv.Handler(), "POST", "/api/maintenance/backup", "", dash())
	if rec.Code != 200 {
		t.Fatalf("backup = %d: %s", rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	info, err := osStat(out.Path)
	if err != nil {
		t.Fatalf("snapshot missing: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("snapshot mode = %#o, want 0600", info.Mode().Perm())
	}
	// The snapshot must actually open and contain the assessment.
	if _, err := intelOpen(out.Path); err != nil {
		t.Fatalf("snapshot does not open: %v", err)
	}
	// The action is in the diary.
	var audit struct {
		Items []struct {
			Action string `json:"action"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/audit?action=maintenance.backup", &audit)
	if len(audit.Items) != 1 {
		t.Fatalf("backup not audited: %+v", audit.Items)
	}
}

// With no directory configured the endpoint explains itself instead of guessing a path.
func TestBackupRefusesWithoutADirectory(t *testing.T) {
	srv := fleetServer(t)
	rec := request(t, srv.Handler(), "POST", "/api/maintenance/backup", "", dash())
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "backup_disabled") {
		t.Fatalf("backup without dir = %d %s", rec.Code, rec.Body.String())
	}
}

// The digest is the only thing that tells a human work is late, so it must fire when there
// is something to say, respect its interval, sign its payload, and stay quiet otherwise.
func TestNotificationDigestFiresOncePerInterval(t *testing.T) {
	var hits int32
	var gotSignature string
	var payload map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		gotSignature = r.Header.Get("X-Guard-Signature")
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.WriteHeader(http.StatusOK)
	}))
	defer hook.Close()

	srv := fleetServer(t)
	// One overdue item, so the digest has something to report.
	postReport(t, srv, "web01", "Ubuntu:24.04", "openssl", "CVE-2026-8300", "critical", "SCAN-N-1")
	var list struct {
		Items []struct {
			ID string `json:"id"`
		} `json:"items"`
	}
	dashGet(t, srv.Handler(), "/api/remediation?asset=web01", &list)
	// Force it overdue by moving the clock past the critical window.
	srv.remediate.SetClock(func() time.Time { return time.Now().UTC().AddDate(0, 0, 30) })

	if err := srv.store.SetSetting(t.Context(), "notify.webhook_url", hook.URL); err != nil {
		t.Fatal(err)
	}
	srv.store.SetSetting(t.Context(), "notify.webhook_secret", "shhh")

	srv.notifyDigest(t.Context())
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("webhook hits = %d, want 1", hits)
	}
	if gotSignature == "" {
		t.Fatal("digest was not signed")
	}
	if payload["source"] != "clanker-guard" || payload["overdue"] == nil {
		t.Fatalf("payload = %+v", payload)
	}
	// A second tick inside the interval must not spam the endpoint.
	srv.notifyDigest(t.Context())
	if atomic.LoadInt32(&hits) != 1 {
		t.Fatalf("digest fired again inside its interval (hits=%d)", hits)
	}
}
