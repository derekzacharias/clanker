package api

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
)

func TestNVDKeyLifecycle(t *testing.T) {
	srv, cachePath := newTestServer(t)

	// Initially not configured.
	var get struct {
		Configured bool `json:"configured"`
	}
	if rec := doJSON(t, srv.Handler(), "GET", "/api/settings/nvd-key", nil, &get); rec.Code != http.StatusOK {
		t.Fatalf("get: %d", rec.Code)
	}
	if get.Configured {
		t.Fatal("a fresh server has no key configured")
	}

	// Save a key.
	const key = "DDA309D5-8843-4FCB-B738-BE3557C94031"
	rec := doJSON(t, srv.Handler(), "PUT", "/api/settings/nvd-key",
		map[string]string{"api_key": key}, &get)
	if rec.Code != http.StatusOK || !get.Configured {
		t.Fatalf("put: %d %+v", rec.Code, get)
	}
	// The response must never contain the key.
	if strings.Contains(rec.Body.String(), key) {
		t.Fatalf("the key leaked into the save response: %s", rec.Body.String())
	}
	// The stored value is used by the sync path and is never exposed.
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		t.Fatal(err)
	}
	got, ok, err := store.Setting(context.Background(), "nvd_api_key")
	store.Close()
	if err != nil || !ok || got != key {
		t.Fatalf("stored key mismatch: %q %v %v", got, ok, err)
	}

	// The feeds endpoint reports only the boolean, never the key.
	var feeds struct {
		Configured bool `json:"nvd_api_key_configured"`
	}
	rec = doJSON(t, srv.Handler(), "GET", "/api/feeds", nil, &feeds)
	if rec.Code != http.StatusOK || !feeds.Configured {
		t.Fatalf("feeds: %d %+v", rec.Code, feeds)
	}
	if strings.Contains(rec.Body.String(), key) {
		t.Fatalf("the key leaked into the feeds response")
	}

	// Clearing removes it and the audit diary records both actions.
	if rec := doJSON(t, srv.Handler(), "PUT", "/api/settings/nvd-key",
		map[string]string{"api_key": ""}, &get); rec.Code != http.StatusOK || get.Configured {
		t.Fatalf("clear: %d %+v", rec.Code, get)
	}
	entries, err := srv.store.ListAudit(context.Background(), 50, "", "")
	if err != nil {
		t.Fatal(err)
	}
	set, cleared := false, false
	for _, e := range entries {
		switch e.Action {
		case "nvd_api_key_set":
			set = true
		case "nvd_api_key_cleared":
			cleared = true
		}
		if strings.Contains(e.Detail, key) || strings.Contains(e.Target, key) {
			t.Fatalf("the key leaked into the audit trail")
		}
	}
	if !set || !cleared {
		t.Fatalf("audit entries missing: set=%v cleared=%v", set, cleared)
	}
}

func TestNVDKeyRejectsOversizedValue(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := doJSON(t, srv.Handler(), "PUT", "/api/settings/nvd-key",
		map[string]string{"api_key": strings.Repeat("x", 128)}, nil)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized key must be refused: %d", rec.Code)
	}
}
