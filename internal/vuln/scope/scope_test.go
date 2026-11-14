package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeScope(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "scope.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadValidScope(t *testing.T) {
	path := writeScope(t, `
name: lab-vlan
authorized_by: derek
authorized_at: 2026-11-13T12:00:00Z
targets:
  - 192.168.20.0/28
  - 192.168.65.13
ports: [22, 443]
max_hosts: 32
notes: internal lab
`)
	s, err := Load(path)
	if err != nil {
		t.Fatalf("valid scope rejected: %v", err)
	}
	if s.Name != "lab-vlan" || s.AuthorizedBy != "derek" || len(s.Targets) != 2 {
		t.Fatalf("scope not parsed: %+v", s)
	}
	if !Allows(s, "192.168.20.5") || !Allows(s, "192.168.65.13") {
		t.Fatal("authorised targets rejected")
	}
	if Allows(s, "192.168.20.200") || Allows(s, "8.8.8.8") {
		t.Fatal("out-of-scope address allowed")
	}
}

func TestScopeRequiresAuthorisation(t *testing.T) {
	path := writeScope(t, `
name: no-approval
targets: [192.168.20.0/30]
`)
	if _, err := Load(path); err == nil {
		t.Fatal("scope without authorized_by/authorized_at must be rejected")
	}

	path = writeScope(t, `
name: public
authorized_by: someone
authorized_at: 2026-11-13T12:00:00Z
targets: [8.8.8.8]
`)
	if _, err := Load(path); err == nil {
		t.Fatal("public target must require allow_public_addresses")
	}
}

func TestScopeBoundsExpansion(t *testing.T) {
	if _, err := Validate(File{
		Name:         "too-big",
		AuthorizedBy: "derek",
		AuthorizedAt: time.Now(),
		Targets:      []string{"10.0.0.0/8"},
		MaxHosts:     16,
	}); err == nil {
		t.Fatal("scope larger than max_hosts must be rejected")
	}
}

func TestExpiredScopeIsRejected(t *testing.T) {
	_, err := Validate(File{
		Name:         "expired",
		AuthorizedBy: "derek",
		AuthorizedAt: time.Now().Add(-48 * time.Hour),
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		Targets:      []string{"192.168.20.0/28"},
	})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected an expiry error, got %v", err)
	}
}

func TestScopeWithFutureExpiryIsAccepted(t *testing.T) {
	sc, err := Validate(File{
		Name:         "temporary",
		AuthorizedBy: "derek",
		AuthorizedAt: time.Now().Add(-time.Hour),
		ExpiresAt:    time.Now().Add(24 * time.Hour),
		Targets:      []string{"127.0.0.1"},
	})
	if err != nil {
		t.Fatalf("future expiry should be valid: %v", err)
	}
	if sc.ExpiresAt.IsZero() {
		t.Fatal("expiry should be carried into the normalised scope")
	}
}
