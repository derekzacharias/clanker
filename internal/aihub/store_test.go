package aihub

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

func TestCredentialRoundTripIsEncryptedAtRest(t *testing.T) {
	s := newStore(t)
	secret := "sk-test-abcdef1234567890"
	if err := s.SetCredential("openai", secret); err != nil {
		t.Fatalf("SetCredential: %v", err)
	}
	got, ok, err := s.Credential("openai")
	if err != nil || !ok || got != secret {
		t.Fatalf("Credential() = %q, %v, %v", got, ok, err)
	}

	raw, err := os.ReadFile(filepath.Join(s.Dir(), "credentials.json"))
	if err != nil {
		t.Fatalf("read credentials file: %v", err)
	}
	if strings.Contains(string(raw), secret) {
		t.Fatal("the credential is stored in plaintext on disk")
	}
	info, err := os.Stat(filepath.Join(s.Dir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("credentials file mode = %o, want 600", perm)
	}
	keyInfo, err := os.Stat(filepath.Join(s.Dir(), "master.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := keyInfo.Mode().Perm(); perm != 0o600 {
		t.Fatalf("master key mode = %o, want 600", perm)
	}
}

func TestCredentialInfoNeverReturnsTheSecret(t *testing.T) {
	s := newStore(t)
	if err := s.SetCredential("anthropic", "sk-ant-super-secret-value"); err != nil {
		t.Fatal(err)
	}
	info, err := s.CredentialInfo("anthropic")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Configured || info.Source != "file" {
		t.Fatalf("unexpected info: %+v", info)
	}
	if strings.Contains(info.Mask, "super-secret") {
		t.Fatalf("mask leaks the secret: %q", info.Mask)
	}
	if !strings.HasSuffix(info.Mask, "alue") {
		t.Fatalf("mask should keep the last characters readable, got %q", info.Mask)
	}
}

func TestCredentialDeleteAndEnvFallback(t *testing.T) {
	s := newStore(t)
	if err := s.SetCredential("openai", "sk-file"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCredential("openai"); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Credential("openai"); ok {
		t.Fatal("deleted credential still resolves")
	}

	t.Setenv("CLANKER_AI_KEY_OPENAI", "sk-from-env")
	info, err := s.CredentialInfo("openai")
	if err != nil {
		t.Fatal(err)
	}
	if !info.Configured || info.Source != "environment" {
		t.Fatalf("environment fallback not reported: %+v", info)
	}
	secret, ok, err := s.QuerySecret("openai")
	if err != nil || !ok || secret != "sk-from-env" {
		t.Fatalf("QuerySecret = %q %v %v", secret, ok, err)
	}
}

func TestMasterKeyFromEnvironment(t *testing.T) {
	dir := t.TempDir()
	// 32 zero bytes, base64.
	t.Setenv("CLANKER_AI_MASTER_KEY", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetCredential("openai", "sk-x"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "master.key")); !os.IsNotExist(err) {
		t.Fatal("a key file must not be written when the key comes from the environment")
	}
	if got, ok, _ := s.Credential("openai"); !ok || got != "sk-x" {
		t.Fatalf("round trip with env key failed: %q %v", got, ok)
	}
}

func TestMasterKeyRejectsBadLength(t *testing.T) {
	t.Setenv("CLANKER_AI_MASTER_KEY", "c2hvcnQ=") // "short"
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetCredential("openai", "sk-x"); err == nil {
		t.Fatal("a short master key must be refused")
	}
}

func TestSettingsValidation(t *testing.T) {
	s := newStore(t)
	if _, err := s.SaveSettings(Settings{Provider: "not-a-provider"}); err == nil {
		t.Fatal("unknown providers must be refused")
	}
	if _, err := s.SaveSettings(Settings{Provider: "bedrock"}); err == nil {
		t.Fatal("unimplemented providers must be refused")
	}
	if _, err := s.SaveSettings(Settings{Provider: "ollama"}); err == nil {
		t.Fatal("a provider that needs an endpoint must require one")
	}
	ok, err := s.SaveSettings(Settings{Provider: "ollama", Endpoint: "http://127.0.0.1:11434", Model: "llama3.1"})
	if err != nil {
		t.Fatalf("valid settings refused: %v", err)
	}
	if ok.UpdatedAt == nil {
		t.Fatal("saved settings should carry a timestamp")
	}
	loaded, err := s.LoadSettings()
	if err != nil || loaded.Model != "llama3.1" {
		t.Fatalf("LoadSettings = %+v, %v", loaded, err)
	}
}

func TestCatalogStaleness(t *testing.T) {
	s := newStore(t)
	if _, err := s.SaveCatalog("openai", []Model{{ID: "gpt-4o", Provider: "openai"}}); err != nil {
		t.Fatal(err)
	}
	cat, ok, err := s.LoadCatalog("openai")
	if err != nil || !ok {
		t.Fatalf("LoadCatalog: %v %v", ok, err)
	}
	if cat.Stale {
		t.Fatal("a fresh catalog must not be marked stale")
	}
	// A failure keeps the list but marks it stale and records why.
	marked, existed := s.MarkCatalogError("openai", "provider unreachable")
	if !existed || !marked.Stale || marked.Error == "" {
		t.Fatalf("MarkCatalogError = %+v, %v", marked, existed)
	}
}
