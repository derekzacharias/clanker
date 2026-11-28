package aihub

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/configdir"
)

// Store persists AI settings, credentials and the model catalog.
//
// Everything here is server-side. There is no method that returns a credential in a form
// a browser could read: CredentialInfo returns a mask, and Credential (the plaintext
// accessor) is used only by the inference client in this package.
type Store struct {
	dir string
	// keyPath/publicKey are injectable for tests.
	keyPath string
	key     []byte
}

// DefaultDir resolves a writable directory, preferring the deployment's mounted config root.
//
// A container has no writable home, so os.UserConfigDir either errors or returns "/.config";
// configdir checks each candidate instead of trusting the first one, and never returns a
// relative path.
func DefaultDir() string {
	if p := strings.TrimSpace(os.Getenv("CLANKER_AI_DIR")); p != "" {
		return p
	}
	return configdir.Resolve("ai", "CLANKER_AI_DIR")
}

// Open prepares the store directory and loads the master key.
func Open(dir string) (*Store, error) {
	if strings.TrimSpace(dir) == "" {
		dir = DefaultDir()
	}
	if err := configdir.EnsureDir(dir); err != nil {
		return nil, fmt.Errorf("create AI config dir: %w", err)
	}
	s := &Store{dir: dir, keyPath: filepath.Join(dir, "master.key")}
	return s, nil
}

// Dir reports where the store lives (shown in the UI so an operator can back it up).
func (s *Store) Dir() string { return s.dir }

// ------------------------------------------------------------------ settings ---

// Settings is the non-secret AI configuration.
type Settings struct {
	// Provider is the selected provider id.
	Provider string `json:"provider"`
	// Model is the selected model id (or Azure deployment name).
	Model string `json:"model"`
	// Endpoint overrides the provider base URL (Azure, self-hosted Ollama).
	Endpoint string `json:"endpoint,omitempty"`
	// APIVersion is used by Azure.
	APIVersion string `json:"api_version,omitempty"`
	// AllowPreview lets preview/experimental models appear in the picker.
	AllowPreview bool `json:"allow_preview"`
	// LastTest records the most recent connection test so the UI can be honest about it.
	LastTestOK     *bool      `json:"last_test_ok,omitempty"`
	LastTestDetail string     `json:"last_test_detail,omitempty"`
	LastTestAt     *time.Time `json:"last_test_at,omitempty"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty"`
}

func (s *Store) settingsPath() string { return filepath.Join(s.dir, "settings.json") }

// LoadSettings reads the saved settings. A missing file is not an error.
func (s *Store) LoadSettings() (Settings, error) {
	var out Settings
	if err := readJSON(s.settingsPath(), &out); err != nil {
		return Settings{}, err
	}
	return out, nil
}

// SaveSettings validates and writes the settings atomically.
func (s *Store) SaveSettings(in Settings) (Settings, error) {
	in.Provider = strings.ToLower(strings.TrimSpace(in.Provider))
	in.Model = strings.TrimSpace(in.Model)
	in.Endpoint = strings.TrimRight(strings.TrimSpace(in.Endpoint), "/")
	in.APIVersion = strings.TrimSpace(in.APIVersion)

	if in.Provider != "" {
		p, ok := Lookup(in.Provider)
		if !ok {
			return Settings{}, fmt.Errorf("unknown provider %q", in.Provider)
		}
		if !p.Ready() {
			return Settings{}, fmt.Errorf("%s is not supported by this build: %s", p.Label, p.Notes)
		}
		if p.NeedsEndpoint && in.Endpoint == "" {
			return Settings{}, fmt.Errorf("%s needs an endpoint URL", p.Label)
		}
	}
	now := time.Now().UTC()
	in.UpdatedAt = &now
	if err := writeJSON(s.settingsPath(), in); err != nil {
		return Settings{}, err
	}
	return in, nil
}

// ClearTest forgets a previous connection result. Any settings change invalidates it:
// "connected" must describe the current configuration, not a previous one.
func (in Settings) ClearTest() Settings {
	in.LastTestOK = nil
	in.LastTestDetail = ""
	in.LastTestAt = nil
	return in
}

// ------------------------------------------------------------------ credentials ---

// sealedSecret is one credential as stored on disk.
type sealedSecret struct {
	Nonce      string    `json:"nonce"`
	Ciphertext string    `json:"ciphertext"`
	UpdatedAt  time.Time `json:"updated_at"`
}

type credentialFile struct {
	Version     int                     `json:"version"`
	Credentials map[string]sealedSecret `json:"credentials"`
}

func (s *Store) credentialsPath() string { return filepath.Join(s.dir, "credentials.json") }

// loadKey returns the master key, generating it on first use.
//
// The key comes from CLANKER_AI_MASTER_KEY when set (base64, 32 bytes) so a container can
// avoid writing key material to disk; otherwise it is generated once into master.key with
// mode 0600. Either way the key never leaves the server.
func (s *Store) loadKey() ([]byte, error) {
	if len(s.key) == 32 {
		return s.key, nil
	}
	if env := strings.TrimSpace(os.Getenv("CLANKER_AI_MASTER_KEY")); env != "" {
		raw, err := base64.StdEncoding.DecodeString(env)
		if err != nil || len(raw) != 32 {
			return nil, errors.New("CLANKER_AI_MASTER_KEY must be base64 of exactly 32 bytes")
		}
		s.key = raw
		return s.key, nil
	}
	if raw, err := os.ReadFile(s.keyPath); err == nil && len(raw) >= 32 {
		s.key = raw[:32]
		return s.key, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read AI master key: %w", err)
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate AI master key: %w", err)
	}
	if err := writeFile0600(s.keyPath, raw); err != nil {
		return nil, fmt.Errorf("write AI master key: %w", err)
	}
	s.key = raw
	return s.key, nil
}

func (s *Store) loadCredentials() (credentialFile, error) {
	file := credentialFile{Version: 1, Credentials: map[string]sealedSecret{}}
	if err := readJSON(s.credentialsPath(), &file); err != nil {
		return file, err
	}
	if file.Credentials == nil {
		file.Credentials = map[string]sealedSecret{}
	}
	return file, nil
}

// SetCredential encrypts and stores one provider credential.
func (s *Store) SetCredential(provider, secret string) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	secret = strings.TrimSpace(secret)
	if provider == "" {
		return errors.New("a provider is required")
	}
	if _, ok := Lookup(provider); !ok {
		return fmt.Errorf("unknown provider %q", provider)
	}
	if secret == "" {
		return errors.New("an API key is required")
	}
	key, err := s.loadKey()
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	sealed := gcm.Seal(nil, nonce, []byte(secret), []byte("clanker-ai:"+provider))

	file, err := s.loadCredentials()
	if err != nil {
		return err
	}
	file.Credentials[provider] = sealedSecret{
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(sealed),
		UpdatedAt:  time.Now().UTC(),
	}
	return writeJSON(s.credentialsPath(), file)
}

// Credential decrypts one credential. It is the only plaintext accessor and is
// package-internal by convention: nothing in the API layer calls it.
func (s *Store) Credential(provider string) (string, bool, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	file, err := s.loadCredentials()
	if err != nil {
		return "", false, err
	}
	entry, ok := file.Credentials[provider]
	if !ok {
		return "", false, nil
	}
	key, err := s.loadKey()
	if err != nil {
		return "", false, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", false, err
	}
	nonce, err := base64.StdEncoding.DecodeString(entry.Nonce)
	if err != nil {
		return "", false, fmt.Errorf("stored credential is corrupt")
	}
	sealed, err := base64.StdEncoding.DecodeString(entry.Ciphertext)
	if err != nil {
		return "", false, fmt.Errorf("stored credential is corrupt")
	}
	plain, err := gcm.Open(nil, nonce, sealed, []byte("clanker-ai:"+provider))
	if err != nil {
		return "", false, fmt.Errorf("stored credential cannot be decrypted (was the master key rotated?)")
	}
	return string(plain), true, nil
}

// DeleteCredential removes a provider credential.
func (s *Store) DeleteCredential(provider string) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	file, err := s.loadCredentials()
	if err != nil {
		return err
	}
	if _, ok := file.Credentials[provider]; !ok {
		return nil
	}
	delete(file.Credentials, provider)
	return writeJSON(s.credentialsPath(), file)
}

// CredentialInfo is what the API returns: presence and a mask, never the secret.
type CredentialInfo struct {
	Provider   string     `json:"provider"`
	Configured bool       `json:"configured"`
	Mask       string     `json:"mask,omitempty"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	// Source says where the secret came from so an operator is not surprised when
	// deleting a file entry does not remove an injected environment variable.
	Source string `json:"source,omitempty"`
}

// CredentialInfo describes a provider credential without revealing it.
func (s *Store) CredentialInfo(provider string) (CredentialInfo, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))
	info := CredentialInfo{Provider: provider}
	file, err := s.loadCredentials()
	if err != nil {
		return info, err
	}
	if entry, ok := file.Credentials[provider]; ok {
		info.Configured = true
		info.Source = "file"
		ts := entry.UpdatedAt
		info.UpdatedAt = &ts
		// Decrypt only to produce a stable mask; failures are reported as configured but
		// unmasked rather than leaking the error text to the client.
		if secret, ok, err := s.Credential(provider); err == nil && ok {
			info.Mask = maskSecret(secret)
		}
	}
	if env := envCredential(provider); env != "" {
		info.Configured = true
		info.Source = "environment"
		info.Mask = maskSecret(env)
	}
	return info, nil
}

// envCredential reads the per-provider environment fallback, so a deployment can inject a
// key without a settings file. Format: CLANKER_AI_KEY_<PROVIDER>.
func envCredential(provider string) string {
	key := "CLANKER_AI_KEY_" + strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(provider))
	return strings.TrimSpace(os.Getenv(key))
}

// maskSecret keeps the shape of a key visible without keeping the key.
func maskSecret(secret string) string {
	secret = strings.TrimSpace(secret)
	switch {
	case len(secret) == 0:
		return ""
	case len(secret) <= 8:
		return "••••"
	default:
		return "••••" + secret[len(secret)-4:]
	}
}

// ------------------------------------------------------------------ catalog cache ---

// Catalog is the cached model list for one provider.
type Catalog struct {
	Provider  string    `json:"provider"`
	Models    []Model   `json:"models"`
	FetchedAt time.Time `json:"fetched_at"`
	// Stale is computed at read time, never stored.
	Stale bool `json:"stale"`
	// Error is the last discovery failure, kept so the UI can explain stale data.
	Error string `json:"error,omitempty"`
}

func (s *Store) catalogPath(provider string) string {
	return filepath.Join(s.dir, "models-"+sanitize(provider)+".json")
}

// LoadCatalog reads a cached catalog. Missing cache is not an error.
func (s *Store) LoadCatalog(provider string) (Catalog, bool, error) {
	var cat Catalog
	ok, err := readJSONOk(s.catalogPath(provider), &cat)
	if err != nil || !ok {
		return Catalog{}, false, err
	}
	cat.Stale = time.Since(cat.FetchedAt) > CatalogTTL
	return cat, true, nil
}

// SaveCatalog stores a discovered catalog.
func (s *Store) SaveCatalog(provider string, models []Model) (Catalog, error) {
	cat := Catalog{Provider: provider, Models: models, FetchedAt: time.Now().UTC()}
	if err := writeJSON(s.catalogPath(provider), cat); err != nil {
		return Catalog{}, err
	}
	return cat, nil
}

// MarkCatalogError records a discovery failure next to the cached data, so a stale list is
// never presented as current.
func (s *Store) MarkCatalogError(provider, msg string) (Catalog, bool) {
	cat, ok, err := s.LoadCatalog(provider)
	if err != nil || !ok {
		return Catalog{Provider: provider, Error: msg, Stale: true}, false
	}
	cat.Error = msg
	cat.Stale = true
	if err := writeJSON(s.catalogPath(provider), cat); err != nil {
		return cat, false
	}
	return cat, true
}

// CatalogTTL is how long a discovered list is trusted before it is refreshed in the
// background. The requirement is at least daily.
const CatalogTTL = 24 * time.Hour

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// ------------------------------------------------------------------ file helpers ---

func readJSON(path string, out any) error {
	ok, err := readJSONOk(path, out)
	if err != nil {
		return err
	}
	if !ok {
		return nil
	}
	return nil
}

func readJSONOk(path string, out any) (bool, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return false, nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return false, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	return true, nil
}

func writeJSON(path string, v any) error {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return writeFile0600(path, append(raw, '\n'))
}

// writeFile0600 writes atomically: a partially written credentials file is a lost
// credential, so the rename does the commit.
func writeFile0600(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
