// Package intel fetches and caches public vulnerability intelligence.
//
// The package is deliberately dumb about applicability: it stores advisories
// with their provenance and hands them to the assessor. Nothing here decides
// that a package is vulnerable.
package intel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

// CVSS is a numeric score plus its provenance.
type CVSS struct {
	Vector string  `json:"vector,omitempty"`
	Score  float64 `json:"score,omitempty"`
	Source string  `json:"source,omitempty"`
}

// Reference is an advisory link.
type Reference struct {
	Type string `json:"type,omitempty"`
	URL  string `json:"url"`
}

// Event is one OSV range event.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// Range is one OSV affected range.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Binary is a distribution binary package version from OSV
// ecosystem_specific.binaries (Ubuntu/Pro records ship these).
type Binary struct {
	Name    string `json:"binary_name"`
	Version string `json:"binary_version"`
}

// Affected is one OSV affected package entry.
type Affected struct {
	Ecosystem        string         `json:"ecosystem"`
	Name             string         `json:"name"`
	PURL             string         `json:"purl,omitempty"`
	Versions         []string       `json:"versions,omitempty"`
	Ranges           []Range        `json:"ranges,omitempty"`
	Binaries         []Binary       `json:"binaries,omitempty"`
	DatabaseSpecific map[string]any `json:"database_specific,omitempty"`
}

// Advisory is a normalized OSV record with provenance.
type Advisory struct {
	ID               string          `json:"id"`
	Source           string          `json:"source"`
	Aliases          []string        `json:"aliases,omitempty"`
	Summary          string          `json:"summary,omitempty"`
	Details          string          `json:"details,omitempty"`
	Published        time.Time       `json:"published,omitempty"`
	Modified         time.Time       `json:"modified,omitempty"`
	Severities       []SeverityEntry `json:"severities,omitempty"`
	Affected         []Affected      `json:"affected,omitempty"`
	References       []Reference     `json:"references,omitempty"`
	DatabaseSpecific map[string]any  `json:"database_specific,omitempty"`
	FetchedAt        time.Time       `json:"fetched_at"`
	Raw              json.RawMessage `json:"-"`
}

// CVEIDs extracts CVE identifiers from an advisory ID and its aliases.
// Distro advisories embed the CVE in the ID (UBUNTU-CVE-2024-1234,
// DEBIAN-CVE-2024-1234), so alias-only extraction would miss every distro
// advisory and break KEV/EPSS enrichment.
func (a Advisory) CVEIDs() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		// Distro advisory IDs embed the CVE (UBUNTU-CVE-2024-1234), so scan for
		// embedded CVE tokens rather than requiring the whole string to match.
		for _, cve := range cveEmbeddedRe.FindAllString(strings.ToUpper(s), -1) {
			if seen[cve] {
				continue
			}
			seen[cve] = true
			out = append(out, cve)
		}
	}
	add(a.ID)
	for _, alias := range a.Aliases {
		add(alias)
	}
	sort.Strings(out)
	return out
}

var (
	cveRe         = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)
	cveEmbeddedRe = regexp.MustCompile(`CVE-\d{4}-\d{4,}`)
)

// Query is one OSV query batch entry.
type Query struct {
	Ecosystem string
	Name      string
	Version   string
}

func (q Query) key() string {
	return strings.ToLower(q.Ecosystem) + "\x00" + strings.ToLower(q.Name) + "\x00" + q.Version
}

// VulnRef is the lightweight identity returned by querybatch.
type VulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// OSVClient talks to api.osv.dev.
type OSVClient struct {
	BaseURL string
	HTTP    *http.Client
	// MaxBatch is the querybatch limit (OSV allows up to 1000).
	MaxBatch int
}

// NewOSVClient returns a client with conservative defaults.
func NewOSVClient() *OSVClient {
	return &OSVClient{
		BaseURL:  "https://api.osv.dev",
		HTTP:     &http.Client{Timeout: 45 * time.Second},
		MaxBatch: 250,
	}
}

// QueryBatch asks OSV which advisory IDs match the given package versions.
// It returns one slice per query, in input order.
func (c *OSVClient) QueryBatch(ctx context.Context, queries []Query) ([][]VulnRef, error) {
	if c.BaseURL == "" {
		c.BaseURL = "https://api.osv.dev"
	}
	if c.HTTP == nil {
		c.HTTP = &http.Client{Timeout: 45 * time.Second}
	}
	if c.MaxBatch <= 0 {
		c.MaxBatch = 250
	}
	out := make([][]VulnRef, len(queries))
	for start := 0; start < len(queries); start += c.MaxBatch {
		end := start + c.MaxBatch
		if end > len(queries) {
			end = len(queries)
		}
		refs, err := c.queryChunk(ctx, queries[start:end])
		if err != nil {
			return out, err
		}
		copy(out[start:end], refs)
	}
	return out, nil
}

type osvBatchRequest struct {
	Queries []osvBatchQuery `json:"queries"`
}

type osvBatchQuery struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version,omitempty"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []VulnRef `json:"vulns"`
	} `json:"results"`
}

func (c *OSVClient) queryChunk(ctx context.Context, queries []Query) ([][]VulnRef, error) {
	req := osvBatchRequest{Queries: make([]osvBatchQuery, 0, len(queries))}
	for _, q := range queries {
		var bq osvBatchQuery
		bq.Package.Name = q.Name
		bq.Package.Ecosystem = q.Ecosystem
		bq.Version = q.Version
		req.Queries = append(req.Queries, bq)
	}
	body, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var resp osvBatchResponse
	if err := c.postJSON(ctx, "/v1/querybatch", body, &resp); err != nil {
		return nil, err
	}
	out := make([][]VulnRef, len(queries))
	for i := range out {
		if i < len(resp.Results) {
			out[i] = resp.Results[i].Vulns
		}
	}
	return out, nil
}

// FetchVuln retrieves a full advisory record.
func (c *OSVClient) FetchVuln(ctx context.Context, id string) (Advisory, error) {
	var raw map[string]any
	path := "/v1/vulns/" + urlPathEscape(id)
	if err := c.getJSON(ctx, path, &raw); err != nil {
		return Advisory{}, err
	}
	return parseOSVRecord(raw, time.Now().UTC())
}

func urlPathEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "%%%02X", c)
	}
	return b.String()
}

// parseOSVRecord normalises an OSV JSON document. It is exported to tests via
// the package-internal tests.
func parseOSVRecord(raw map[string]any, now time.Time) (Advisory, error) {
	encoded, err := json.Marshal(raw)
	if err != nil {
		return Advisory{}, err
	}
	var wire struct {
		ID         string          `json:"id"`
		Aliases    []string        `json:"aliases"`
		Summary    string          `json:"summary"`
		Details    string          `json:"details"`
		Published  string          `json:"published"`
		Modified   string          `json:"modified"`
		Severity   []SeverityEntry `json:"severity"`
		References []Reference     `json:"references"`
		Affected   []struct {
			Package struct {
				Name      string `json:"name"`
				Ecosystem string `json:"ecosystem"`
				PURL      string `json:"purl"`
			} `json:"package"`
			Ranges            []Range  `json:"ranges"`
			Versions          []string `json:"versions"`
			EcosystemSpecific struct {
				Binaries []Binary `json:"binaries"`
			} `json:"ecosystem_specific"`
			DatabaseSpecific map[string]any `json:"database_specific"`
		} `json:"affected"`
		DatabaseSpecific map[string]any `json:"database_specific"`
	}
	if err := json.Unmarshal(encoded, &wire); err != nil {
		return Advisory{}, err
	}
	if wire.ID == "" {
		return Advisory{}, fmt.Errorf("advisory record without id")
	}
	a := Advisory{
		ID:               wire.ID,
		Source:           advisorySource(wire.ID),
		Aliases:          wire.Aliases,
		Summary:          wire.Summary,
		Details:          wire.Details,
		Severities:       wire.Severity,
		References:       wire.References,
		DatabaseSpecific: wire.DatabaseSpecific,
		FetchedAt:        now,
		Raw:              json.RawMessage(encoded),
	}
	if t, err := time.Parse(time.RFC3339, wire.Published); err == nil {
		a.Published = t
	}
	if t, err := time.Parse(time.RFC3339, wire.Modified); err == nil {
		a.Modified = t
	}
	for _, aff := range wire.Affected {
		a.Affected = append(a.Affected, Affected{
			Ecosystem:        aff.Package.Ecosystem,
			Name:             aff.Package.Name,
			PURL:             aff.Package.PURL,
			Versions:         aff.Versions,
			Ranges:           aff.Ranges,
			Binaries:         aff.EcosystemSpecific.Binaries,
			DatabaseSpecific: aff.DatabaseSpecific,
		})
	}
	return a, nil
}

// advisorySource derives the feed name from an advisory ID prefix.
func advisorySource(id string) string {
	switch {
	case strings.HasPrefix(id, "UBUNTU-"):
		return "Ubuntu"
	case strings.HasPrefix(id, "DEBIAN-"):
		return "Debian"
	case strings.HasPrefix(id, "ALPINE-"):
		return "Alpine"
	case strings.HasPrefix(id, "RLSA-"), strings.HasPrefix(id, "RHSA-"):
		return "Red Hat"
	case strings.HasPrefix(id, "CVE-"):
		return "CVE"
	case strings.HasPrefix(id, "GHSA-"):
		return "GitHub"
	case strings.HasPrefix(id, "PYSEC-"):
		return "OSV"
	case strings.HasPrefix(id, "GO-"):
		return "OSV"
	case strings.HasPrefix(id, "RUSTSEC-"):
		return "OSV"
	default:
		return "OSV"
	}
}

func (c *OSVClient) postJSON(ctx context.Context, path string, body []byte, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "clanker-guard/0.1 (+https://github.com/bgdnvk/clanker)")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("osv request failed: %w", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv %s returned %d: %s", path, resp.StatusCode, truncate(string(payload), 200))
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("osv %s: invalid JSON: %w", path, err)
	}
	return nil
}

func (c *OSVClient) getJSON(ctx context.Context, path string, dst any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(c.BaseURL, "/")+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "clanker-guard/0.1 (+https://github.com/bgdnvk/clanker)")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("osv request failed: %w", err)
	}
	defer resp.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("osv %s returned %d: %s", path, resp.StatusCode, truncate(string(payload), 200))
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("osv %s: invalid JSON: %w", path, err)
	}
	return nil
}

func truncate(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
