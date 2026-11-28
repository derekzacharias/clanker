package nvd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/cpe"
)

// DefaultBaseURL is the NVD API 2.0 base.
const DefaultBaseURL = "https://services.nvd.nist.gov/rest/json"

// APIKeyEnvNames are the environment variables consulted for NVD credentials,
// in order. The settings table is consulted separately by the CLI/server.
var APIKeyEnvNames = []string{"CLANKER_GUARD_NVD_API_KEY", "NVD_API_KEY"}

// Rate limits published by NVD: without a key, 5 requests per rolling 30
// seconds; with a key, 50. The client also spaces requests evenly, which is
// friendlier to the service than bursting the window.
const (
	RequestsPerWindowAnon = 5
	RequestsPerWindowKey  = 50
	RateWindow            = 30 * time.Second
)

// Client is a rate-limited NVD API 2.0 client with pagination, retries and
// exponential backoff. Request timing is serialised so callers may share one
// client safely.
type Client struct {
	BaseURL string
	HTTP    *http.Client
	// APIKey, when set, raises the rate limit. Never logged.
	APIKey string
	// MaxRetries bounds 429/5xx retries (default 5).
	MaxRetries int
	// ResultsPerPage is used for paginated endpoints (default 2000, max 2000).
	ResultsPerPage int
	// MinInterval overrides the computed minimum spacing (tests).
	MinInterval time.Duration
	// BackoffBase is the initial retry delay (default 6s).
	BackoffBase time.Duration
	// Now injects time (tests).
	Now func() time.Time

	mu   chan struct{} // request serialisation token
	last time.Time
}

// NewClient returns a production client. apiKey may be empty.
func NewClient(apiKey string) *Client {
	return &Client{
		BaseURL:        DefaultBaseURL,
		HTTP:           &http.Client{Timeout: 90 * time.Second},
		APIKey:         apiKey,
		MaxRetries:     5,
		ResultsPerPage: 2000,
		BackoffBase:    6 * time.Second,
		Now:            func() time.Time { return time.Now().UTC() },
		mu:             make(chan struct{}, 1),
	}
}

func (c *Client) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now().UTC()
}

// minInterval computes the required spacing between requests.
func (c *Client) minInterval() time.Duration {
	if c.MinInterval > 0 {
		return c.MinInterval
	}
	if c.APIKey != "" {
		return RateWindow / RequestsPerWindowKey
	}
	return RateWindow / RequestsPerWindowAnon
}

// get performs one GET with rate limiting, retries and backoff. The response
// body is returned; the caller owns closing it.
func (c *Client) get(ctx context.Context, url string) (*http.Response, error) {
	client := c.HTTP
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	interval := c.minInterval()
	retries := c.MaxRetries
	if retries <= 0 {
		retries = 5
	}
	backoff := c.BackoffBase
	if backoff <= 0 {
		backoff = 6 * time.Second
	}

	c.mu <- struct{}{} // serialize requests: timing state is process-global
	defer func() { <-c.mu }()
	if !c.last.IsZero() {
		if wait := interval - c.now().Sub(c.last); wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}

	var lastErr error
	for attempt := 0; attempt <= retries; attempt++ {
		if attempt > 0 {
			delay := backoff * time.Duration(1<<(attempt-1))
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		c.last = c.now()
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "clanker-guard/0.1 (authorised vulnerability assessment)")
		// Do NOT set Accept-Encoding manually: Go's transport adds gzip and
		// decompresses transparently only when it set the header itself.
		if c.APIKey != "" {
			req.Header.Set("apiKey", c.APIKey)
		}
		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("NVD request failed: %w", err)
			continue
		}
		switch {
		case resp.StatusCode == http.StatusOK:
			return resp, nil
		case resp.StatusCode == http.StatusTooManyRequests,
			resp.StatusCode == http.StatusForbidden,
			resp.StatusCode >= 500:
			wait := backoff * time.Duration(1<<attempt)
			if ra := resp.Header.Get("Retry-After"); ra != "" {
				if secs, err := strconv.Atoi(ra); err == nil && secs > 0 && secs < 3600 {
					wait = time.Duration(secs) * time.Second
				}
			}
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			lastErr = fmt.Errorf("NVD returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
			backoff = wait
			continue
		default:
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
			resp.Body.Close()
			return nil, fmt.Errorf("NVD returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
		}
	}
	return nil, fmt.Errorf("NVD request failed after %d attempts: %w", retries+1, lastErr)
}

// page is the common envelope of every NVD API 2.0 response.
type page struct {
	ResultsPerPage  int               `json:"resultsPerPage"`
	StartIndex      int               `json:"startIndex"`
	TotalResults    int               `json:"totalResults"`
	Format          string            `json:"format"`
	Version         string            `json:"version"`
	Timestamp       string            `json:"timestamp"`
	Vulnerabilities []json.RawMessage `json:"vulnerabilities"`
	Products        []json.RawMessage `json:"products"`
}

// cveDoc is the JSON shape of one CVE record.
type cveDoc struct {
	ID           string `json:"id"`
	Published    string `json:"published"`
	LastModified string `json:"lastModified"`
	VulnStatus   string `json:"vulnStatus"`
	Descriptions []struct {
		Lang  string `json:"lang"`
		Value string `json:"value"`
	} `json:"descriptions"`
	Metrics map[string][]struct {
		Source   string `json:"source"`
		Type     string `json:"type"`
		CVSSData struct {
			Version      string  `json:"version"`
			VectorString string  `json:"vectorString"`
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	} `json:"metrics"`
	Weaknesses []struct {
		Source      string `json:"source"`
		Type        string `json:"type"`
		Description []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		} `json:"description"`
	} `json:"weaknesses"`
	Configurations []cpe.Node `json:"configurations"`
	References     []struct {
		URL    string   `json:"url"`
		Source string   `json:"source"`
		Tags   []string `json:"tags"`
	} `json:"references"`
}

// parseRecord converts one CVE document into the persisted Record shape.
// The API wraps each record in a "cve" object.
func parseRecord(raw json.RawMessage) (Record, error) {
	var wrapper struct {
		CVE cveDoc `json:"cve"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return Record{}, fmt.Errorf("parse CVE document: %w", err)
	}
	doc := wrapper.CVE
	if doc.ID == "" {
		return Record{}, fmt.Errorf("CVE document without id")
	}
	r := Record{ID: strings.ToUpper(doc.ID), Status: doc.VulnStatus}
	if t, err := time.Parse(time.RFC3339, doc.Published); err == nil {
		r.Published = t
	}
	if t, err := time.Parse(time.RFC3339, doc.LastModified); err == nil {
		r.Modified = t
	}
	for _, d := range doc.Descriptions {
		if d.Lang == "en" && d.Value != "" {
			r.Description = d.Value
			break
		}
	}
	for key, list := range doc.Metrics {
		version := normalizeCVSSVersion(strings.TrimPrefix(key, "cvssMetricV"))
		for _, m := range list {
			if m.CVSSData.BaseScore <= 0 && m.CVSSData.VectorString == "" {
				continue
			}
			r.Metrics = append(r.Metrics, CVSSMetric{
				Version:  version,
				Score:    m.CVSSData.BaseScore,
				Vector:   m.CVSSData.VectorString,
				Severity: strings.ToLower(m.CVSSData.BaseSeverity),
				Source:   m.Source,
				Type:     m.Type,
			})
		}
	}
	for _, w := range doc.Weaknesses {
		for _, d := range w.Description {
			if d.Lang == "en" && d.Value != "" {
				r.Weaknesses = append(r.Weaknesses, Weakness{
					CWE:     d.Value,
					Source:  w.Source,
					Primary: strings.EqualFold(w.Type, "Primary"),
				})
			}
		}
	}
	r.Configs = doc.Configurations
	for _, ref := range doc.References {
		r.References = append(r.References, Reference{URL: ref.URL, Source: ref.Source, Tags: ref.Tags})
	}
	return r, nil
}

func normalizeCVSSVersion(v string) string {
	switch strings.ToUpper(v) {
	case "V4", "4", "4.0":
		return "4.0"
	case "V31", "31", "3.1":
		return "3.1"
	case "V30", "30", "3.0":
		return "3.0"
	case "V2", "2", "2.0":
		return "2.0"
	}
	return v
}

// cpeDoc is the JSON shape of one CPE dictionary entry.
type cpeDoc struct {
	Deprecated   bool   `json:"deprecated"`
	CPEName      string `json:"cpeName"`
	LastModified string `json:"lastModified"`
	Titles       []struct {
		Title string `json:"title"`
		Lang  string `json:"lang"`
	} `json:"titles"`
	References []struct {
		URL    string   `json:"url"`
		Source string   `json:"source"`
		Tags   []string `json:"tags"`
	} `json:"references"`
	DeprecatedBy []struct {
		CPEName   string `json:"cpeName"`
		CPEName23 string `json:"cpeNameId"`
	} `json:"deprecatedBy"`
}

// parseDictEntry converts one dictionary document. The API wraps each entry
// in a "cpe" object.
func parseDictEntry(raw json.RawMessage) (DictEntry, error) {
	var wrapper struct {
		CPE cpeDoc `json:"cpe"`
	}
	if err := json.Unmarshal(raw, &wrapper); err != nil {
		return DictEntry{}, fmt.Errorf("parse CPE dictionary entry: %w", err)
	}
	doc := wrapper.CPE
	if doc.CPEName == "" {
		return DictEntry{}, fmt.Errorf("dictionary entry without cpeName")
	}
	parsed, err := cpe.Parse(doc.CPEName)
	if err != nil {
		// The dictionary should never contain unparsable CPEs; keep the
		// record out rather than poisoning the index.
		return DictEntry{}, fmt.Errorf("unparsable dictionary CPE %q: %w", doc.CPEName, err)
	}
	e := DictEntry{
		CPE23:      doc.CPEName,
		Vendor:     strings.ToLower(parsed.Vendor),
		Product:    strings.ToLower(parsed.Product),
		Version:    parsed.Version,
		Deprecated: doc.Deprecated,
	}
	if len(doc.DeprecatedBy) > 0 {
		e.DeprecatedBy = doc.DeprecatedBy[0].CPEName
	}
	for _, t := range doc.Titles {
		e.Titles = append(e.Titles, t.Title)
	}
	for _, ref := range doc.References {
		e.Refs = append(e.Refs, Reference{URL: ref.URL, Source: ref.Source, Tags: ref.Tags})
	}
	if t, err := time.Parse(time.RFC3339, doc.LastModified); err == nil {
		e.LastModified = t
	}
	return e, nil
}

// CVEPage fetches one page of CVE records.
//
// Filters: lastModStartDate and lastModEndDate are BOTH required by the NVD
// API when either is used (it answers 404 otherwise), so an unset end date
// defaults to now. startIndex pages through the result set.
func (c *Client) CVEPage(ctx context.Context, startIndex int, lastModStart, lastModEnd time.Time) (total int, records []Record, err error) {
	base := strings.TrimRight(c.BaseURL, "/") + "/cves/2.0"
	params := []string{
		"startIndex=" + strconv.Itoa(startIndex),
		"resultsPerPage=" + strconv.Itoa(c.ResultsPerPage),
	}
	if !lastModStart.IsZero() {
		end := lastModEnd
		if end.IsZero() {
			end = c.now()
		}
		params = append(params,
			"lastModStartDate="+nvdDateParam(lastModStart),
			"lastModEndDate="+nvdDateParam(end))
	}
	p, err := c.fetchPage(ctx, base+"?"+strings.Join(params, "&"), true)
	if err != nil {
		return 0, nil, err
	}
	records = make([]Record, 0, len(p.Vulnerabilities))
	for _, raw := range p.Vulnerabilities {
		r, err := parseRecord(raw)
		if err != nil {
			return 0, nil, fmt.Errorf("page corrupt: %w", err)
		}
		records = append(records, r)
	}
	return p.TotalResults, records, nil
}

// CPEDictionaryPage fetches one page of the CPE dictionary.
func (c *Client) CPEDictionaryPage(ctx context.Context, startIndex int, lastModStart time.Time) (total int, entries []DictEntry, err error) {
	base := strings.TrimRight(c.BaseURL, "/") + "/cpes/2.0"
	params := []string{
		"startIndex=" + strconv.Itoa(startIndex),
		"resultsPerPage=" + strconv.Itoa(c.ResultsPerPage),
	}
	if !lastModStart.IsZero() {
		params = append(params,
			"lastModStartDate="+nvdDateParam(lastModStart),
			"lastModEndDate="+nvdDateParam(c.now()))
	}
	p, err := c.fetchPage(ctx, base+"?"+strings.Join(params, "&"), false)
	if err != nil {
		return 0, nil, err
	}
	entries = make([]DictEntry, 0, len(p.Products))
	for _, raw := range p.Products {
		e, err := parseDictEntry(raw)
		if err != nil {
			return 0, nil, fmt.Errorf("dictionary page corrupt: %w", err)
		}
		entries = append(entries, e)
	}
	return p.TotalResults, entries, nil
}

// nvdDateParam renders the ISO 8601 format the NVD API requires for its date
// filters. NVD rejects the "Z" suffix for these parameters, so the offset is
// always emitted numerically and the "+" percent-encoded, exactly as its API
// documentation shows.
func nvdDateParam(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000") + "%2B00:00"
}

func (c *Client) fetchPage(ctx context.Context, url string, cves bool) (*page, error) {
	resp, err := c.get(ctx, url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var p page
	dec := json.NewDecoder(io.LimitReader(resp.Body, 512<<20))
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("NVD response is not valid JSON: %w", err)
	}
	if cves && p.Format != "" && !strings.HasPrefix(strings.ToUpper(p.Format), "NVD_CVE") {
		return nil, fmt.Errorf("unexpected NVD response format %q", p.Format)
	}
	// Feed integrity: the envelope's own count must agree with the payload,
	// or the page is treated as corrupt rather than half-imported.
	limit := p.ResultsPerPage
	if limit <= 0 {
		limit = c.ResultsPerPage
	}
	if cves && len(p.Vulnerabilities) > limit {
		return nil, fmt.Errorf("feed integrity: %d records exceed resultsPerPage %d", len(p.Vulnerabilities), limit)
	}
	if !cves && len(p.Products) > limit {
		return nil, fmt.Errorf("feed integrity: %d dictionary entries exceed resultsPerPage %d", len(p.Products), limit)
	}
	return &p, nil
}
