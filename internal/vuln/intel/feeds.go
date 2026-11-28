package intel

import (
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Default feed endpoints.
const (
	DefaultKEVURL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	DefaultEPSSURL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
)

// Fetcher downloads feeds. It exists as a type so tests can redirect endpoints
// to httptest servers and so callers can tune timeouts.
type Fetcher struct {
	HTTP    *http.Client
	KEVURL  string
	EPSSURL string
	// OnProgress receives transfer progress with real byte counts (nil-safe).
	OnProgress func(stage string, bytes int64)
}

// NewFetcher returns a fetcher with production endpoints.
func NewFetcher() *Fetcher {
	return &Fetcher{
		HTTP:    &http.Client{Timeout: 120 * time.Second},
		KEVURL:  DefaultKEVURL,
		EPSSURL: DefaultEPSSURL,
	}
}

// FetchKEV downloads and normalises the CISA KEV catalog.
func (f *Fetcher) FetchKEV(ctx context.Context) ([]KEVEntry, error) {
	url := f.KEVURL
	if url == "" {
		url = DefaultKEVURL
	}
	body, err := f.get(ctx, url, "KEV")
	if err != nil {
		return nil, err
	}
	var doc struct {
		Vulnerabilities []struct {
			CVEID             string `json:"cveID"`
			VendorProject     string `json:"vendorProject"`
			Product           string `json:"product"`
			VulnerabilityName string `json:"vulnerabilityName"`
			DateAdded         string `json:"dateAdded"`
			KnownRansomware   string `json:"knownRansomwareCampaignUse"`
			Notes             string `json:"notes"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse KEV catalog: %w", err)
	}
	out := make([]KEVEntry, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		if v.CVEID == "" {
			continue
		}
		out = append(out, KEVEntry{
			CVEID:      strings.ToUpper(v.CVEID),
			DateAdded:  v.DateAdded,
			Vendor:     v.VendorProject,
			Product:    v.Product,
			Name:       v.VulnerabilityName,
			Ransomware: v.KnownRansomware,
			URL:        "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
		})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("KEV catalog contained no records (unexpected feed shape)")
	}
	return out, nil
}

// FetchEPSS downloads the current EPSS scores.
//
// The feed is a gzipped CSV whose first line is a comment carrying the model
// version and score date.
func (f *Fetcher) FetchEPSS(ctx context.Context) ([]EPSSEntry, error) {
	url := f.EPSSURL
	if url == "" {
		url = DefaultEPSSURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "clanker-guard/0.1")
	client := f.HTTP
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download EPSS: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("EPSS feed returned %d", resp.StatusCode)
	}
	gz, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("EPSS feed is not gzip: %w", err)
	}
	defer gz.Close()

	// Bytes here are the decompressed stream the parser actually consumed —
	// real transfer progress, not an estimate.
	counter := &countingReader{r: gz}
	r := csv.NewReader(io.LimitReader(counter, 512<<20))
	r.FieldsPerRecord = -1
	var model, scoreDate string
	out := make([]EPSSEntry, 0, 300000)
	first := true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parse EPSS CSV: %w", err)
		}
		if first {
			first = false
			line := strings.Join(rec, ",")
			if strings.HasPrefix(line, "#") {
				for _, part := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
					k, v, ok := strings.Cut(part, ":")
					if !ok {
						continue
					}
					switch strings.TrimSpace(k) {
					case "model_version":
						model = strings.TrimSpace(v)
					case "score_date":
						scoreDate = strings.TrimSpace(v)
					}
				}
				continue
			}
			if strings.EqualFold(rec[0], "cve") {
				continue
			}
		}
		if len(rec) < 3 {
			continue
		}
		score, err1 := strconv.ParseFloat(rec[1], 64)
		pct, err2 := strconv.ParseFloat(rec[2], 64)
		cve := strings.ToUpper(strings.TrimSpace(rec[0]))
		if err1 != nil || err2 != nil || !cveRe.MatchString(cve) {
			continue
		}
		out = append(out, EPSSEntry{CVE: cve, Score: score, Percentile: pct, Model: model, ScoreDate: scoreDate})
		if f.OnProgress != nil && len(out)%100000 == 0 {
			f.OnProgress("EPSS", counter.n)
		}
	}
	if f.OnProgress != nil {
		f.OnProgress("EPSS", counter.n)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("EPSS feed contained no parsable rows")
	}
	return out, nil
}

func (f *Fetcher) get(ctx context.Context, url, stage string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "clanker-guard/0.1")
	client := f.HTTP
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s returned %d", url, resp.StatusCode)
	}
	counter := &countingReader{r: resp.Body}
	body, err := io.ReadAll(io.LimitReader(counter, 64<<20))
	if f.OnProgress != nil {
		f.OnProgress(stage, counter.n)
	}
	return body, err
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}
