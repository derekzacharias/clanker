package netscan

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// EcosystemNVD labels NVD-sourced advisory cache entries.
const EcosystemNVD = "NVD"

// EcosystemService labels fingerprinted services in the inventory. It is
// deliberately distinct from EcosystemNVD: the assessment engine must not
// re-derive network findings from cached NVD records, because their
// applicability depends on the distribution-build logic in FindingForAdvisory
// (a distro package is needs_investigation even when NVD matches upstream).
const EcosystemService = "network-service"

// NVDClient queries the NVD CPE API.
//
// Rate limits are enforced client-side: NVD allows five requests per 30 seconds
// without a key, so the default interval is 6s. Results are cached in the
// scanner database, and a package with a fresh cache entry is never re-queried.
type NVDClient struct {
	BaseURL string
	HTTP    *http.Client
	APIKey  string
	// MinInterval is the minimum spacing between requests.
	MinInterval time.Duration
	// MaxResults caps CVEs per CPE match.
	MaxResults int
	now        func() time.Time
	last       time.Time
}

// NewNVDClient returns a client honouring NVD's published rate limits.
func NewNVDClient(apiKey string) *NVDClient {
	interval := 6 * time.Second
	if apiKey != "" {
		interval = 700 * time.Millisecond
	}
	return &NVDClient{
		BaseURL:     "https://services.nvd.nist.gov/rest/json/cves/2.0",
		HTTP:        &http.Client{Timeout: 45 * time.Second},
		APIKey:      apiKey,
		MinInterval: interval,
		MaxResults:  50,
		now:         func() time.Time { return time.Now().UTC() },
	}
}

// CVEMatch is one NVD record returned for a CPE query.
type CVEMatch struct {
	ID          string
	Description string
	CVSS        *intel.CVSS
	Published   time.Time
	URL         string
}

type nvdResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID           string `json:"id"`
			Published    string `json:"published"`
			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`
			Metrics map[string][]struct {
				CVSSData struct {
					BaseScore    float64 `json:"baseScore"`
					VectorString string  `json:"vectorString"`
					BaseSeverity string  `json:"baseSeverity"`
				} `json:"cvssData"`
			} `json:"metrics"`
			References []struct {
				URL string `json:"url"`
			} `json:"references"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

// MatchCPE returns CVEs NVD associates with an exact CPE.
func (c *NVDClient) MatchCPE(ctx context.Context, cpe string) ([]CVEMatch, error) {
	if c.BaseURL == "" || c.HTTP == nil {
		return nil, fmt.Errorf("NVD client is not configured")
	}
	if c.now == nil {
		c.now = func() time.Time { return time.Now().UTC() }
	}
	// Serialise and rate-limit requests.
	if !c.last.IsZero() {
		if wait := c.MinInterval - c.now().Sub(c.last); wait > 0 {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
	}
	c.last = c.now()

	u := fmt.Sprintf("%s?virtualMatchString=%s&resultsPerPage=%d", c.BaseURL, urlQueryEscape(cpe), c.MaxResults)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "clanker-guard/0.1 (authorised assessment)")
	if c.APIKey != "" {
		req.Header.Set("apiKey", c.APIKey)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("NVD returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var doc nvdResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 16<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("NVD response is not valid JSON: %w", err)
	}
	out := make([]CVEMatch, 0, len(doc.Vulnerabilities))
	for _, v := range doc.Vulnerabilities {
		m := CVEMatch{ID: v.CVE.ID}
		for _, d := range v.CVE.Descriptions {
			if d.Lang == "en" {
				m.Description = d.Value
				break
			}
		}
		if t, err := time.Parse(time.RFC3339, v.CVE.Published); err == nil {
			m.Published = t
		}
		// Prefer the newest CVSS version available.
		for _, key := range []string{"cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"} {
			if entries, ok := v.CVE.Metrics[key]; ok && len(entries) > 0 {
				d := entries[0].CVSSData
				m.CVSS = &intel.CVSS{Score: d.BaseScore, Vector: d.VectorString, Source: "NVD"}
				break
			}
		}
		if len(v.CVE.References) > 0 {
			m.URL = v.CVE.References[0].URL
		}
		if m.URL == "" {
			m.URL = "https://nvd.nist.gov/vuln/detail/" + m.ID
		}
		out = append(out, m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func urlQueryEscape(s string) string {
	// Minimal escaping for the characters NVD sees in CPE strings.
	r := strings.NewReplacer(
		"\\", "%5C",
		":", "%3A",
		" ", "%20",
		"+", "%2B",
		"&", "%26",
		"#", "%23",
		"?", "%3F",
	)
	return r.Replace(s)
}

// --- correlation through the ordinary assessment engine -----------------------

// PackageFor builds the pseudo-package representing a fingerprinted service.
func PackageFor(s Service) (model.Package, bool) {
	if s.Product == "" || s.Version == "" {
		return model.Package{}, false
	}
	vendor := s.Vendor
	if vendor == "" {
		vendor = "-"
	}
	return model.Package{
		Name:      vendor + ":" + s.Product,
		Version:   s.Version,
		Ecosystem: EcosystemService,
		Source:    model.OriginManifest,
		Manager:   "network-fingerprint",
		Arch:      fmt.Sprintf("%s:%d", s.Host, s.Port),
		PURL:      s.CPE,
		Vendor:    vendor,
	}, true
}

// AdvisoryFor converts one NVD match into the engine's advisory shape: the
// observed version is the affected version, so applicability is an exact match
// on evidence rather than a range guess.
func AdvisoryFor(pkg model.Package, m CVEMatch, now time.Time) intel.Advisory {
	refs := []intel.Reference{{Type: "ADVISORY", URL: m.URL}}
	var sev []intel.SeverityEntry
	if m.CVSS != nil && m.CVSS.Vector != "" {
		sev = append(sev, intel.SeverityEntry{Type: "CVSS_V3", Score: m.CVSS.Vector})
	}
	return intel.Advisory{
		ID:         m.ID,
		Source:     "NVD",
		Summary:    m.Description,
		Severities: sev,
		Affected: []intel.Affected{{
			Ecosystem: EcosystemNVD,
			Name:      pkg.Name,
			Versions:  []string{pkg.Version},
		}},
		References: refs,
		Published:  m.Published,
		FetchedAt:  now,
	}
}

// FindingsFromCache rebuilds findings from previously cached NVD advisories, so a
// re-scan inside the cache window does not silently report nothing.
func FindingsFromCache(store *intel.Store, svc Service, now time.Time) []model.Finding {
	if store == nil {
		return nil
	}
	pkg, ok := PackageFor(svc)
	if !ok {
		return nil
	}
	cached, err := store.AdvisoriesFor(context.Background(), EcosystemNVD, pkg.Name)
	if err != nil {
		return nil
	}
	var out []model.Finding
	for _, adv := range cached {
		m := CVEMatch{ID: adv.ID, Description: adv.Summary, Published: adv.Published}
		for _, ref := range adv.References {
			if ref.URL != "" {
				m.URL = ref.URL
				break
			}
		}
		if m.URL == "" {
			m.URL = "https://nvd.nist.gov/vuln/detail/" + adv.ID
		}
		if _, cvss, _, _ := intel.InterpretSeverities(adv.Severities); cvss != nil {
			m.CVSS = &intel.CVSS{Score: cvss.Score, Vector: cvss.Vector, Source: "NVD"}
		}
		out = append(out, FindingForAdvisory(svc, m, now))
	}
	return out
}

// CacheFresh reports whether an NVD result for this package is recent enough to
// reuse. Cached evidence is preferred over repeated API calls.
func CacheFresh(store *intel.Store, pkg model.Package, ttl time.Duration, now time.Time) bool {
	if store == nil {
		return false
	}
	cached, err := store.AdvisoriesFor(context.Background(), EcosystemNVD, pkg.Name)
	if err != nil || len(cached) == 0 {
		return false
	}
	var newest time.Time
	for _, a := range cached {
		if a.FetchedAt.After(newest) {
			newest = a.FetchedAt
		}
	}
	return !newest.IsZero() && now.Sub(newest) < ttl
}

// FindingForAdvisory turns an NVD match into a report finding.
//
// A distribution build is reported as needs_investigation rather than confirmed:
// distributions backport fixes without changing the upstream version, and NVD
// only knows the upstream version. Claiming "confirmed" there is exactly the
// false positive this project is built to avoid.
func FindingForAdvisory(svc Service, m CVEMatch, now time.Time) model.Finding {
	severity := "unknown"
	var cvss *model.CVSS
	if m.CVSS != nil {
		severity = intel.SeverityFromScore(m.CVSS.Score)
		cvss = &model.CVSS{Score: m.CVSS.Score, Vector: m.CVSS.Vector, Source: "NVD"}
	}
	evidence := []model.Evidence{
		{Kind: "service_fingerprint", Detail: fmt.Sprintf("%s:%d identifies as %s %s", svc.Host, svc.Port, svc.Product, svc.Version)},
		{Kind: "nvd_cpe_match", Detail: "NVD associates this CVE with " + svc.CPE, URL: m.URL},
	}
	if svc.DistroBuild {
		evidence = append(evidence, model.Evidence{
			Kind:   "distro_build",
			Source: svc.Distro,
			Detail: fmt.Sprintf("banner shows a %s package build (%s); distribution backports are not described by NVD",
				svc.Distro, svc.DistroVersion),
		})
	}

	f := model.Finding{
		Asset:            svc.Host,
		Product:          svc.Product,
		InstalledVersion: svc.Version,
		Ecosystem:        EcosystemNVD,
		VulnerabilityID:  m.ID,
		Source:           "NVD",
		ValidationStatus: model.ValidationPassive,
		Severity:         severity,
		CVSS:             cvss,
		Evidence:         evidence,
		PackageRef:       fmt.Sprintf("%s:%d", svc.Host, svc.Port),
		LastChecked:      &now,
	}
	if m.Description != "" {
		f.Explanation = m.Description
	}

	if svc.DistroBuild {
		f.Affected = model.ApplicabilityNeedsInvestigation
		f.Confidence = model.ConfidenceLow
		f.Explanation = fmt.Sprintf(
			"NVD matches %s %s, but the service reports a %s build. Distributions backport security fixes without changing the upstream version, so applicability must be confirmed against the vendor advisory before this is treated as actionable.",
			svc.Product, svc.Version, svc.Distro)
		f.RaiseConfidence = []string{
			fmt.Sprintf("%s's advisory lists %s %s as affected", svc.Distro, svc.Product, svc.DistroVersion),
			"the vulnerable behaviour is observed directly",
		}
		f.LowerConfidence = []string{
			fmt.Sprintf("%s's advisory shows the installed build contains the fix", svc.Distro),
		}
		f.Remediation = fmt.Sprintf("Check the %s security tracker for %s; the package build (%s) usually carries the fix.",
			svc.Distro, m.ID, svc.DistroVersion)
		return f
	}

	f.Affected = model.ApplicabilityProbable
	f.Confidence = model.ConfidenceMedium
	f.Explanation = fmt.Sprintf(
		"NVD matches %s %s by CPE. This is version-level evidence: it does not confirm the vulnerable code path is reachable or enabled.",
		svc.Product, svc.Version)
	f.RaiseConfidence = []string{"the vulnerable behaviour is observed directly on the service"}
	f.LowerConfidence = []string{"the vendor documents the issue as fixed in this version"}
	f.Remediation = fmt.Sprintf("Review %s and the vendor advisory; upgrade %s if the issue applies.", m.URL, svc.Product)
	return f
}

// ToModelFinding converts a configuration finding to the report model. These are
// observed conditions, so they are marked as validated behaviour: the evidence is
// the observation itself, not a version guess.
func (f Finding) ToModelFinding(asset string) model.Finding {
	ev := append([]model.Evidence(nil), f.Evidence...)
	return model.Finding{
		Asset:            asset,
		Product:          f.Title,
		InstalledVersion: "",
		Ecosystem:        "network",
		VulnerabilityID:  f.ID,
		Source:           "network assessment",
		Affected:         model.ApplicabilityValidated,
		ValidationStatus: model.ValidationActive,
		Confidence:       model.ConfidenceHigh,
		Severity:         f.Severity,
		Evidence:         ev,
		Remediation:      f.Remediation,
		Explanation: fmt.Sprintf(
			"Observed directly during an authorised network assessment of %s:%d. This is a configuration/exposure condition, not a CVE match.",
			f.Host, f.Port),
		PackageRef: fmt.Sprintf("%s:%d", f.Host, f.Port),
	}
}
