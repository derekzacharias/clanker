// Package nvd is the NVD intelligence provider: the CVE API, the CPE
// dictionary, and CPE match data, synchronized into the shared local cache.
//
// Design rules:
//   - Everything the correlation engine reads comes from the local cache;
//     NVD is never queried per-application during a scan.
//   - Rate limits, pagination, retries and backoff are the client's problem,
//     not the sync's. A failed request is an error; the last known good
//     dataset stays in place.
//   - API credentials come from secure configuration only (environment or
//     the settings table) and are never logged or embedded in errors.
package nvd

import (
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/cpe"
)

// VulnStatus values NVD assigns to a CVE record.
const (
	StatusAnalyzed   = "Analyzed"
	StatusModified   = "Modified"
	StatusRejected   = "Rejected"
	StatusReceived   = "Received"
	StatusAwaiting   = "Awaiting Analysis"
	StatusDeferred   = "Deferred"
	StatusUndergoing = "Undergoing Analysis"
)

// Rejected reports whether NVD withdrew the CVE. Rejected records are kept
// (so a scan can explain why they were excluded) but never matched.
func Rejected(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), StatusRejected)
}

// Reference is one advisory URL from a CVE record.
type Reference struct {
	URL    string   `json:"url"`
	Source string   `json:"source,omitempty"`
	Tags   []string `json:"tags,omitempty"`
}

// Weakness is one CWE classification.
type Weakness struct {
	CWE     string `json:"cwe"`
	Source  string `json:"source,omitempty"`
	Primary bool   `json:"primary"`
}

// CVSSMetric is one published CVSS score for a CVE.
type CVSSMetric struct {
	Version  string  `json:"version"`
	Score    float64 `json:"score"`
	Vector   string  `json:"vector"`
	Severity string  `json:"severity"`
	Source   string  `json:"source"`
	Type     string  `json:"type"` // Primary | Secondary
}

// Record is one CVE with everything the correlation engine needs. It is what
// gets persisted; the raw NVD payload is never stored verbatim.
type Record struct {
	ID          string       `json:"id"`
	Published   time.Time    `json:"published"`
	Modified    time.Time    `json:"modified"`
	Status      string       `json:"vuln_status"`
	Description string       `json:"description"`
	Metrics     []CVSSMetric `json:"metrics"`
	Weaknesses  []Weakness   `json:"weaknesses"`
	Configs     []cpe.Node   `json:"configurations"`
	References  []Reference  `json:"references"`
}

// PrimaryCVSS returns the best CVSS score NVD publishes: prefer v4.0, then
// 3.1, 3.0, 2.0, and within a version prefer Primary over Secondary.
func (r Record) PrimaryCVSS() *CVSSMetric {
	order := map[string]int{"4.0": 0, "3.1": 1, "3.0": 2, "2.0": 3}
	best := -1
	var out *CVSSMetric
	for i := range r.Metrics {
		m := &r.Metrics[i]
		if m.Score <= 0 {
			continue
		}
		rank, ok := order[m.Version]
		if !ok {
			continue
		}
		typeRank := 1
		if strings.EqualFold(m.Type, "Primary") {
			typeRank = 0
		}
		key := rank*2 + typeRank
		if best == -1 || key < best {
			best = key
			out = m
		}
	}
	return out
}

// WeaknessIDs returns the CWE identifiers, primary first.
func (r Record) WeaknessIDs() []string {
	var prim, others []string
	for _, w := range r.Weaknesses {
		if strings.HasPrefix(strings.ToUpper(w.CWE), "CWE-") {
			if w.Primary {
				prim = append(prim, w.CWE)
			} else {
				others = append(others, w.CWE)
			}
		}
	}
	return append(prim, others...)
}

// DetailURL is the canonical NVD advisory URL.
func (r Record) DetailURL() string {
	return "https://nvd.nist.gov/vuln/detail/" + r.ID
}

// DictEntry is one CPE dictionary record.
type DictEntry struct {
	CPE23        string
	Vendor       string
	Product      string
	Version      string
	Deprecated   bool
	DeprecatedBy string
	Titles       []string
	Refs         []Reference
	LastModified time.Time
}

// Bound copies the NVD range fields of a match into the cpe.Range type.
type boundFields struct {
	StartIncluding string `json:"versionStartIncluding"`
	StartExcluding string `json:"versionStartExcluding"`
	EndIncluding   string `json:"versionEndIncluding"`
	EndExcluding   string `json:"versionEndExcluding"`
}
