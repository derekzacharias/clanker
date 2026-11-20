package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/report"
	"github.com/bgdnvk/clanker/internal/vuln/ticketing"
)

// jobManager tracks running scan/feed jobs and their cancel functions.
type jobManager struct {
	mu      sync.Mutex
	cancels map[string]context.CancelFunc
}

func newJobManager() *jobManager {
	return &jobManager{cancels: map[string]context.CancelFunc{}}
}

func (m *jobManager) newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("SCAN-%d", time.Now().UnixNano())
	}
	return "SCAN-" + hex.EncodeToString(b)
}

// register records a job's cancel function.
func (m *jobManager) register(id string, cancel context.CancelFunc) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cancels[id] = cancel
}

// forget drops a finished job.
func (m *jobManager) forget(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.cancels, id)
}

// cancel stops a running job. It reports whether the job was running.
func (m *jobManager) cancel(id string) bool {
	m.mu.Lock()
	cancel, ok := m.cancels[id]
	m.mu.Unlock()
	if ok {
		cancel()
	}
	return ok
}

// active reports how many jobs are running.
func (m *jobManager) active() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.cancels)
}

// ---------------------------------------------------------- dataset views ---

type dataset struct {
	Hosts map[string]*hostView
	Vulns []vulnRow
	Runs  []intel.RunSummary
	ByID  map[string]*vulnRow
}

type hostView struct {
	Host       string
	Asset      assetInfo
	ReportID   string
	FinishedAt time.Time
	StartedAt  time.Time
	Findings   []vulnRow
	Packages   []packageRow
	Coverage   coverageView
	Skipped    []skippedRow
	// Suppressed explains findings deliberately not shown (OS-owned Python duplicates).
	Suppressed  []string
	Errors      []string
	Offline     bool
	ToolVersion string
	Mode        string
	Feeds       []feedRow
	Policy      policyView
}

type assetInfo struct {
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	OSVersion   string `json:"os_version"`
	OSCodename  string `json:"os_codename,omitempty"`
	Kernel      string `json:"kernel,omitempty"`
	Arch        string `json:"arch,omitempty"`
	DistroID    string `json:"distro_id,omitempty"`
	IsContainer bool   `json:"is_container,omitempty"`
}

type packageRow struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
	Source    string `json:"source"`
	// Origin is the metadata path (or package file) a distribution was read from. It is what
	// distinguishes an OS-owned Python package from a real pip dependency.
	Origin string `json:"origin,omitempty"`
	Arch   string `json:"arch,omitempty"`
	PURL   string `json:"purl,omitempty"`
	Patch  string `json:"patch_status,omitempty"`
}

type vulnRow struct {
	ID               string        `json:"id"`
	Finding          string        `json:"finding_id"`
	ReportID         string        `json:"report_id"`
	CVE              string        `json:"cve"`
	Aliases          []string      `json:"aliases,omitempty"`
	Asset            string        `json:"asset"`
	Product          string        `json:"product"`
	InstalledVersion string        `json:"installed_version"`
	Ecosystem        string        `json:"ecosystem"`
	Severity         string        `json:"severity"`
	Affected         string        `json:"affected"`
	Confidence       string        `json:"confidence"`
	Validation       string        `json:"validation_status"`
	KEV              bool          `json:"kev"`
	KEVDateAdded     string        `json:"kev_date_added,omitempty"`
	Ransomware       string        `json:"kev_ransomware,omitempty"`
	EPSS             *float64      `json:"epss"`
	EPSSPercentile   *float64      `json:"epss_percentile"`
	CVSS             *float64      `json:"cvss"`
	CVSSVector       string        `json:"cvss_vector,omitempty"`
	FixedVersion     string        `json:"fixed_version,omitempty"`
	Remediation      string        `json:"remediation"`
	Source           string        `json:"source"`
	AdvisoryID       string        `json:"advisory_id"`
	Vendor           string        `json:"vendor,omitempty"`
	RiskScore        float64       `json:"risk_score"`
	FirstSeen        string        `json:"first_seen"`
	LastSeen         string        `json:"last_seen"`
	Explanation      string        `json:"explanation,omitempty"`
	Evidence         []evidenceRow `json:"evidence,omitempty"`
	// WorkItem is the remediation work derived from this finding, when one exists.
	// Attached by the detail handler only: the list endpoints stay about findings, and
	// ownership is one lookup rather than a join across every row. (The field next to it,
	// Remediation, is the advisory's advice text — a different thing.)
	WorkItem *remediationView `json:"remediation_item,omitempty"`
	// GitLabTickets are the issues tracked for this finding (normally zero or one).
	GitLabTickets []ticketing.Ticket `json:"gitlab_tickets,omitempty"`
	Raise         []string           `json:"confidence_increase,omitempty"`
	Lower         []string           `json:"confidence_reduction,omitempty"`
	RiskFactors   []riskRow          `json:"risk_factors,omitempty"`
	References    []linkRow          `json:"references,omitempty"`
	// Analyst is the evidence-backed correction applied by a review, when one
	// exists. The scanner verdict stays in Affected.
	Analyst *analystView `json:"analyst,omitempty"`
	// Effective is what the UI should treat as current (Analyst if present).
	Effective string `json:"effective_affected,omitempty"`
	// Fingerprint is the history identity (host-independent); it links a finding
	// to stored run history for first-seen dates. Not exposed over the API.
	Fingerprint string `json:"-"`
}

type evidenceRow struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	URL    string `json:"url,omitempty"`
	Source string `json:"source,omitempty"`
}

type riskRow struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail,omitempty"`
}

type linkRow struct {
	Label string `json:"label"`
	URL   string `json:"url"`
}

type coverageView struct {
	PackagesInspected int      `json:"packages_inspected"`
	PackagesMatched   int      `json:"packages_matched"`
	AdvisoriesChecked int      `json:"advisories_checked"`
	Sources           []string `json:"sources_used"`
	NotCovered        []string `json:"not_covered,omitempty"`
	Limitations       []string `json:"limitations,omitempty"`
}

type skippedRow struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

type feedRow struct {
	Source   string `json:"source"`
	LastSync string `json:"last_sync,omitempty"`
	Records  int    `json:"records"`
	Stale    bool   `json:"stale"`
}

type policyView struct {
	FailOn    string `json:"fail_on,omitempty"`
	FailOnKEV bool   `json:"fail_on_kev"`
}

// buildDataset projects the stored reports into the views the UI needs.
func (s *Server) buildDataset(ctx context.Context) (*dataset, error) {
	runs, err := s.store.ListRuns(ctx, 200)
	if err != nil {
		return nil, err
	}
	ds := &dataset{Hosts: map[string]*hostView{}, Runs: runs, ByID: map[string]*vulnRow{}}
	if len(runs) == 0 {
		return ds, nil
	}

	feeds, _ := s.feedRows(ctx)
	// first-seen lookup: run id -> fingerprints, keyed by host
	firstSeen := map[string]map[string]time.Time{}
	for _, run := range runs {
		m := firstSeen[run.Host]
		if m == nil {
			m = map[string]time.Time{}
			firstSeen[run.Host] = m
		}
		for _, fp := range run.FindingIDs {
			if prev, ok := m[fp]; !ok || run.FinishedAt.Before(prev) {
				m[fp] = run.FinishedAt
			}
		}
	}

	// newest run per host wins
	seenHost := map[string]bool{}
	for _, run := range runs {
		if seenHost[run.Host] {
			continue
		}
		seenHost[run.Host] = true

		payload, err := s.store.ReportByID(ctx, run.ID)
		if err != nil {
			continue
		}
		var rep reportDoc
		if err := json.Unmarshal(payload, &rep); err != nil {
			continue
		}
		hv := &hostView{
			Host:        rep.Metadata.Host,
			ReportID:    rep.ReportID,
			StartedAt:   rep.Metadata.StartedAt,
			Offline:     rep.Metadata.Offline,
			ToolVersion: rep.Metadata.ToolVersion,
			Mode:        rep.Metadata.Mode,
			Feeds:       feeds,
			Policy:      policyView{FailOn: rep.Metadata.Policy.FailOnSeverity, FailOnKEV: rep.Metadata.Policy.FailOnKEV},
			Errors:      rep.Metadata.Errors,
			Asset: assetInfo{
				Hostname: rep.Inventory.Asset.Hostname, OS: rep.Inventory.Asset.OS,
				OSVersion: rep.Inventory.Asset.OSVersion, OSCodename: rep.Inventory.Asset.OSCodename,
				Kernel: rep.Inventory.Asset.Kernel, Arch: rep.Inventory.Asset.Arch,
				DistroID: rep.Inventory.Asset.DistroID, IsContainer: rep.Inventory.Asset.IsContainer,
			},
			Coverage: coverageView{
				PackagesInspected: rep.Metadata.Coverage.PackagesInspected,
				PackagesMatched:   rep.Metadata.Coverage.PackagesMatched,
				AdvisoriesChecked: rep.Metadata.Coverage.AdvisoriesChecked,
				Sources:           rep.Metadata.Coverage.Sources,
				NotCovered:        rep.Metadata.Coverage.NotCovered,
				Limitations:       rep.Metadata.Coverage.Limitations,
			},
		}
		if hv.Host == "" {
			hv.Host = run.Host
			hv.Asset.Hostname = run.Host
		}
		if rep.Metadata.FinishedAt != nil {
			hv.FinishedAt = *rep.Metadata.FinishedAt
		} else {
			hv.FinishedAt = run.FinishedAt
		}
		hv.Packages = append(hv.Packages, rep.Inventory.Packages...)
		for _, sk := range rep.Metadata.SkippedChecks {
			hv.Skipped = append(hv.Skipped, skippedRow{Check: sk.Check, Reason: sk.Reason})
		}
		// Findings that duplicate an OS-owned Python package are skipped here: the OS package
		// manager reports that copy under its real name, and the PyPI copy would carry the
		// wrong remediation (pip cannot upgrade a distribution package).
		suppressedRows, reasons := suppressDistroPythonDuplicates(rep)
		if len(reasons) > 0 {
			hv.Suppressed = append(hv.Suppressed, reasons...)
		}
		for _, f := range rep.Findings {
			if suppressedRows[f.FindingID] {
				continue
			}
			row := toVulnRow(hv.Host, rep.ReportID, f)
			if fs, ok := firstSeen[hv.Host][row.Fingerprint]; ok && !fs.IsZero() {
				row.FirstSeen = fs.UTC().Format(time.RFC3339)
			}
			hv.Findings = append(hv.Findings, row)
			if _, exists := ds.ByID[row.ID]; !exists {
				copyRow := row
				ds.ByID[row.ID] = &copyRow
				ds.Vulns = append(ds.Vulns, row)
			}
		}
		ds.Hosts[hv.Host] = hv
	}

	// Analyst-verified corrections are an overlay: stored reports are never
	// rewritten, so the scanner verdict and the correction remain comparable.
	if states, err := s.improve.States(ctx); err == nil && len(states) > 0 {
		ds.applyAnalystStates(states)
	}
	return ds, nil
}

func (s *Server) feedRows(ctx context.Context) ([]feedRow, error) {
	states, err := s.store.SyncStates(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]feedRow, 0, len(states))
	for _, st := range states {
		stale := time.Since(st.LastSync) > 7*24*time.Hour
		if st.Source == "EPSS" {
			stale = time.Since(st.LastSync) > 3*24*time.Hour
		}
		last := ""
		if !st.LastSync.IsZero() {
			last = st.LastSync.UTC().Format(time.RFC3339)
		}
		out = append(out, feedRow{Source: st.Source, LastSync: last, Records: st.Records, Stale: stale})
	}
	return out, nil
}

// ------------------------------------------------------- report wire types ---

// reportDoc mirrors the parts of model.Report the API reads. Keeping a local
// copy means the wire format is explicit and stable even if the model grows.
type reportDoc struct {
	SchemaVersion string `json:"schema_version"`
	ReportID      string `json:"report_id"`
	Metadata      struct {
		ToolVersion   string     `json:"tool_version"`
		StartedAt     time.Time  `json:"started_at"`
		FinishedAt    *time.Time `json:"finished_at"`
		Mode          string     `json:"mode"`
		Host          string     `json:"host"`
		Offline       bool       `json:"offline"`
		Errors        []string   `json:"errors"`
		SkippedChecks []struct {
			Check  string `json:"check"`
			Reason string `json:"reason"`
		} `json:"skipped_checks"`
		Coverage struct {
			PackagesInspected int      `json:"packages_inspected"`
			PackagesMatched   int      `json:"packages_matched"`
			AdvisoriesChecked int      `json:"advisories_checked"`
			Sources           []string `json:"sources_used"`
			NotCovered        []string `json:"not_covered"`
			Limitations       []string `json:"limitations"`
		} `json:"coverage"`
		Policy struct {
			FailOnSeverity string `json:"fail_on_severity"`
			FailOnKEV      bool   `json:"fail_on_kev"`
		} `json:"policy"`
	} `json:"metadata"`
	Inventory struct {
		Asset    assetInfo    `json:"asset"`
		Packages []packageRow `json:"packages"`
	} `json:"inventory"`
	Findings []findingDoc `json:"findings"`
	Summary  struct {
		Total       int            `json:"total"`
		BySeverity  map[string]int `json:"by_severity"`
		ByAffected  map[string]int `json:"by_affected"`
		KEVCount    int            `json:"kev_count"`
		Actionable  int            `json:"actionable"`
		NotAffected int            `json:"not_affected"`
	} `json:"summary"`
}

type findingDoc struct {
	FindingID        string   `json:"finding_id"`
	Asset            string   `json:"asset"`
	Product          string   `json:"product"`
	InstalledVersion string   `json:"installed_version"`
	Ecosystem        string   `json:"ecosystem"`
	VulnerabilityID  string   `json:"vulnerability_id"`
	Aliases          []string `json:"aliases"`
	Source           string   `json:"source"`
	Affected         string   `json:"affected"`
	ValidationStatus string   `json:"validation_status"`
	Confidence       string   `json:"confidence"`
	Severity         string   `json:"severity"`
	CVSS             *struct {
		Vector string  `json:"vector"`
		Score  float64 `json:"score"`
		Source string  `json:"source"`
	} `json:"cvss"`
	EPSS *struct {
		Score      float64 `json:"score"`
		Percentile float64 `json:"percentile"`
	} `json:"epss"`
	CISAKEV        bool          `json:"cisa_kev"`
	FixedVersion   string        `json:"fixed_version"`
	Remediation    string        `json:"remediation"`
	Explanation    string        `json:"explanation"`
	Raise          []string      `json:"confidence_increase_evidence"`
	Lower          []string      `json:"confidence_reduction_evidence"`
	RiskScore      float64       `json:"risk_score"`
	AdvisoryID     string        `json:"advisory_id"`
	Evidence       []evidenceRow `json:"evidence"`
	VendorAdvisory *struct {
		Vendor       string `json:"vendor"`
		ID           string `json:"id"`
		URL          string `json:"url"`
		FixedVersion string `json:"fixed_version"`
	} `json:"vendor_advisory"`
	KEV *struct {
		DateAdded  string `json:"date_added"`
		Ransomware string `json:"known_ransomware_use"`
	} `json:"kev"`
	RiskFactors []riskRow `json:"risk_factors"`
}

func toVulnRow(host, reportID string, f findingDoc) vulnRow {
	row := vulnRow{
		ID:               findingIdentity(host, f),
		Fingerprint:      findingFingerprint(f),
		Finding:          f.FindingID,
		ReportID:         reportID,
		CVE:              primaryCVE(f),
		Aliases:          f.Aliases,
		Asset:            host,
		Product:          f.Product,
		InstalledVersion: f.InstalledVersion,
		Ecosystem:        f.Ecosystem,
		Severity:         normalizeSeverity(f.Severity),
		Affected:         f.Affected,
		Confidence:       f.Confidence,
		Validation:       f.ValidationStatus,
		KEV:              f.CISAKEV,
		FixedVersion:     f.FixedVersion,
		Remediation:      f.Remediation,
		Source:           f.Source,
		AdvisoryID:       f.AdvisoryID,
		RiskScore:        f.RiskScore,
		Explanation:      f.Explanation,
		Evidence:         f.Evidence,
		Raise:            f.Raise,
		Lower:            f.Lower,
		RiskFactors:      f.RiskFactors,
	}
	if f.CVSS != nil {
		score := f.CVSS.Score
		row.CVSS = &score
		row.CVSSVector = f.CVSS.Vector
	}
	if f.EPSS != nil {
		score, pct := f.EPSS.Score, f.EPSS.Percentile
		row.EPSS = &score
		row.EPSSPercentile = &pct
	}
	if f.KEV != nil {
		row.KEVDateAdded = f.KEV.DateAdded
		row.Ransomware = f.KEV.Ransomware
	}
	if f.VendorAdvisory != nil {
		row.Vendor = f.VendorAdvisory.Vendor
	}
	row.References = referencesFor(f)
	return row
}

func primaryCVE(f findingDoc) string {
	if len(f.VulnerabilityID) > 4 && f.VulnerabilityID[:4] == "CVE-" {
		return f.VulnerabilityID
	}
	for _, a := range f.Aliases {
		if len(a) > 4 && a[:4] == "CVE-" {
			return a
		}
	}
	return f.VulnerabilityID
}

func referencesFor(f findingDoc) []linkRow {
	var out []linkRow
	seen := map[string]bool{}
	add := func(label, url string) {
		if url == "" || seen[url] {
			return
		}
		seen[url] = true
		out = append(out, linkRow{Label: label, URL: url})
	}
	cve := primaryCVE(f)
	if len(cve) > 4 && cve[:4] == "CVE-" {
		add("NVD", "https://nvd.nist.gov/vuln/detail/"+cve)
		add("CISA KEV catalog", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog")
		add("EPSS", "https://api.first.org/data/v1/epss?cve="+cve)
	}
	if f.AdvisoryID != "" {
		add("OSV advisory", "https://osv.dev/vulnerability/"+f.AdvisoryID)
	}
	if f.VendorAdvisory != nil && f.VendorAdvisory.URL != "" {
		add(f.VendorAdvisory.Vendor+" advisory", f.VendorAdvisory.URL)
	}
	for _, e := range f.Evidence {
		if e.URL != "" {
			add("Advisory reference", e.URL)
		}
	}
	return out
}

func normalizeSeverity(sev string) string {
	switch sev {
	case "critical", "high", "medium", "low", "none":
		return sev
	default:
		return "unknown"
	}
}

// suppressDistroPythonDuplicates finds findings that duplicate an OS-owned Python package.
//
// The stored report is mapped onto the shared model so the same rule applies here, at ingest and
// in the collector: one definition of "the distribution owns this", three places that use it.
func suppressDistroPythonDuplicates(rep reportDoc) (map[string]bool, []string) {
	m := model.Report{ReportID: rep.ReportID}
	for _, p := range rep.Inventory.Packages {
		m.Inventory.Packages = append(m.Inventory.Packages, model.Package{
			Name: p.Name, Version: p.Version, Ecosystem: p.Ecosystem,
			Source: model.PackageOrigin(p.Source), Origin: p.Origin,
		})
	}
	for _, f := range rep.Findings {
		m.Findings = append(m.Findings, model.Finding{
			FindingID: f.FindingID, Product: f.Product,
			InstalledVersion: f.InstalledVersion, Ecosystem: f.Ecosystem,
		})
	}
	_, _, reasons := report.FilterSuppressed(m)
	suppressed := map[string]bool{}
	if len(reasons) == 0 {
		return suppressed, nil
	}
	// FilterSuppressed drops in order; walk the same order to learn which ids went.
	kept := map[string]bool{}
	keptFindings, _, _ := report.FilterSuppressed(m)
	for _, f := range keptFindings {
		kept[f.FindingID] = true
	}
	for _, f := range m.Findings {
		if !kept[f.FindingID] {
			suppressed[f.FindingID] = true
		}
	}
	return suppressed, reasons
}
