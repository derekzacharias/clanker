package ticketing

import (
	"fmt"
	"sort"
	"strings"
)

// Finding is the evidence the issue text is built from. It mirrors only what the
// description needs, so the renderer has no dependency on the store or the API types.
type Finding struct {
	// FindingKey is the stable identity (asset + package + version + advisory), used for
	// duplicate prevention and for the marker a retry searches for.
	FindingKey       string
	Asset            string
	Hostname         string
	OS               string
	OSVersion        string
	Product          string
	InstalledVersion string
	Ecosystem        string
	VulnerabilityID  string
	Aliases          []string
	Severity         string
	// EffectiveSeverity accounts for KEV and internet exposure; it is what the SLA was
	// computed from, and what the ticket should say.
	EffectiveSeverity string
	CVSS              *float64
	CVSSVector        string
	EPSS              *float64
	KEV               bool
	Explanation       string
	// RemediationText and its provenance. The brief requires keeping verified advisory
	// guidance distinct from anything the scanner generated itself.
	RemediationText   string
	RemediationSource string
	RemediationOrigin string
	FixedVersion      string
	Evidence          []Evidence
	References        []Reference
	Arch              string
	FirstSeen         string
	LastSeen          string
	ReportID          string
	// Ownership, when the work item has it.
	Team     string
	Owner    string
	DueAt    string
	Priority string
	// Access is how a person reaches the host (SSH target, jump host, runbook).
	// References only: no credentials are ever stored or printed.
	Access AccessBlock
	// Runbook is the team's own procedure, already rendered with this finding's values.
	Runbook string
}

// Evidence is one scanner observation.
type Evidence struct {
	Kind   string
	Source string
	Detail string
	URL    string
}

// Reference is an advisory or vendor link.
type Reference struct {
	Label string
	URL   string
}

// Marker is embedded in every issue description. A retry after a timeout searches for it,
// so an issue that GitLab already created is adopted rather than duplicated.
func Marker(findingKey string) string {
	return "<!-- clanker-guard:finding:" + findingKey + " -->"
}

// MarkerSearch is the text a recovery lookup passes to GitLab's search.
func MarkerSearch(findingKey string) string {
	return "clanker-guard:finding:" + findingKey
}

// Title builds "[HIGH] CVE-XXXX-YYYY | Outdated <package> | <asset>".
//
// The asset makes a list of tickets readable in GitLab, and the severity prefix is what
// makes them sortable there without opening each one.
func Title(f Finding) string {
	sev := strings.ToUpper(firstNonEmpty(f.EffectiveSeverity, f.Severity, "unknown"))
	cve := firstNonEmpty(f.VulnerabilityID, "(no advisory id)")
	host := firstNonEmpty(f.Hostname, f.Asset, "unknown host")
	pkg := firstNonEmpty(f.Product, f.Ecosystem, "unknown package")
	return fmt.Sprintf("[%s] %s | %s | %s", sev, cve, host, pkg)
}

// RenderDescription produces the issue body from the structured plan.
//
// Kept as the entry point the service and the API already use; the content comes from
// BuildPlan + Render so the ticket and the preview can never drift apart.
func RenderDescription(f Finding) string {
	_, body := Compose(f)
	return body
}

// Labels merges configured default labels with the ones derived from the finding:
// severity and KEV first, because that is what people filter on in GitLab.
func Labels(configured []string, f Finding) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(configured)+3)
	add := func(l string) {
		l = strings.TrimSpace(l)
		if l == "" || seen[strings.ToLower(l)] {
			return
		}
		seen[strings.ToLower(l)] = true
		out = append(out, l)
	}
	if sev := strings.ToLower(firstNonEmpty(f.EffectiveSeverity, f.Severity)); sev != "" {
		add("security")
		add(sev)
	}
	if f.KEV {
		add("cisa-kev")
	}
	if f.FixedVersion != "" {
		add("fix-available")
	} else {
		add("needs-triage")
	}
	for _, l := range configured {
		add(l)
	}
	return out
}

// LabelString is the comma-separated form GitLab's create endpoint accepts.
func LabelString(labels []string) string {
	clean := make([]string, 0, len(labels))
	for _, l := range labels {
		l = strings.TrimSpace(l)
		if l != "" {
			clean = append(clean, l)
		}
	}
	sort.SliceStable(clean, func(i, j int) bool { return false })
	return strings.Join(clean, ",")
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func joinNonEmpty(values ...string) string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			out = append(out, strings.TrimSpace(v))
		}
	}
	return strings.Join(out, " ")
}

func teamInParens(team string) string {
	if strings.TrimSpace(team) == "" {
		return ""
	}
	return "(" + strings.TrimSpace(team) + ")"
}

func oneLine(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func trimFloat(f float64) string {
	s := fmt.Sprintf("%.1f", f)
	return strings.TrimSuffix(s, ".0")
}
