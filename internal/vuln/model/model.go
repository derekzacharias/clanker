// Package model defines the shared data structures for Clanker Guard.
//
// The package deliberately keeps inventory, advisories and findings separate:
// a package being installed is not evidence that an advisory applies, and an
// advisory matching a version is not evidence of exploitability.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"
)

// Applicability captures how strongly the evidence supports that an advisory
// applies to the observed software. It is intentionally independent from
// exploitability and from severity.
type Applicability string

const (
	// ApplicabilityConfirmed means an authoritative advisory (vendor or
	// ecosystem security tracker) states the installed version is affected.
	ApplicabilityConfirmed Applicability = "confirmed_applicability"
	// ApplicabilityValidated means a safe, vulnerability-specific check
	// observed the vulnerable behaviour.
	ApplicabilityValidated Applicability = "validated_behavior"
	// ApplicabilityProbable means strong evidence exists but at least one
	// prerequisite could not be verified.
	ApplicabilityProbable Applicability = "probable"
	// ApplicabilityPotential means only a version or fingerprint matches.
	ApplicabilityPotential Applicability = "potential"
	// ApplicabilityNotAffected means authoritative evidence shows the
	// vulnerable condition does not apply (e.g. vendor backported the fix).
	ApplicabilityNotAffected Applicability = "not_affected"
	// ApplicabilityNeedsInvestigation means evidence is missing or conflicting.
	ApplicabilityNeedsInvestigation Applicability = "needs_investigation"
)

// ValidationStatus records how far the validation pipeline got.
type ValidationStatus string

const (
	ValidationNotPerformed  ValidationStatus = "not_performed"
	ValidationPassive       ValidationStatus = "passive_fingerprint"
	ValidationVersion       ValidationStatus = "version_correlation"
	ValidationAuthenticated ValidationStatus = "authenticated_check"
	ValidationSignature     ValidationStatus = "signature_validation"
	ValidationActive        ValidationStatus = "active_verification"
)

// Confidence is a coarse bucket derived from the applicability state and the
// provenance of the evidence backing it.
type Confidence string

const (
	ConfidenceLow    Confidence = "low"
	ConfidenceMedium Confidence = "medium"
	ConfidenceHigh   Confidence = "high"
)

// Severity buckets.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityNone     = "none"
	SeverityUnknown  = "unknown"
)

// Ecosystem identifiers follow OSV naming where an OSV ecosystem exists
// (for example "Debian:12", "Ubuntu:24.04:LTS", "PyPI", "npm"), because the
// intel layer speaks OSV natively.
type Ecosystem string

const (
	EcosystemDebian    = "Debian"
	EcosystemUbuntu    = "Ubuntu"
	EcosystemPyPI      = "PyPI"
	EcosystemNPM       = "npm"
	EcosystemGo        = "Go"
	EcosystemCargo     = "crates.io"
	EcosystemMaven     = "Maven"
	EcosystemNuGet     = "NuGet"
	EcosystemRubyGems  = "RubyGems"
	EcosystemPackagist = "Packagist"
	EcosystemAlpine    = "Alpine"
	EcosystemRocky     = "Rocky Linux"
	EcosystemAlmaLinux = "AlmaLinux"
	EcosystemRedHat    = "Red Hat"
	EcosystemFedora    = "Fedora"
	EcosystemOpenSUSE  = "openSUSE"
	EcosystemSUSE      = "SUSE"
	EcosystemWindows   = "Windows"
	EcosystemUnknown   = "unknown"
)

// PackageOrigin records where an inventory entry came from. It is used for
// provenance in reports and for vendor-backport decisions.
type PackageOrigin string

const (
	OriginDpkg     PackageOrigin = "dpkg"
	OriginRPM      PackageOrigin = "rpm"
	OriginPip      PackageOrigin = "pip"
	OriginNpm      PackageOrigin = "npm"
	OriginGo       PackageOrigin = "go_modules"
	OriginCargo    PackageOrigin = "cargo"
	OriginGem      PackageOrigin = "gem"
	OriginAPK      PackageOrigin = "apk"
	OriginAppx     PackageOrigin = "appx"
	OriginDPKGInfo PackageOrigin = "dpkg_query"
	OriginManifest PackageOrigin = "manifest"
)

// PatchStatus records whether the distribution shipped the fix for a package.
type PatchStatus string

const (
	PatchUnknown     PatchStatus = "unknown"
	PatchVendorFixed PatchStatus = "vendor_fixed"
	PatchVulnerable  PatchStatus = "vulnerable"
)

// Package is one installed (or observed) software component.
type Package struct {
	Name      string        `json:"name"`
	Version   string        `json:"version"`
	Ecosystem string        `json:"ecosystem"`
	PURL      string        `json:"purl,omitempty"`
	Source    PackageOrigin `json:"source"`
	Manager   string        `json:"manager,omitempty"`
	Arch      string        `json:"arch,omitempty"`
	// Vendor is the distribution vendor that built the package, when known.
	// It drives backport awareness: Ubuntu/Debian/RHEL rebuild upstream
	// versions with security patches applied.
	Vendor  string `json:"vendor,omitempty"`
	Origin  string `json:"origin,omitempty"`
	Release string `json:"release,omitempty"`
	// PatchStatus is filled by the assessor when a vendor advisory can be
	// resolved for this package.
	PatchStatus PatchStatus `json:"patch_status"`
	// NeedsPrivileges marks inventory entries that only appear with elevated
	// rights (the collector records the gap explicitly instead of hiding it).
	NeedsPrivileges bool `json:"needs_privileges,omitempty"`
}

// Asset describes the scanned endpoint.
type Asset struct {
	Hostname    string `json:"hostname"`
	OS          string `json:"os"`
	OSVersion   string `json:"os_version"`
	OSCodename  string `json:"os_codename,omitempty"`
	Kernel      string `json:"kernel,omitempty"`
	Arch        string `json:"arch,omitempty"`
	DistroID    string `json:"distro_id,omitempty"`
	IsContainer bool   `json:"is_container,omitempty"`
}

// Inventory is the complete output of the inventory stage.
type Inventory struct {
	Asset       Asset          `json:"asset"`
	Packages    []Package      `json:"packages"`
	CollectedAt time.Time      `json:"collected_at"`
	Warnings    []string       `json:"warnings,omitempty"`
	Skipped     []SkippedCheck `json:"skipped_checks,omitempty"`
	// Windows is present only on Windows endpoints. It is an optional block so reports
	// written by older agents stay valid, and a Windows report without it is treated as
	// "not assessed" rather than "nothing to fix".
	Windows *WindowsState `json:"windows,omitempty"`
}

// WindowsState is what only a Windows endpoint can report: the servicing identity, the
// updates it already has, the updates Windows itself says are applicable and missing, and
// the environment facts that change how a fix behaves (pending reboot, runtimes).
type WindowsState struct {
	// Product / DisplayVersion / Build come from the registry identity.
	Product        string `json:"product,omitempty"`
	DisplayVersion string `json:"display_version,omitempty"`
	Build          string `json:"build,omitempty"`
	Edition        string `json:"edition,omitempty"`
	// InstalledUpdates are KB identifiers already present (Get-HotFix / WU history).
	InstalledUpdates []string `json:"installed_updates,omitempty"`
	// MissingUpdates is the Windows Update Agent's own answer to "what is applicable and
	// not installed". It is the evidence a Windows finding rests on.
	MissingUpdates []WindowsUpdate `json:"missing_updates,omitempty"`
	// DotNet lists installed .NET Framework / runtime versions.
	DotNet []string `json:"dotnet,omitempty"`
	// PendingReboot marks a host whose servicing state is not final until it reboots.
	PendingReboot  bool     `json:"pending_reboot,omitempty"`
	PendingReasons []string `json:"pending_reboot_reasons,omitempty"`
	// WUAStatus is "ok", "unavailable", "running", or "error: <reason>". Anything but "ok"
	// means update applicability was not assessed.
	WUAStatus string `json:"wua_status,omitempty"`
	// CollectorStatus records per-source outcomes so partial coverage is visible.
	CollectorStatus map[string]string `json:"collector_status,omitempty"`
}

// WindowsUpdate is one applicable, not-installed update as the Windows Update Agent
// describes it. Only read-only details are collected: nothing is downloaded or installed.
type WindowsUpdate struct {
	Title          string   `json:"title"`
	KBs            []string `json:"kb_ids,omitempty"`
	MsrcSeverity   string   `json:"msrc_severity,omitempty"`
	Classification []string `json:"classifications,omitempty"`
	RebootBehavior string   `json:"reboot_behavior,omitempty"`
	Downloaded     bool     `json:"downloaded,omitempty"`
	SupportURL     string   `json:"support_url,omitempty"`
}

// IsSecurityUpdate reports whether the update is classified as a security update.
func (u WindowsUpdate) IsSecurityUpdate() bool {
	for _, c := range u.Classification {
		if strings.Contains(strings.ToLower(c), "security") {
			return true
		}
	}
	return false
}

// SkippedCheck documents a capability that could not run (missing tool,
// privileges, platform) so reports never imply full coverage.
type SkippedCheck struct {
	Check  string `json:"check"`
	Reason string `json:"reason"`
}

// CVSS holds severity data from an advisory.
type CVSS struct {
	Vector string  `json:"vector,omitempty"`
	Score  float64 `json:"score,omitempty"`
	// Source names the scoring authority (e.g. "NVD", "Ubuntu", "GitHub").
	Source string `json:"source,omitempty"`
}

// EPSS is the FIRST exploitation probability estimate.
type EPSS struct {
	Score      float64 `json:"score"`
	Percentile float64 `json:"percentile"`
	Model      string  `json:"model,omitempty"`
	ScoreDate  string  `json:"score_date,omitempty"`
}

// KEVInfo is CISA Known Exploited Vulnerabilities metadata.
type KEVInfo struct {
	CVEID      string `json:"cve_id"`
	DateAdded  string `json:"date_added,omitempty"`
	Vendor     string `json:"vendor,omitempty"`
	Product    string `json:"product,omitempty"`
	Name       string `json:"name,omitempty"`
	Ransomware string `json:"known_ransomware_use,omitempty"`
}

// Evidence is a single verifiable observation supporting (or refuting) a
// finding. Evidence entries are deliberately plain strings plus an origin so
// they can be reproduced by a human reviewer.
type Evidence struct {
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
	URL    string `json:"url,omitempty"`
	Source string `json:"source,omitempty"`
}

// VendorAdvisory links to the distribution/vendor statement used.
type VendorAdvisory struct {
	Vendor       string `json:"vendor"`
	ID           string `json:"id,omitempty"`
	URL          string `json:"url,omitempty"`
	FixedVersion string `json:"fixed_version,omitempty"`
	Statement    string `json:"statement,omitempty"`
}

// Finding is one (package, vulnerability) pair with its evidence chain.
type Finding struct {
	FindingID string `json:"finding_id"`
	// StableID is the cross-report identity (asset + package + version + CVE).
	StableID         string           `json:"stable_id,omitempty"`
	Asset            string           `json:"asset"`
	Product          string           `json:"product"`
	InstalledVersion string           `json:"installed_version"`
	Ecosystem        string           `json:"ecosystem"`
	VulnerabilityID  string           `json:"vulnerability_id"`
	Aliases          []string         `json:"aliases,omitempty"`
	Source           string           `json:"source"`
	Affected         Applicability    `json:"affected"`
	ValidationStatus ValidationStatus `json:"validation_status"`
	Confidence       Confidence       `json:"confidence"`
	Severity         string           `json:"severity"`
	CVSS             *CVSS            `json:"cvss"`
	EPSS             *EPSS            `json:"epss"`
	CISAKEV          bool             `json:"cisa_kev"`
	KEV              *KEVInfo         `json:"kev,omitempty"`
	Evidence         []Evidence       `json:"evidence"`
	VendorAdvisory   *VendorAdvisory  `json:"vendor_advisory"`
	FixedVersion     string           `json:"fixed_version"`
	Remediation      string           `json:"remediation"`
	LastChecked      *time.Time       `json:"last_checked"`
	// Explanation states why this classification was assigned.
	Explanation string `json:"explanation"`
	// RaiseConfidence / LowerConfidence describe what evidence would move the
	// classification, so reviewers know where the uncertainty lives.
	RaiseConfidence []string     `json:"confidence_increase_evidence,omitempty"`
	LowerConfidence []string     `json:"confidence_reduction_evidence,omitempty"`
	RiskScore       float64      `json:"risk_score"`
	RiskFactors     []RiskFactor `json:"risk_factors,omitempty"`
	// Internally used while correlating; never serialized as authoritative.
	AdvisoryID string `json:"advisory_id,omitempty"`
	PackageRef string `json:"package_ref,omitempty"`
}

// RiskFactor is one transparent contribution to the risk score.
type RiskFactor struct {
	Name   string  `json:"name"`
	Weight float64 `json:"weight"`
	Detail string  `json:"detail,omitempty"`
}

// ScanMetadata describes how a report was produced. It exists so a reader can
// judge freshness and coverage instead of trusting a bare finding list.
type ScanMetadata struct {
	ToolVersion   string         `json:"tool_version"`
	StartedAt     time.Time      `json:"started_at"`
	FinishedAt    *time.Time     `json:"finished_at,omitempty"`
	Mode          string         `json:"mode"` // local | network | sbom
	Host          string         `json:"host"`
	Offline       bool           `json:"offline"`
	FeedFreshness []FeedState    `json:"feed_freshness,omitempty"`
	Permissions   string         `json:"permissions,omitempty"`
	Errors        []string       `json:"errors,omitempty"`
	SkippedChecks []SkippedCheck `json:"skipped_checks,omitempty"`
	Coverage      Coverage       `json:"coverage"`
	Scope         *Scope         `json:"scope,omitempty"`
	Policy        Policy         `json:"policy"`
	// DetectionPolicy lists non-default detection decisions that shaped the
	// findings, so a report explains itself without external context.
	DetectionPolicy []string `json:"detection_policy,omitempty"`
}

// Coverage states what the scan actually inspected. A completed scan with no
// findings is reported as "no findings in the assessed scope", never as
// "vulnerability free".
type Coverage struct {
	PackagesInspected int      `json:"packages_inspected"`
	PackagesMatched   int      `json:"packages_matched"`
	AdvisoriesChecked int      `json:"advisories_checked"`
	Sources           []string `json:"sources_used"`
	NotCovered        []string `json:"not_covered,omitempty"`
	Limitations       []string `json:"limitations,omitempty"`
}

// FeedState is the freshness of one intelligence source.
type FeedState struct {
	Source   string     `json:"source"`
	LastSync *time.Time `json:"last_sync,omitempty"`
	Records  int        `json:"records,omitempty"`
	Stale    bool       `json:"stale"`
	Error    string     `json:"error,omitempty"`
}

// Scope is an explicitly authorised target set. Remote scanning refuses to run
// without one.
type Scope struct {
	Name         string    `json:"name"`
	AuthorizedBy string    `json:"authorized_by"`
	AuthorizedAt time.Time `json:"authorized_at"`
	ExpiresAt    time.Time `json:"expires_at,omitempty"`
	Targets      []string  `json:"targets"`
	Ports        []int     `json:"ports,omitempty"`
	MaxHosts     int       `json:"max_hosts,omitempty"`
	AllowPublic  bool      `json:"allow_public_addresses"`
	Notes        string    `json:"notes,omitempty"`
}

// Policy controls what the CLI treats as a failing scan.
type Policy struct {
	FailOnSeverity string `json:"fail_on_severity,omitempty"`
	FailOnKEV      bool   `json:"fail_on_kev"`
	MinConfidence  string `json:"min_confidence,omitempty"`
}

// Summary aggregates findings for quick reading.
type Summary struct {
	Total       int            `json:"total"`
	BySeverity  map[string]int `json:"by_severity"`
	ByAffected  map[string]int `json:"by_affected"`
	KEVCount    int            `json:"kev_count"`
	Actionable  int            `json:"actionable"`
	NotAffected int            `json:"not_affected"`
	Suppressed  int            `json:"suppressed"`
	TopRisk     []string       `json:"top_risk_finding_ids,omitempty"`
}

// Report is the machine-readable assessment output.
type Report struct {
	SchemaVersion string       `json:"schema_version"`
	ReportID      string       `json:"report_id"`
	Metadata      ScanMetadata `json:"metadata"`
	Inventory     Inventory    `json:"inventory"`
	Findings      []Finding    `json:"findings"`
	Summary       Summary      `json:"summary"`
	Delta         *Delta       `json:"delta,omitempty"`
}

// Delta compares this run with a previous one.
type Delta struct {
	PreviousReportID string   `json:"previous_report_id,omitempty"`
	NewFindings      []string `json:"new_findings,omitempty"`
	ResolvedFindings []string `json:"resolved_findings,omitempty"`
}

// RunRecord is what the local store keeps for history/deltas.
type RunRecord struct {
	ID           string    `json:"id"`
	Host         string    `json:"host"`
	StartedAt    time.Time `json:"started_at"`
	FinishedAt   time.Time `json:"finished_at"`
	FindingIDs   []string  `json:"finding_ids"`
	FindingCount int       `json:"finding_count"`
	Actionable   int       `json:"actionable"`
	KEVCount     int       `json:"kev_count"`
}

// ----------------------------------------------------------------- identity ---

// FindingFingerprint is the stable, host-independent identity of a finding. It
// is used for run history and delta comparison, so it must not depend on report
// numbering or timestamps.
func FindingFingerprint(f Finding) string {
	h := sha256.Sum256([]byte(strings.Join([]string{
		strings.ToLower(f.Ecosystem), strings.ToLower(f.Product), f.InstalledVersion, f.VulnerabilityID,
	}, "\x00")))
	return hex.EncodeToString(h[:8])
}

// FindingStableID is the identity used by the HTTP API and the CLI to address a
// finding: the fingerprint plus the asset, so two hosts cannot collide.
func FindingStableID(host string, f Finding) string {
	sum := sha256.Sum256([]byte(strings.ToLower(host) + "\x00" + FindingFingerprint(f)))
	return hex.EncodeToString(sum[:8])
}
