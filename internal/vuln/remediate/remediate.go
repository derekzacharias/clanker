// Package remediate turns findings into owned remediation work.
//
// A finding says "this host has this problem". A remediation item says who is
// responsible, when it is due, and where it is in its lifecycle — the part an
// organisation actually manages. Findings stay immutable evidence: an item can only
// reach "resolved" through verification, never by someone marking it done.
package remediate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// State is the lifecycle of a remediation item.
type State string

// The lifecycle, in the order it normally moves. "Awaiting ownership" and the three
// terminal states are deliberately reachable from anywhere that still has work to do.
const (
	StateDetected            State = "detected"
	StateValidated           State = "validated"
	StateAwaitingOwnership   State = "awaiting_ownership"
	StateAssigned            State = "assigned"
	StateAwaitingApproval    State = "awaiting_approval"
	StateScheduled           State = "scheduled"
	StateInProgress          State = "in_progress"
	StateApplied             State = "remediation_applied"
	StatePendingVerification State = "pending_verification"
	StateResolved            State = "resolved"
	StateFailed              State = "failed"
	StateRiskAccepted        State = "risk_accepted"
	StateFalsePositive       State = "false_positive"
)

// AllStates is the closed set used for validation.
var AllStates = []State{
	StateDetected, StateValidated, StateAwaitingOwnership, StateAssigned,
	StateAwaitingApproval, StateScheduled, StateInProgress, StateApplied,
	StatePendingVerification, StateResolved, StateFailed, StateRiskAccepted,
	StateFalsePositive,
}

// ValidState reports whether s is one of the defined states.
func ValidState(s State) bool {
	for _, candidate := range AllStates {
		if candidate == s {
			return true
		}
	}
	return false
}

// terminal states need no further work.
func terminal(s State) bool {
	return s == StateResolved || s == StateRiskAccepted || s == StateFalsePositive
}

// allowedTransitions encodes the workflow. It is deliberately explicit: a closed set
// is the only thing that stops "someone set the field" from becoming "work is done".
var allowedTransitions = map[State][]State{
	StateDetected:            {StateValidated, StateAwaitingOwnership, StateAssigned, StateRiskAccepted, StateFalsePositive},
	StateValidated:           {StateAwaitingOwnership, StateAssigned, StateRiskAccepted, StateFalsePositive},
	StateAwaitingOwnership:   {StateAssigned, StateValidated, StateRiskAccepted, StateFalsePositive},
	StateAssigned:            {StateAwaitingApproval, StateScheduled, StateInProgress, StateAwaitingOwnership, StateRiskAccepted, StateFalsePositive, StateDetected},
	StateAwaitingApproval:    {StateScheduled, StateInProgress, StateAssigned, StateRiskAccepted, StateFalsePositive},
	StateScheduled:           {StateInProgress, StateAwaitingApproval, StateAssigned, StateFailed},
	StateInProgress:          {StateApplied, StateFailed, StatePendingVerification},
	StateApplied:             {StatePendingVerification, StateFailed, StateInProgress},
	StatePendingVerification: {StateResolved, StateFailed, StateInProgress},
	StateFailed:              {StateAssigned, StateInProgress, StateScheduled, StateRiskAccepted},
	// A resolved or accepted item reopens as "detected" when a later assessment sees
	// the vulnerability again; a false positive stays closed.
	StateResolved:      {StateDetected},
	StateRiskAccepted:  {StateDetected},
	StateFalsePositive: {},
}

// CanTransition reports whether from → to is a legal move.
func CanTransition(from, to State) bool {
	if from == to {
		return true
	}
	for _, candidate := range allowedTransitions[from] {
		if candidate == to {
			return true
		}
	}
	return false
}

// Ownership is the responsibility recorded for one asset.
type Ownership struct {
	Asset             string `json:"asset"`
	Team              string `json:"team,omitempty"`
	Owner             string `json:"owner,omitempty"`
	Service           string `json:"service,omitempty"`
	Environment       string `json:"environment,omitempty"`
	Criticality       string `json:"criticality,omitempty"` // low|medium|high|critical
	Exposure          string `json:"exposure,omitempty"`    // internal|internet
	Contact           string `json:"contact,omitempty"`     // escalation path
	Mechanism         string `json:"mechanism,omitempty"`   // manual|agent
	MaintenanceWindow string `json:"maintenance_window,omitempty"`
	// Access describes how a person reaches the host, so a ticket can say it. These are
	// references, never credentials: a username, a jump host, a runbook URL. No keys, no
	// passwords, and nothing that would make this table a secret store.
	SSHUser    string    `json:"ssh_user,omitempty"`
	SSHHost    string    `json:"ssh_host,omitempty"` // empty means "the asset name"
	SSHJump    string    `json:"ssh_jump,omitempty"` // bastion host, if one is required
	RunbookURL string    `json:"runbook_url,omitempty"`
	Source     string    `json:"source,omitempty"` // manual|cmdb|cloud_tag|repo|triage
	Status     string    `json:"status"`           // owned|triage
	UpdatedAt  time.Time `json:"updated_at"`
}

// Item is one remediation work item.
type Item struct {
	ID               string     `json:"id"`
	Asset            string     `json:"asset"`
	FindingKey       string     `json:"finding_key"`
	VulnerabilityID  string     `json:"vulnerability_id"`
	Product          string     `json:"product"`
	InstalledVersion string     `json:"installed_version"`
	Ecosystem        string     `json:"ecosystem"`
	Severity         string     `json:"severity"`
	Category         string     `json:"category"`
	Team             string     `json:"team,omitempty"`
	Owner            string     `json:"owner,omitempty"`
	State            State      `json:"state"`
	Priority         string     `json:"priority"`
	DueAt            *time.Time `json:"due_at,omitempty"`
	FixedVersion     string     `json:"fixed_version,omitempty"`
	Remediation      string     `json:"remediation,omitempty"`
	Evidence         string     `json:"evidence,omitempty"`
	ReportID         string     `json:"report_id,omitempty"`
	// VerifiedReport is the assessment whose absence of this finding resolved the item.
	// It is the receipt: without one, "resolved" is only an assertion.
	VerifiedReport string `json:"verified_report_id,omitempty"`
	// Acceptance is the exception register: an accepted risk always has who, why and
	// until when. An exception without an end date is just a forgotten finding.
	AcceptReason    string     `json:"accept_reason,omitempty"`
	AcceptedBy      string     `json:"accepted_by,omitempty"`
	AcceptExpiresAt *time.Time `json:"accept_expires_at,omitempty"`
	Notes           string     `json:"notes,omitempty"`
	FirstSeen       time.Time  `json:"first_seen"`
	LastSeen        time.Time  `json:"last_seen"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// Overdue reports whether the item is past due and still needs work.
func (i Item) Overdue(now time.Time) bool {
	return i.DueAt != nil && !terminal(i.State) && now.After(*i.DueAt)
}

// AcceptanceExpired reports whether an accepted risk has passed its review date.
func (i Item) AcceptanceExpired(now time.Time) bool {
	return i.State == StateRiskAccepted && i.AcceptExpiresAt != nil && now.After(*i.AcceptExpiresAt)
}

// AcceptanceEndsSoon reports an exception that needs review within the window.
func (i Item) AcceptanceEndsSoon(now time.Time, window time.Duration) bool {
	if i.State != StateRiskAccepted || i.AcceptExpiresAt == nil {
		return false
	}
	return !now.After(*i.AcceptExpiresAt) && i.AcceptExpiresAt.Before(now.Add(window))
}

// Policy configures deadlines and routing. Zero values fall back to the documented
// defaults so a fresh deployment behaves sensibly without any configuration.
type Policy struct {
	// Days is the remediation window per severity.
	Days map[string]int `json:"days"`
	// AccelerateKEV treats known-exploited findings as critical.
	AccelerateKEV bool `json:"accelerate_kev"`
	// AccelerateInternetExposure treats internet-facing assets as one severity higher.
	AccelerateInternetExposure bool `json:"accelerate_internet_exposure"`
	// Teams overrides the default responsibility mapping per category.
	Teams map[string]string `json:"teams"`
}

// DefaultPolicy is the illustrative default from the requirements: 7/30/60/90 days,
// KEV and internet exposure escalate. Every value is configurable.
func DefaultPolicy() Policy {
	return Policy{
		Days:                       map[string]int{"critical": 7, "high": 30, "medium": 60, "low": 90, "unknown": 90},
		AccelerateKEV:              true,
		AccelerateInternetExposure: true,
		Teams:                      nil,
	}
}

// DefaultTeams is the responsibility model from the requirements, used when the
// organisation has not overridden a category.
//
// Every key here must be producible by Category: a mapping no finding can ever reach is
// configuration that reads as if it were in force while doing nothing. Two keys from the
// original requirements were dropped for exactly that reason — "app_source" (source
// scanning is not part of this build) and "policy_exception" (an accepted risk is a
// state, not a classification). TestDefaultTeamsAreAllReachable enforces this.
var DefaultTeams = map[string]string{
	"os_package":      "Infrastructure",
	"app_dependency":  "Development",
	"container_image": "Platform Engineering",
	"cloud_config":    "Cloud Engineering",
	"infrastructure":  "DevOps",
}

func (p Policy) teams() map[string]string {
	out := make(map[string]string, len(DefaultTeams))
	for k, v := range DefaultTeams {
		out[k] = v
	}
	for k, v := range p.Teams {
		if strings.TrimSpace(v) != "" {
			out[k] = strings.TrimSpace(v)
		}
	}
	return out
}

var severityRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

func raise(sev string) string {
	switch strings.ToLower(sev) {
	case "low":
		return "medium"
	case "medium":
		return "high"
	case "high", "critical":
		return "critical"
	default:
		return "unknown"
	}
}

// EffectiveSeverity applies the escalation rules that change a deadline.
func (p Policy) EffectiveSeverity(f model.Finding, own Ownership) string {
	sev := strings.ToLower(strings.TrimSpace(f.Severity))
	if sev == "" {
		sev = "unknown"
	}
	if p.AccelerateKEV && (f.CISAKEV || f.KEV != nil) {
		sev = "critical"
	}
	if p.AccelerateInternetExposure && strings.EqualFold(own.Exposure, "internet") {
		sev = raise(sev)
	}
	return sev
}

// DueAt computes the deadline for a finding on an owned asset. nil means the
// organisation has no window for that severity, so no deadline is invented.
func (p Policy) DueAt(now time.Time, f model.Finding, own Ownership) (*time.Time, string) {
	sev := p.EffectiveSeverity(f, own)
	days, ok := p.days()[sev]
	if !ok || days <= 0 {
		return nil, sev
	}
	due := now.AddDate(0, 0, days).UTC()
	return &due, sev
}

func (p Policy) days() map[string]int {
	if len(p.Days) == 0 {
		return DefaultPolicy().Days
	}
	return p.Days
}

// Priority maps severity, exploitation and what the asset is worth to an operational rank.
//
// Business criticality raises the rank but never the severity: a "high" finding on a
// payment host is still high, it is simply worked sooner. Conflating the two is how severity
// loses its meaning.
func (p Policy) Priority(f model.Finding, own Ownership) string {
	sev := p.EffectiveSeverity(f, own)
	// A business-critical or internet-facing asset is stepped up one rank, once.
	if sev != "critical" && (strings.EqualFold(own.Criticality, "critical") ||
		strings.EqualFold(own.Criticality, "high")) {
		sev = raise(sev)
	}
	switch sev {
	case "critical":
		return "P1"
	case "high":
		return "P2"
	case "medium":
		return "P3"
	default:
		return "P4"
	}
}

// Category classifies a finding so the responsibility mapping can answer it.
//
// The classification is deliberately conservative: container and application
// ecosystems are distinguished from OS packages because they route to different
// teams, and anything unknown is treated as an OS/infrastructure concern only when
// the ecosystem actually says so — otherwise it is returned as unclassified and the
// asset goes to triage rather than to an arbitrary team.
func Category(f model.Finding) string {
	eco := strings.ToLower(f.Ecosystem)
	switch {
	case strings.HasPrefix(eco, "container"), strings.Contains(eco, "image"):
		return "container_image"
	case strings.Contains(eco, "terraform"), strings.Contains(eco, "cloudformation"),
		strings.Contains(eco, "helm"), strings.Contains(eco, "kubernetes"), strings.Contains(eco, "k8s"),
		strings.Contains(eco, "ansible"), strings.Contains(eco, "pulumi"), strings.Contains(eco, "iac"),
		strings.Contains(eco, "aws"), strings.Contains(eco, "azure"), strings.Contains(eco, "gcp"),
		strings.Contains(eco, "cloud"):
		// Configuration of infrastructure-as-code platforms, where a fix is a plan and
		// an apply rather than a package upgrade in the owning team's release cycle.
		return "cloud_config"
	case strings.Contains(eco, "firmware"), strings.Contains(eco, "bios"), strings.Contains(eco, "uefi"),
		strings.Contains(eco, "kernel"), strings.Contains(eco, "hypervisor"), strings.Contains(eco, "esxi"),
		strings.Contains(eco, "hardware"):
		// Below the OS package layer: firmware and hypervisor patches need a maintenance
		// window and a restart, which is a different process from a package upgrade.
		return "infrastructure"
	case strings.Contains(eco, "npm"), strings.Contains(eco, "pypi"), strings.Contains(eco, "pip"),
		strings.Contains(eco, "rubygems"), strings.Contains(eco, "gem"), strings.Contains(eco, "maven"),
		strings.Contains(eco, "go"), strings.Contains(eco, "cargo"), strings.Contains(eco, "nuget"),
		strings.Contains(eco, "packagist"):
		return "app_dependency"
	case strings.Contains(eco, "ubuntu"), strings.Contains(eco, "debian"), strings.Contains(eco, "rhel"),
		strings.Contains(eco, "centos"), strings.Contains(eco, "fedora"), strings.Contains(eco, "alpine"),
		strings.Contains(eco, "suse"), strings.Contains(eco, "amazon"), strings.Contains(eco, "rocky"),
		strings.Contains(eco, "alma"), strings.Contains(eco, "windows"), strings.Contains(eco, "macos"),
		strings.Contains(eco, "brew"):
		return "os_package"
	default:
		return ""
	}
}

// Route decides who owns a finding.
//
// Precedence, per the requirements: an explicit asset ownership record wins; then
// the (configurable) category → team mapping; otherwise the item is unowned and goes
// to triage. It never defaults an unknown asset to the security team.
func (p Policy) Route(f model.Finding, own Ownership) (team, category string, triaged bool) {
	category = Category(f)
	if own.Status == "owned" && strings.TrimSpace(own.Team) != "" {
		return own.Team, category, false
	}
	if category == "" {
		return "", "", true
	}
	if team = p.teams()[category]; team != "" {
		return team, category, false
	}
	return "", category, true
}

// FindingKey is the stable identity of a finding within one asset. Remediation items
// are keyed by it, so a rescan updates the same item instead of creating another.
func FindingKey(asset string, f model.Finding) string {
	host := strings.TrimSpace(asset)
	if host == "" {
		host = strings.TrimSpace(f.Asset)
	}
	return model.FindingStableID(host, f)
}

// ItemID is the deterministic idempotency key for an item.
func ItemID(findingKey string) string {
	sum := sha256.Sum256([]byte(findingKey))
	return "REM-" + hex.EncodeToString(sum[:8])
}

// relevant reports whether a finding should become work at all: "not affected" and
// suppressed records are evidence, not tasks.
func relevant(f model.Finding) bool {
	if f.Affected == model.ApplicabilityNotAffected {
		return false
	}
	return strings.TrimSpace(f.VulnerabilityID) != ""
}

// Apply folds a report's findings into the store.
//
// Idempotent by design: the item id is derived from the asset + finding identity, so
// reconciling the same report twice changes nothing, and a later report updates the
// existing item (last seen, versions, evidence) instead of adding a duplicate. A
// finding that reappears after being resolved reopens as "detected"; a false positive
// stays closed.
func (s *Store) Reconcile(report model.Report, policy Policy) (created, updated, reopened int, err error) {
	now := s.now()
	host := strings.TrimSpace(report.Metadata.Host)
	for _, f := range report.Findings {
		if !relevant(f) {
			continue
		}
		asset := strings.TrimSpace(f.Asset)
		if asset == "" {
			asset = host
		}
		own, ownErr := s.Ownership(asset)
		if ownErr != nil {
			return created, updated, reopened, ownErr
		}
		key := FindingKey(asset, f)
		id := ItemID(key)

		existing, getErr := s.Get(id)
		if getErr != nil && !isNotFound(getErr) {
			return created, updated, reopened, getErr
		}

		team, category, triaged := policy.Route(f, own)
		due, sev := policy.DueAt(now, f, own)
		priority := policy.Priority(f, own)
		evidence := evidenceFor(f)

		if existing == nil {
			state := StateAssigned
			owner := own.Owner
			if triaged || team == "" {
				state = StateAwaitingOwnership
				owner = ""
			}
			item := Item{
				ID: id, Asset: asset, FindingKey: key,
				VulnerabilityID: f.VulnerabilityID, Product: f.Product,
				InstalledVersion: f.InstalledVersion, Ecosystem: f.Ecosystem,
				Severity: sev, Category: category, Team: team, Owner: owner,
				State: state, Priority: priority, DueAt: due,
				FixedVersion: f.FixedVersion, Remediation: f.Remediation,
				Evidence: evidence, ReportID: report.ReportID,
				FirstSeen: now, LastSeen: now, UpdatedAt: now,
			}
			if err := s.insert(item); err != nil {
				return created, updated, reopened, err
			}
			created++
			continue
		}

		// Existing item: refresh the evidence, keep the human decisions.
		item := *existing
		item.LastSeen = now
		item.UpdatedAt = now
		item.ReportID = report.ReportID
		item.Severity = sev
		item.Priority = priority
		item.FixedVersion = f.FixedVersion
		item.Remediation = f.Remediation
		item.Evidence = evidence
		if item.Team == "" && team != "" {
			item.Team = team
			if item.State == StateAwaitingOwnership {
				item.State = StateAssigned
				if item.Owner == "" {
					item.Owner = own.Owner
				}
			}
		}
		if item.DueAt == nil && due != nil {
			item.DueAt = due
		}
		// Reappearance after closure: reopen, do not silently stay resolved.
		if item.State == StateResolved || item.State == StateRiskAccepted {
			item.State = StateDetected
			item.Notes = strings.TrimSpace("reopened: still present in " + report.ReportID + " " + item.Notes)
			reopened++
		}
		if err := s.update(item); err != nil {
			return created, updated, reopened, err
		}
		updated++
	}
	return created, updated, reopened, nil
}

// evidenceFor is the one-line justification stored with the item: what was seen and
// what fixes it, without leaking scanner internals into the work item.
func evidenceFor(f model.Finding) string {
	parts := []string{strings.ToLower(strings.TrimSpace(f.Severity))}
	if f.FixedVersion != "" {
		parts = append(parts, "fixed in "+f.FixedVersion)
	} else {
		parts = append(parts, "no fixed version published")
	}
	if f.CISAKEV || f.KEV != nil {
		parts = append(parts, "known exploited")
	}
	if f.Confidence != "" {
		parts = append(parts, "confidence "+string(f.Confidence))
	}
	return strings.Join(parts, " · ")
}

// String forms are used in error messages and logs.
func (s State) String() string { return string(s) }

// ValidateState turns an untrusted string into a State.
func ValidateState(raw string) (State, error) {
	candidate := State(strings.ToLower(strings.TrimSpace(raw)))
	if !ValidState(candidate) {
		return "", fmt.Errorf("unknown remediation state %q", raw)
	}
	return candidate, nil
}

// IsTerminal reports whether a state means "no further work expected".
func IsTerminal(st State) bool { return terminal(st) }
