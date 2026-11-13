// Package improve implements Clanker Guard's controlled improvement loop.
//
// Design constraints (all enforced in code, not by prompt):
//   - analyst feedback is recorded but never treated as proof on its own;
//   - classification changes require evidence resolved from advisory data;
//   - a proposed change is a versioned detection policy, tested against fixtures
//     before it can be approved, and reversible by a single rollback;
//   - agents never push code or rules: every deployment is an explicit human
//     action recorded in an audit trail.
package improve

import (
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/assess"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// Verdict is the analyst's assessment of a finding.
type Verdict string

const (
	VerdictConfirmed           Verdict = "confirmed"
	VerdictFalsePositive       Verdict = "false_positive"
	VerdictNeedsInvestigation  Verdict = "needs_investigation"
	VerdictRemediated          Verdict = "remediated"
	VerdictRequestVerification Verdict = "request_verification"
)

// ValidVerdict reports whether v is supported by the API and CLI.
func ValidVerdict(v Verdict) bool {
	switch v {
	case VerdictConfirmed, VerdictFalsePositive, VerdictNeedsInvestigation, VerdictRemediated, VerdictRequestVerification:
		return true
	}
	return false
}

// ReasonCode is the structured reason for a review. Free text is stored as data
// and never parsed for instructions.
type ReasonCode string

const (
	ReasonVendorPatch     ReasonCode = "vendor_patch_installed"
	ReasonIdentification  ReasonCode = "incorrect_identification"
	ReasonFeatureDisabled ReasonCode = "feature_not_enabled"
	ReasonNotApplicable   ReasonCode = "advisory_not_applicable"
	ReasonOther           ReasonCode = "other"
)

// ValidReason reports whether r is a supported reason code.
func ValidReason(r ReasonCode) bool {
	switch r {
	case ReasonVendorPatch, ReasonIdentification, ReasonFeatureDisabled, ReasonNotApplicable, ReasonOther, "":
		return true
	}
	return false
}

// Status is the improvement lifecycle state.
type Status string

const (
	StatusDiscovered       Status = "discovered"
	StatusResearching      Status = "researching"
	StatusProposed         Status = "proposed"
	StatusTesting          Status = "testing"
	StatusAwaitingApproval Status = "awaiting_approval"
	StatusApproved         Status = "approved"
	StatusDeployed         Status = "deployed"
	StatusMonitoring       Status = "monitoring"
	StatusRolledBack       Status = "rolled_back"
	StatusRejected         Status = "rejected"
)

// allowedTransitions is the only source of truth for lifecycle moves. Anything
// not listed here is rejected by the API and CLI.
var allowedTransitions = map[Status][]Status{
	StatusDiscovered:       {StatusResearching, StatusProposed, StatusRejected},
	StatusResearching:      {StatusProposed, StatusRejected},
	StatusProposed:         {StatusTesting, StatusRejected},
	StatusTesting:          {StatusAwaitingApproval, StatusRejected},
	StatusAwaitingApproval: {StatusApproved, StatusRejected},
	StatusApproved:         {StatusDeployed, StatusRejected},
	StatusDeployed:         {StatusMonitoring, StatusRolledBack},
	StatusMonitoring:       {StatusRolledBack},
	StatusRolledBack:       {},
	StatusRejected:         {},
}

// CanTransition reports whether from → to is permitted.
func CanTransition(from, to Status) bool {
	for _, s := range allowedTransitions[from] {
		if s == to {
			return true
		}
	}
	return false
}

// Category keeps improvement dimensions separate, as required.
type Category string

const (
	CategoryDetectionAccuracy Category = "detection_accuracy"
	CategoryIntelligence      Category = "intelligence"
	CategoryCoverage          Category = "coverage"
	CategoryRisk              Category = "risk"
	CategoryUX                Category = "ux"
	CategoryPerformance       Category = "performance"
	CategoryCodeQuality       Category = "code_quality"
)

// FindingRef is the minimal finding snapshot the improvement engine needs. It is
// built from stored reports; no endpoint secrets or personal data enter it.
type FindingRef struct {
	ID            string `json:"id"`
	ReportID      string `json:"report_id"`
	Host          string `json:"host"`
	CVE           string `json:"cve"`
	AdvisoryID    string `json:"advisory_id"`
	Product       string `json:"product"`
	Version       string `json:"version"`
	Ecosystem     string `json:"ecosystem"`
	Severity      string `json:"severity"`
	Applicability string `json:"applicability"`
	Confidence    string `json:"confidence"`
	Explanation   string `json:"explanation"`
}

// Feedback is one analyst review.
type Feedback struct {
	ID            string        `json:"id"`
	Finding       FindingRef    `json:"finding"`
	Verdict       Verdict       `json:"verdict"`
	ReasonCode    ReasonCode    `json:"reason_code,omitempty"`
	ReasonText    string        `json:"reason_text,omitempty"`
	Analyst       string        `json:"analyst"`
	CreatedAt     time.Time     `json:"created_at"`
	Verification  *Verification `json:"verification,omitempty"`
	ImprovementID string        `json:"improvement_id,omitempty"`
}

// Verification is the deterministic result of checking feedback against advisory
// evidence. Only Supported results may change a classification.
type Verification struct {
	Supported   bool             `json:"supported"`
	Confidence  string           `json:"confidence"` // high | medium | low
	Explanation string           `json:"explanation"`
	Evidence    []model.Evidence `json:"evidence"`
	Original    string           `json:"original_applicability"`
	Reassessed  string           `json:"reassessed_applicability,omitempty"`
	Changed     bool             `json:"changed"`
	AdvisoryID  string           `json:"advisory_id,omitempty"`
	Category    string           `json:"category,omitempty"` // signature for the improvement engine
}

// State is the analyst-verified classification applied to a finding. The
// scanner's own classification is never overwritten; both are kept.
type State struct {
	FindingID     string           `json:"finding_id"`
	Verdict       Verdict          `json:"verdict"`
	Applicability string           `json:"applicability"`
	Confidence    string           `json:"confidence"`
	Explanation   string           `json:"explanation"`
	Evidence      []model.Evidence `json:"evidence"`
	FeedbackID    string           `json:"feedback_id"`
	UpdatedAt     time.Time        `json:"updated_at"`
}

// Fixture is one labelled evaluation case.
type Fixture struct {
	ID            string         `json:"id"`
	Description   string         `json:"description"`
	Label         string         `json:"label"` // affected | not_affected | unresolved
	Package       model.Package  `json:"package"`
	Advisory      intel.Advisory `json:"advisory"`
	Expect        string         `json:"expect"` // expected applicability under the candidate policy
	Origin        string         `json:"origin"` // baseline | feedback
	SourceFinding string         `json:"source_finding,omitempty"`
}

// Metrics are only reported when labelled fixtures exist.
type Metrics struct {
	Available bool    `json:"available"`
	Cases     int     `json:"cases"`
	TruePos   int     `json:"true_positives"`
	FalsePos  int     `json:"false_positives"`
	TrueNeg   int     `json:"true_negatives"`
	FalseNeg  int     `json:"false_negatives"`
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	Accuracy  float64 `json:"accuracy"`
}

// CaseResult is one evaluated fixture.
type CaseResult struct {
	Fixture   string `json:"fixture"`
	Label     string `json:"label"`
	Expected  string `json:"expected"`
	Baseline  string `json:"baseline"`
	Candidate string `json:"candidate"`
	Pass      bool   `json:"pass"`
	Note      string `json:"note,omitempty"`
}

// Evaluation is the sandboxed comparison of a candidate rule against the
// baseline. It never touches the network or the live corpus.
type Evaluation struct {
	Passed      bool         `json:"passed"`
	Baseline    Metrics      `json:"baseline"`
	Candidate   Metrics      `json:"candidate"`
	Cases       []CaseResult `json:"cases"`
	Regressions []string     `json:"regressions,omitempty"`
	Fixed       []string     `json:"fixed_cases,omitempty"`
	Notes       []string     `json:"notes,omitempty"`
	EvaluatedAt time.Time    `json:"evaluated_at"`
}

// Improvement is a versioned proposal with its evidence and test results.
type Improvement struct {
	ID               string           `json:"id"`
	Category         Category         `json:"category"`
	Status           Status           `json:"status"`
	Title            string           `json:"title"`
	Problem          string           `json:"problem"`
	ProposedChange   string           `json:"proposed_change"`
	ExpectedBenefit  string           `json:"expected_benefit"`
	RiskLevel        string           `json:"risk_level"` // low | medium | high
	Signature        string           `json:"signature"`
	AffectedFindings []string         `json:"affected_findings"`
	Evidence         []model.Evidence `json:"evidence"`
	Policy           *assess.Policy   `json:"policy,omitempty"`
	PolicyNotes      []string         `json:"policy_notes,omitempty"`
	Fixtures         []Fixture        `json:"fixtures,omitempty"`
	Evaluation       *Evaluation      `json:"evaluation,omitempty"`
	CreatedAt        time.Time        `json:"created_at"`
	UpdatedAt        time.Time        `json:"updated_at"`
	ApprovedBy       string           `json:"approved_by,omitempty"`
	ApprovedAt       *time.Time       `json:"approved_at,omitempty"`
	DeployedAt       *time.Time       `json:"deployed_at,omitempty"`
	RolledBackAt     *time.Time       `json:"rolled_back_at,omitempty"`
	RuleID           string           `json:"rule_id,omitempty"`
	RejectedReason   string           `json:"rejected_reason,omitempty"`
}

// Event is one lifecycle transition (audit trail).
type Event struct {
	ID            int64     `json:"id"`
	ImprovementID string    `json:"improvement_id"`
	From          Status    `json:"from"`
	To            Status    `json:"to"`
	Actor         string    `json:"actor"`
	Note          string    `json:"note,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

// Rule is a versioned detection rule (currently only detection_policy).
type Rule struct {
	ID            string     `json:"id"`
	Kind          string     `json:"kind"`
	Version       int        `json:"version"`
	Payload       string     `json:"payload"`
	ImprovementID string     `json:"improvement_id,omitempty"`
	Active        bool       `json:"active"`
	CreatedAt     time.Time  `json:"created_at"`
	DeactivatedAt *time.Time `json:"deactivated_at,omitempty"`
}

// RuleKindDetectionPolicy is the only rule kind this build can deploy. Anything
// else would be a code change, which this system deliberately cannot perform.
const RuleKindDetectionPolicy = "detection_policy"

// QualityMetrics summarises detection quality from reviewed findings. Values are
// only meaningful when the sample exists; the UI must not render absent ground
// truth as if it were measured.
type QualityMetrics struct {
	Reviewed                   int      `json:"reviewed"`
	Confirmed                  int      `json:"confirmed"`
	FalsePositives             int      `json:"false_positives"`
	NeedsInvestigation         int      `json:"needs_investigation"`
	Remediated                 int      `json:"remediated"`
	VerificationSupported      int      `json:"verification_supported"`
	VerificationContradicted   int      `json:"verification_contradicted"`
	VerificationInconclusive   int      `json:"verification_inconclusive"`
	FalsePositiveRate          *float64 `json:"false_positive_rate"`
	ReviewedRate               *float64 `json:"reviewed_rate"`
	FindingsConsidered         int      `json:"findings_considered"`
	Actionable                 int      `json:"actionable"`
	NeedsInvestigationFindings int      `json:"needs_investigation_findings"`
	OpenImprovements           int      `json:"open_improvements"`
	DeployedImprovements       int      `json:"deployed_improvements"`
	RejectedImprovements       int      `json:"rejected_improvements"`
	Notes                      []string `json:"notes,omitempty"`
}
