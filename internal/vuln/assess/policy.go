package assess

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Policy contains the detection decisions that the improvement engine may tune.
//
// This is the seam that makes self-improvement real rather than decorative: a
// versioned rule changes these values, evaluation measures the effect on
// fixtures, and deployment changes what the next scan reports.
//
// Every field has a safe default equal to the shipped behaviour. Unknown or
// out-of-range values are rejected at load time (see Validate) so a bad rule can
// never silently weaken detection.
type Policy struct {
	// BackportDowngrade downgrades an upstream-only advisory match on a
	// distribution build from "confirmed" to BackportOutcome. Distributions
	// backport fixes without changing the upstream version, so a bare range
	// match is not authoritative.
	BackportDowngrade bool `json:"backport_downgrade"`
	// BackportOutcome is "probable" or "needs_investigation".
	BackportOutcome string `json:"backport_outcome"`
	// UnlistedBuildOutcome is the verdict when the installed build is newer than
	// every version the vendor enumerates as affected and the build is not from
	// a third party: "not_affected" or "needs_investigation".
	UnlistedBuildOutcome string `json:"unlisted_build_outcome"`
	// ForeignBuildOutcome is the verdict for third-party builds (NodeSource, PPA,
	// COPR, snap stubs) that vendor enumeration cannot resolve:
	// "needs_investigation" or "probable".
	ForeignBuildOutcome string `json:"foreign_build_outcome"`
	// SnapStubUnresolved treats snap transition packages (version marker
	// "snap1") as needs_investigation: the vulnerable code lives in the snap,
	// not in the stub the package manager reports.
	SnapStubUnresolved bool `json:"snap_stub_unresolved"`
	// TrustedVendors lists distribution vendors whose advisories are treated as
	// authoritative for patched builds.
	TrustedVendors []string `json:"trusted_vendors"`
}

// DefaultPolicy is the shipped detection behaviour.
func DefaultPolicy() Policy {
	return Policy{
		BackportDowngrade:    true,
		BackportOutcome:      string(probable),
		UnlistedBuildOutcome: "not_affected",
		ForeignBuildOutcome:  string(needsInvestigation),
		SnapStubUnresolved:   false,
		TrustedVendors:       []string{"Ubuntu", "Debian", "Red Hat", "Rocky Linux", "AlmaLinux", "Fedora", "Alpine"},
	}
}

// WithDefaults fills zero values from DefaultPolicy so callers can construct a
// partial policy (for example from a stored rule payload).
func (p Policy) WithDefaults() Policy {
	d := DefaultPolicy()
	if p.BackportOutcome == "" {
		p.BackportOutcome = d.BackportOutcome
	}
	if p.UnlistedBuildOutcome == "" {
		p.UnlistedBuildOutcome = d.UnlistedBuildOutcome
	}
	if p.ForeignBuildOutcome == "" {
		p.ForeignBuildOutcome = d.ForeignBuildOutcome
	}
	if len(p.TrustedVendors) == 0 {
		p.TrustedVendors = d.TrustedVendors
	}
	// BackportDowngrade / SnapStubUnresolved default to the shipped behaviour
	// only when the whole policy is zero; callers that set them explicitly keep
	// their value. WithDefaults therefore cannot distinguish "false" from
	// "unset", which is why DefaultPolicy is used as the base by callers.
	return p
}

// Validate rejects policies that could weaken detection silently.
func (p Policy) Validate() error {
	switch p.BackportOutcome {
	case string(probable), string(needsInvestigation):
	default:
		return fmt.Errorf("backport_outcome must be probable or needs_investigation, got %q", p.BackportOutcome)
	}
	switch p.UnlistedBuildOutcome {
	case "not_affected", string(needsInvestigation):
	default:
		return fmt.Errorf("unlisted_build_outcome must be not_affected or needs_investigation, got %q", p.UnlistedBuildOutcome)
	}
	switch p.ForeignBuildOutcome {
	case string(needsInvestigation), string(probable):
	default:
		return fmt.Errorf("foreign_build_outcome must be needs_investigation or probable, got %q", p.ForeignBuildOutcome)
	}
	return nil
}

// PolicyNotes returns human-readable differences from the default policy, used
// in reports so a reader can see which rules shaped the findings.
func (p Policy) Notes() []string {
	d := DefaultPolicy()
	var out []string
	if p.BackportDowngrade != d.BackportDowngrade {
		out = append(out, fmt.Sprintf("backport downgrade %v", p.BackportDowngrade))
	}
	if p.BackportOutcome != d.BackportOutcome {
		out = append(out, fmt.Sprintf("backport outcome %q", p.BackportOutcome))
	}
	if p.UnlistedBuildOutcome != d.UnlistedBuildOutcome {
		out = append(out, fmt.Sprintf("unlisted build outcome %q", p.UnlistedBuildOutcome))
	}
	if p.ForeignBuildOutcome != d.ForeignBuildOutcome {
		out = append(out, fmt.Sprintf("third-party build outcome %q", p.ForeignBuildOutcome))
	}
	if p.SnapStubUnresolved != d.SnapStubUnresolved {
		out = append(out, fmt.Sprintf("snap stub unresolved %v", p.SnapStubUnresolved))
	}
	return out
}

// ParsePolicy builds a complete policy from a stored rule payload: it starts
// from the shipped defaults and overlays the supplied fields. Starting from the
// defaults is what prevents a partial rule from accidentally turning off
// backport awareness.
func ParsePolicy(data []byte) (Policy, error) {
	p := DefaultPolicy()
	if len(data) > 0 {
		if err := json.Unmarshal(data, &p); err != nil {
			return Policy{}, fmt.Errorf("policy payload is not valid JSON: %w", err)
		}
	}
	if err := p.Validate(); err != nil {
		return Policy{}, err
	}
	return p, nil
}

// MarshalPolicy renders a policy for storage in a versioned rule.
func MarshalPolicy(p Policy) ([]byte, error) { return json.MarshalIndent(p, "", "  ") }

// ------------------------------------------------------------------ helpers ---

// These aliases keep the policy readable without exporting model constants for
// every enum in the file.
type applicability = string
type confidence = string

const (
	confirmed          applicability = "confirmed_applicability"
	validated          applicability = "validated_behavior"
	probable           applicability = "probable"
	potential          applicability = "potential"
	needsInvestigation applicability = "needs_investigation"
	notAffected        applicability = "not_affected"

	confidenceHigh   confidence = "high"
	confidenceMedium confidence = "medium"
	confidenceLow    confidence = "low"
)

// isSnapStub reports whether a package version identifies a snap transition
// wrapper rather than the application itself.
func isSnapStub(version string) bool {
	return strings.Contains(strings.ToLower(version), "snap1")
}
