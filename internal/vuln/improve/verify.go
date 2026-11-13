package improve

import (
	"context"
	"fmt"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/assess"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// Verify checks analyst feedback against advisory evidence. It never trusts the
// analyst's word: a classification changes only when vendor data supports it.
//
// Outcomes:
//   - supported: evidence confirms the claim; Reassessed holds the new state;
//   - contradicted: evidence says the opposite; the scanner classification stands;
//   - inconclusive: nothing cached can decide it; the classification stands and
//     the gap is recorded so it can become an improvement candidate.
func (e *Engine) Verify(ctx context.Context, f FindingRef, verdict Verdict, reason ReasonCode) (*Verification, error) {
	v := &Verification{Original: f.Applicability, Confidence: "low"}

	// Only a false-positive claim asserts inapplicability. Every other verdict is
	// recorded as an analyst annotation and never rewrites the scanner verdict.
	if verdict != VerdictFalsePositive {
		v.Explanation = fmt.Sprintf(
			"Recorded the %q verdict as an analyst annotation. It does not assert inapplicability, so the scanner classification is unchanged.",
			verdict)
		return v, nil
	}

	switch reason {
	case ReasonVendorPatch:
		return e.verifyVendorPatch(ctx, f, v)
	case ReasonIdentification:
		return verifyIdentification(f, v)
	case ReasonFeatureDisabled, ReasonNotApplicable:
		v.Explanation = "This claim depends on runtime configuration that the scanner does not collect (enabled modules, bound interfaces). " +
			"No deterministic check can confirm it yet, so the finding keeps its scanner classification."
		v.Evidence = append(v.Evidence, model.Evidence{
			Kind:   "verification_gap",
			Detail: "configuration evidence is not collected by this build",
		})
		v.Category = "fp:configuration_evidence"
		return v, nil
	case ReasonOther, "":
		v.Explanation = "No structured reason was supplied, so there is nothing to verify against authoritative data. " +
			"The finding keeps its scanner classification."
		return v, nil
	default:
		return nil, fmt.Errorf("unsupported reason code %q", reason)
	}
}

// verifyVendorPatch looks for a distribution statement about this CVE and build.
func (e *Engine) verifyVendorPatch(ctx context.Context, f FindingRef, v *Verification) (*Verification, error) {
	if e.store == nil {
		v.Explanation = "Vendor advisories are unavailable (no intelligence cache), so the claim cannot be verified."
		return v, nil
	}
	advisories, err := e.store.AdvisoriesFor(ctx, f.Ecosystem, f.Product)
	if err != nil {
		return nil, fmt.Errorf("read cached advisories: %w", err)
	}
	pkg := model.Package{Name: f.Product, Version: f.Version, Ecosystem: f.Ecosystem}

	var contradicted, inconclusive []string
	for _, adv := range advisories {
		if !containsCVE(adv, f.CVE) {
			continue
		}
		if !assess.IsDistroAdvisory(adv) {
			continue // upstream data cannot decide distributor patch state
		}
		out, ok := assess.MatchWithPolicy(pkg, adv, assess.DefaultPolicy())
		if !ok {
			continue
		}
		switch out.Applicability {
		case model.ApplicabilityNotAffected:
			v.Supported = true
			v.Changed = true
			v.Confidence = "high"
			v.Reassessed = string(model.ApplicabilityNotAffected)
			v.AdvisoryID = adv.ID
			v.Category = "fp:vendor_backport"
			v.Explanation = fmt.Sprintf(
				"%s confirms the installed build is not affected: %s", adv.Source, out.Explanation)
			v.Evidence = append(v.Evidence, model.Evidence{
				Kind:   "vendor_advisory_not_affected",
				Source: adv.Source,
				Detail: fmt.Sprintf("%s %s: %s", adv.ID, f.Product, out.Explanation),
				URL:    advisoryURL(adv),
			})
			v.Evidence = append(v.Evidence, out.Evidence...)
			return v, nil
		case model.ApplicabilityConfirmed:
			contradicted = append(contradicted, fmt.Sprintf("%s lists %s %s as affected", adv.Source, f.Product, f.Version))
		}
	}

	if len(contradicted) > 0 {
		v.Supported = false
		v.Changed = false
		v.Confidence = "high"
		v.Explanation = "Authoritative distribution data contradicts the reported fix: " +
			strings.Join(contradicted, "; ") + ". The finding keeps its classification."
		for _, c := range contradicted {
			v.Evidence = append(v.Evidence, model.Evidence{Kind: "vendor_advisory_contradicts", Detail: c})
		}
		return v, nil
	}

	v.Explanation = fmt.Sprintf(
		"No cached %s advisory states that %s %s is unaffected by %s. The claim is plausible but unverified, so the finding keeps its classification.",
		f.Ecosystem, f.Product, f.Version, f.CVE)
	v.Evidence = append(v.Evidence, model.Evidence{
		Kind:   "verification_gap",
		Detail: "no distribution advisory for this CVE is present in the local intelligence cache",
	})
	v.Category = "fp:missing_vendor_data"
	_ = inconclusive
	return v, nil
}

// verifyIdentification handles "the scanner identified the software incorrectly".
// It is resolvable when the version itself shows the package is not the
// application (snap stub) or is not a distribution build at all.
func verifyIdentification(f FindingRef, v *Verification) (*Verification, error) {
	if assess.IsSnapStub(f.Version) {
		v.Supported = true
		v.Changed = string(model.ApplicabilityNeedsInvestigation) != f.Applicability
		v.Confidence = "high"
		v.Reassessed = string(model.ApplicabilityNeedsInvestigation)
		v.Category = "fp:snap_stub"
		v.Explanation = fmt.Sprintf(
			"%s is a snap transition package: the version points at a snap, not at an installed %s build, so advisory version data cannot be applied to it.",
			f.Version, f.Product)
		v.Evidence = append(v.Evidence, model.Evidence{
			Kind:   "package_identity",
			Detail: "version carries a snap transition marker",
		})
		return v, nil
	}
	if marker := assess.IdentifyBuildMarker(f.Ecosystem, f.Version); marker != "" {
		v.Supported = true
		v.Changed = string(model.ApplicabilityNeedsInvestigation) != f.Applicability
		v.Confidence = "medium"
		v.Reassessed = string(model.ApplicabilityNeedsInvestigation)
		v.Category = "fp:foreign_build"
		v.Explanation = fmt.Sprintf(
			"%s is a %s build, so the distribution's affected-version data does not describe it. The finding is downgraded to needs investigation rather than confirmed or dismissed.",
			f.Version, marker)
		v.Evidence = append(v.Evidence, model.Evidence{
			Kind:   "foreign_build",
			Detail: fmt.Sprintf("build marker %q", marker),
		})
		return v, nil
	}
	v.Explanation = "The installed version looks like a normal build for this ecosystem, so the identification claim is not supported by local evidence. " +
		"If the package is custom-built, record the build provenance and re-run the scan."
	return v, nil
}

// Reassess re-runs the matcher against cached advisories for a finding. It is the
// deterministic answer to "request additional verification" and is also used
// after intelligence updates to see whether a verdict would change.
func (e *Engine) Reassess(ctx context.Context, f FindingRef) (*Verification, error) {
	v := &Verification{Original: f.Applicability, Confidence: "low"}
	if e.store == nil {
		v.Explanation = "No intelligence cache is available, so reassessment cannot run."
		return v, nil
	}
	advisories, err := e.store.AdvisoriesFor(ctx, f.Ecosystem, f.Product)
	if err != nil {
		return nil, err
	}
	pkg := model.Package{Name: f.Product, Version: f.Version, Ecosystem: f.Ecosystem}
	pol, ruleID, _ := e.ActivePolicy(ctx)
	best := ""
	for _, adv := range advisories {
		if !containsCVE(adv, f.CVE) {
			continue
		}
		out, ok := assess.MatchWithPolicy(pkg, adv, pol)
		if !ok {
			continue
		}
		best = string(out.Applicability)
		v.Evidence = append(v.Evidence, model.Evidence{
			Kind:   "reassessment",
			Source: adv.Source,
			Detail: fmt.Sprintf("%s (%s): %s", adv.ID, out.Applicability, out.Explanation),
			URL:    advisoryURL(adv),
		})
		break
	}
	if ruleID != "" {
		v.Evidence = append(v.Evidence, model.Evidence{
			Kind:   "detection_policy",
			Detail: "reassessed with deployed rule " + ruleID,
		})
	}
	switch {
	case best == "":
		v.Explanation = "No cached advisory matches this package and CVE any more; the finding may be stale."
	case best == f.Applicability:
		v.Explanation = fmt.Sprintf("Reassessment with current intelligence and policy keeps the classification at %s.", best)
	default:
		v.Supported = true
		v.Changed = true
		v.Confidence = "high"
		v.Reassessed = best
		v.Explanation = fmt.Sprintf("Reassessment changes the classification from %s to %s.", f.Applicability, best)
	}
	return v, nil
}

// ApplyFeedback verifies and records a review, applying a verified state change.
func (e *Engine) ApplyFeedback(ctx context.Context, fb Feedback) (*Feedback, error) {
	if !ValidVerdict(fb.Verdict) {
		return nil, fmt.Errorf("unsupported verdict %q", fb.Verdict)
	}
	if !ValidReason(fb.ReasonCode) {
		return nil, fmt.Errorf("unsupported reason %q", fb.ReasonCode)
	}
	if fb.Analyst == "" {
		fb.Analyst = "unknown"
	}
	verification, err := e.Verify(ctx, fb.Finding, fb.Verdict, fb.ReasonCode)
	if err != nil {
		return nil, err
	}
	fb.Verification = verification
	if err := e.RecordFeedback(ctx, fb); err != nil {
		return nil, err
	}
	if verification.Supported {
		if err := e.SaveState(ctx, State{
			FindingID:     fb.Finding.ID,
			Verdict:       fb.Verdict,
			Applicability: verification.Reassessed,
			Confidence:    verification.Confidence,
			Explanation:   verification.Explanation,
			Evidence:      verification.Evidence,
			FeedbackID:    fb.ID,
			UpdatedAt:     fb.CreatedAt,
		}); err != nil {
			return nil, err
		}
	}
	return &fb, nil
}

func containsCVE(adv intel.Advisory, cve string) bool {
	if cve == "" {
		return false
	}
	for _, id := range adv.CVEIDs() {
		if strings.EqualFold(id, cve) {
			return true
		}
	}
	return false
}

func advisoryURL(adv intel.Advisory) string {
	for _, ref := range adv.References {
		if ref.URL != "" {
			return ref.URL
		}
	}
	return ""
}
