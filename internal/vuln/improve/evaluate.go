package improve

import (
	"fmt"
	"sort"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/assess"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// ------------------------------------------------------------------ fixtures ---

// BaselineFixtures is the labelled evaluation corpus that ships with the binary.
//
// Each case encodes a detection rule that matters in production, and each label
// is ground truth (not "what the current code does"): vulnerability is a property
// of the software, not of the scanner. Keeping this corpus in code means a policy
// change can be tested without any network access or customer data.
func BaselineFixtures() []Fixture {
	ubuntuBinaries := func(name, version string) []intel.Binary {
		return []intel.Binary{{Name: name, Version: version}}
	}

	return []Fixture{
		{
			ID:          "debian-vulnerable-build",
			Description: "Debian package below the fixed version must be reported",
			Label:       "affected",
			Package:     model.Package{Name: "openssl", Version: "3.0.11-1~deb12u2", Ecosystem: "Debian:12"},
			Advisory: intel.Advisory{
				ID: "DEBIAN-CVE-9000-0001", Source: "Debian",
				Affected: []intel.Affected{{
					Ecosystem: "Debian:12", Name: "openssl",
					Ranges: []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}, {Fixed: "3.0.13-1~deb12u1"}}}},
				}},
			},
			Expect: string(model.ApplicabilityConfirmed),
			Origin: "baseline",
		},
		{
			ID:          "debian-fixed-build",
			Description: "Debian package at the fixed version must not be reported",
			Label:       "not_affected",
			Package:     model.Package{Name: "openssl", Version: "3.0.13-1~deb12u1", Ecosystem: "Debian:12"},
			Advisory: intel.Advisory{
				ID: "DEBIAN-CVE-9000-0001", Source: "Debian",
				Affected: []intel.Affected{{
					Ecosystem: "Debian:12", Name: "openssl",
					Ranges: []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}, {Fixed: "3.0.13-1~deb12u1"}}}},
				}},
			},
			Expect: string(model.ApplicabilityNotAffected),
			Origin: "baseline",
		},
		{
			ID:          "ubuntu-enumerated-build",
			Description: "Ubuntu binary view that lists this exact build is affected",
			Label:       "affected",
			Package:     model.Package{Name: "libssl3t64", Version: "3.0.13-0ubuntu3.6", Ecosystem: "Ubuntu:24.04:LTS"},
			Advisory: intel.Advisory{
				ID: "UBUNTU-CVE-9000-0002", Source: "Ubuntu",
				Affected: []intel.Affected{{
					Ecosystem: "Ubuntu:24.04:LTS", Name: "openssl",
					Versions: []string{"3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.6"},
					Binaries: ubuntuBinaries("libssl3t64", "3.0.13-0ubuntu3.6"),
				}},
			},
			Expect: string(model.ApplicabilityConfirmed),
			Origin: "baseline",
		},
		{
			ID:          "ubuntu-newer-build",
			Description: "Ubuntu build newer than the enumeration is treated as fixed",
			Label:       "not_affected",
			Package:     model.Package{Name: "libssl3t64", Version: "3.0.13-0ubuntu3.9", Ecosystem: "Ubuntu:24.04:LTS"},
			Advisory: intel.Advisory{
				ID: "UBUNTU-CVE-9000-0002", Source: "Ubuntu",
				Affected: []intel.Affected{{
					Ecosystem: "Ubuntu:24.04:LTS", Name: "openssl",
					Versions: []string{"3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.6"},
					Binaries: ubuntuBinaries("libssl3t64", "3.0.13-0ubuntu3.6"),
				}},
			},
			Expect: string(model.ApplicabilityNotAffected),
			Origin: "baseline",
		},
		{
			ID:          "upstream-range-on-distro-build",
			Description: "Upstream advisory matched against a patched distro build must not be confirmed",
			Label:       "unresolved",
			Package:     model.Package{Name: "openssl", Version: "3.0.11-1~deb12u1", Ecosystem: "Debian:12"},
			Advisory: intel.Advisory{
				ID: "CVE-9000-0003", Source: "CVE",
				Affected: []intel.Affected{{
					Ecosystem: "Debian:12", Name: "openssl",
					Ranges: []intel.Range{{Type: "ECOSYSTEM", Events: []intel.Event{{Introduced: "0"}, {Fixed: "3.0.14-1"}}}},
				}},
			},
			Expect: string(model.ApplicabilityProbable),
			Origin: "baseline",
		},
		{
			ID:          "third-party-build",
			Description: "NodeSource build cannot be resolved by Ubuntu enumeration",
			Label:       "unresolved",
			Package:     model.Package{Name: "nodejs", Version: "22.23.5-1nodesource1", Ecosystem: "Ubuntu:24.04:LTS"},
			Advisory: intel.Advisory{
				ID: "UBUNTU-CVE-9000-0004", Source: "Ubuntu",
				Affected: []intel.Affected{{
					Ecosystem: "Ubuntu:24.04:LTS", Name: "nodejs",
					Versions: []string{"18.19.1+dfsg-6ubuntu5"},
				}},
			},
			Expect: string(model.ApplicabilityNeedsInvestigation),
			Origin: "baseline",
		},
		{
			ID:          "snap-transition-stub",
			Description: "Snap transition package carries no application code",
			Label:       "unresolved",
			Package:     model.Package{Name: "thunderbird", Version: "2:1snap1-0ubuntu3", Ecosystem: "Ubuntu:24.04:LTS"},
			Advisory: intel.Advisory{
				ID: "UBUNTU-CVE-9000-0005", Source: "Ubuntu",
				Affected: []intel.Affected{{
					Ecosystem: "Ubuntu:24.04:LTS", Name: "thunderbird",
					Versions: []string{"1snap1-0ubuntu2", "1snap1-0ubuntu3"},
					Binaries: ubuntuBinaries("thunderbird", "2:1snap1-0ubuntu3"),
				}},
			},
			// Ground truth: a snap wrapper has no application code, so the correct
			// verdict is "unresolved". The shipped policy reports it as affected,
			// which is the documented false positive this corpus guards against.
			Expect: string(model.ApplicabilityNeedsInvestigation),
			Origin: "baseline",
		},
		{
			ID:          "snap-real-build",
			Description: "A real Thunderbird build from the same advisory must stay detected",
			Label:       "affected",
			Package:     model.Package{Name: "thunderbird", Version: "1:115.0-1", Ecosystem: "Ubuntu:24.04:LTS"},
			Advisory: intel.Advisory{
				ID: "UBUNTU-CVE-9000-0005", Source: "Ubuntu",
				Affected: []intel.Affected{{
					Ecosystem: "Ubuntu:24.04:LTS", Name: "thunderbird",
					Versions: []string{"1:115.0-1", "1:115.1-1"},
					Binaries: ubuntuBinaries("thunderbird", "1:115.0-1"),
				}},
			},
			Expect: string(model.ApplicabilityConfirmed),
			Origin: "baseline",
		},
	}
}

// FixtureFromFeedback turns a verified analyst review into an evaluation case.
//
// "expect" is the outcome the candidate rule should produce for this finding; the
// caller derives it from the proposed change (a policy tightening targets
// needs_investigation, a verified non-issue targets not_affected). The fixture
// replays the advisory the scan actually used.
func FixtureFromFeedback(fb Feedback, advisories []intel.Advisory, expect string) (Fixture, bool) {
	if fb.Verification == nil || !fb.Verification.Supported || !fb.Verification.Changed {
		return Fixture{}, false
	}
	var chosen *intel.Advisory
	for i := range advisories {
		if advisories[i].ID == fb.Finding.AdvisoryID {
			chosen = &advisories[i]
			break
		}
	}
	if chosen == nil {
		return Fixture{}, false
	}
	return Fixture{
		ID:          "feedback-" + fb.ID,
		Description: "Analyst-verified correction: " + fb.Verification.Explanation,
		Label:       "corrected",
		Package: model.Package{
			Name: fb.Finding.Product, Version: fb.Finding.Version,
			Ecosystem: fb.Finding.Ecosystem,
		},
		Advisory:      *chosen,
		Expect:        expect,
		Origin:        "feedback",
		SourceFinding: fb.Finding.ID,
	}, true
}

// ---------------------------------------------------------------- evaluation ---

// Evaluate compares a candidate policy against the shipped baseline over a
// fixture set. It is pure: no database, no network, no filesystem.
//
// Rule set, per fixture label (ground truth, not "what the code does"):
//
//	affected    — a vulnerable build must not be dismissed (not_affected)
//	not_affected— a patched build must not be reported as affected
//	unresolved  — the verdict must not be "confirmed" (the build cannot be
//	              resolved from the available data)
//	corrected   — the analyst-verified outcome; must match exactly
//
// A candidate passes when it improves at least one case and regresses none,
// compared against the shipped baseline. Requiring a single change to fix every
// known gap would reject all incremental improvements.
func Evaluate(pol assess.Policy, fixtures []Fixture, now time.Time) Evaluation {
	pol = pol.WithDefaults()
	base := assess.DefaultPolicy()
	ev := Evaluation{EvaluatedAt: now}
	var baseTP, baseFP, baseTN, baseFN, candTP, candFP, candTN, candFN int

	for _, f := range fixtures {
		baseOut, _ := assess.Classify(f.Package, f.Advisory, base)
		candOut, _ := assess.Classify(f.Package, f.Advisory, pol)
		baseline := string(baseOut.Applicability)
		candidate := string(candOut.Applicability)

		basePass := satisfiesLabel(f, baseline)
		candPass := satisfiesLabel(f, candidate)

		switch f.Label {
		case "affected":
			if baseline != string(model.ApplicabilityNotAffected) {
				baseTP++
			} else {
				baseFN++
			}
			if candidate != string(model.ApplicabilityNotAffected) {
				candTP++
			} else {
				candFN++
			}
		case "not_affected":
			if baseline == string(model.ApplicabilityNotAffected) {
				baseTN++
			} else {
				baseFP++
			}
			if candidate == string(model.ApplicabilityNotAffected) {
				candTN++
			} else {
				candFP++
			}
		}

		note := ""
		switch {
		case basePass && !candPass:
			note = "regression: the candidate is worse than the shipped policy for this case"
			ev.Regressions = append(ev.Regressions, f.ID+": "+note)
		case !basePass && candPass:
			ev.Fixed = append(ev.Fixed, f.ID)
			note = "fixed relative to the shipped policy"
		case !candPass:
			note = fmt.Sprintf("still unresolved: expected %s behaviour, got %s", f.Label, candidate)
		}

		ev.Cases = append(ev.Cases, CaseResult{
			Fixture: f.ID, Label: f.Label, Expected: expectationsFor(f),
			Baseline: baseline, Candidate: candidate, Pass: candPass, Note: note,
		})
	}

	ev.Baseline = metrics(baseTP+baseFN > 0 || baseTN+baseFP > 0, baseTP, baseFP, baseTN, baseFN)
	ev.Candidate = metrics(candTP+candFN > 0 || candTN+candFP > 0, candTP, candFP, candTN, candFN)

	switch {
	case len(fixtures) == 0:
		ev.Notes = append(ev.Notes, "no fixtures: nothing can be validated")
	case len(ev.Fixed) == 0:
		ev.Notes = append(ev.Notes, "no fixture improves relative to the shipped policy, so this candidate has no measurable effect")
	}
	if len(ev.Regressions) > 0 {
		ev.Notes = append(ev.Notes, "the candidate regresses at least one case; it must be rejected even if another metric improves")
	}
	ev.Passed = len(ev.Regressions) == 0 && len(ev.Fixed) > 0
	return ev
}

// satisfiesLabel applies the ground-truth rule for a fixture label.
func satisfiesLabel(f Fixture, applicability string) bool {
	switch f.Label {
	case "affected":
		return applicability != string(model.ApplicabilityNotAffected)
	case "not_affected":
		return applicability == string(model.ApplicabilityNotAffected)
	case "corrected":
		return applicability == f.Expect
	case "unresolved":
		return applicability != string(model.ApplicabilityConfirmed) &&
			applicability != string(model.ApplicabilityNotAffected)
	default:
		return true
	}
}

func expectationsFor(f Fixture) string {
	if f.Label == "corrected" {
		return f.Expect
	}
	return f.Label
}

func allPass(cases []CaseResult) bool {
	for _, c := range cases {
		if !c.Pass {
			return false
		}
	}
	return true
}

func metrics(available bool, tp, fp, tn, fn int) Metrics {
	m := Metrics{Available: available, Cases: tp + fp + tn + fn,
		TruePos: tp, FalsePos: fp, TrueNeg: tn, FalseNeg: fn}
	if !available {
		return m
	}
	ratio := func(num, den int) float64 {
		if den == 0 {
			return 0
		}
		return float64(num) / float64(den)
	}
	m.Precision = ratio(tp, tp+fp)
	m.Recall = ratio(tp, tp+fn)
	m.Accuracy = ratio(tp+tn, tp+tn+fp+fn)
	return m
}

// SortedFixtures returns fixtures ordered by id so evaluation output is stable.
func SortedFixtures(in []Fixture) []Fixture {
	out := append([]Fixture(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
