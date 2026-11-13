package assess

import (
	"context"
	"fmt"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// RiskWeights makes the prioritisation model explicit and tunable.
//
// The model is a transparent weighted sum capped at 100. It is intentionally
// additive rather than multiplicative so that a reviewer can recompute it by
// hand from the report's risk_factors.
type RiskWeights struct {
	KEV            float64 `json:"kev"`
	EPSS           float64 `json:"epss"` // scaled by EPSS probability
	Critical       float64 `json:"critical"`
	High           float64 `json:"high"`
	Medium         float64 `json:"medium"`
	Low            float64 `json:"low"`
	Unknown        float64 `json:"unknown"`
	Exposure       float64 `json:"exposure"`
	Criticality    float64 `json:"asset_criticality"`
	ConfidenceHgh  float64 `json:"confidence_high"`
	ConfidenceMed  float64 `json:"confidence_medium"`
	PatchAvailable float64 `json:"patch_available"`
}

// DefaultRiskWeights is the shipped prioritisation policy.
func DefaultRiskWeights() RiskWeights {
	return RiskWeights{
		KEV:            30,
		EPSS:           20,
		Critical:       20,
		High:           15,
		Medium:         8,
		Low:            3,
		Unknown:        2,
		Exposure:       10,
		Criticality:    10,
		ConfidenceHgh:  10,
		ConfidenceMed:  5,
		PatchAvailable: 5,
	}
}

func (e *Engine) enrich(ctx context.Context, f *model.Finding) {
	if e.Store == nil {
		return
	}
	// Not-affected findings are not enriched: enrichment exists to prioritise
	// remediation work, and there is no work for them.
	if f.Affected == model.ApplicabilityNotAffected {
		return
	}
	cves := f.Aliases
	if len(cves) == 0 && f.VulnerabilityID != "" {
		cves = []string{f.VulnerabilityID}
	}
	for _, id := range cves {
		if len(id) < 5 || id[:4] != "CVE-" {
			continue
		}
		if kev, ok, err := e.Store.KEVFor(ctx, id); err == nil && ok {
			f.CISAKEV = true
			f.KEV = &model.KEVInfo{
				CVEID: kev.CVEID, DateAdded: kev.DateAdded, Vendor: kev.Vendor,
				Product: kev.Product, Name: kev.Name, Ransomware: kev.Ransomware,
			}
			break
		}
	}
	for _, id := range cves {
		if len(id) < 5 || id[:4] != "CVE-" {
			continue
		}
		if epss, ok, err := e.Store.EPSSFor(ctx, id); err == nil && ok {
			f.EPSS = &model.EPSS{Score: epss.Score, Percentile: epss.Percentile, Model: epss.Model, ScoreDate: epss.ScoreDate}
			break
		}
	}
}

// score computes the remediation priority and records every factor so the
// number in the report is auditable.
func (e *Engine) score(f *model.Finding) {
	w := e.Weights
	if w == (RiskWeights{}) {
		w = DefaultRiskWeights()
	}
	var factors []model.RiskFactor
	total := 0.0
	add := func(name string, weight float64, detail string) {
		if weight == 0 {
			return
		}
		total += weight
		factors = append(factors, model.RiskFactor{Name: name, Weight: weight, Detail: detail})
	}

	if f.Affected == model.ApplicabilityNotAffected {
		f.RiskScore = 0
		f.RiskFactors = []model.RiskFactor{{Name: "not_affected", Weight: 0, Detail: "no remediation work required"}}
		return
	}

	switch f.Severity {
	case model.SeverityCritical:
		add("severity_critical", w.Critical, "CVSS/vendor severity critical")
	case model.SeverityHigh:
		add("severity_high", w.High, "CVSS/vendor severity high")
	case model.SeverityMedium:
		add("severity_medium", w.Medium, "CVSS/vendor severity medium")
	case model.SeverityLow:
		add("severity_low", w.Low, "CVSS/vendor severity low")
	default:
		add("severity_unknown", w.Unknown, "no severity published")
	}
	if f.CISAKEV {
		add("cisa_kev", w.KEV, "listed in CISA Known Exploited Vulnerabilities")
	}
	if f.EPSS != nil {
		add("epss", w.EPSS*f.EPSS.Score, fmt.Sprintf("EPSS %.3f (percentile %.1f%%)", f.EPSS.Score, f.EPSS.Percentile*100))
	}
	if e.Exposed {
		add("internet_exposure", w.Exposure, "asset reachable from an untrusted network")
	}
	if e.AssetCriticality > 0 {
		add("asset_criticality", w.Criticality*clamp01(e.AssetCriticality),
			fmt.Sprintf("asset criticality %.2f", clamp01(e.AssetCriticality)))
	}
	switch f.Confidence {
	case model.ConfidenceHigh:
		add("confidence_high", w.ConfidenceHgh, "applicability evidence is authoritative")
	case model.ConfidenceMedium:
		add("confidence_medium", w.ConfidenceMed, "applicability evidence is indirect")
	}
	if f.FixedVersion != "" || f.VendorAdvisory != nil {
		add("patch_available", w.PatchAvailable, "a vendor fix or advisory exists, so remediation is actionable")
	}
	if total > 100 {
		total = 100
	}
	f.RiskScore = round1(total)
	f.RiskFactors = factors
}

func clamp01(v float64) float64 {
	switch {
	case v < 0:
		return 0
	case v > 1:
		return 1
	default:
		return v
	}
}

func round1(v float64) float64 {
	return float64(int(v*10+0.5)) / 10
}

// EnrichOnly attaches KEV/EPSS data and scores pre-built findings. It is used
// by the report renderer when findings come from a stored run.
func (e *Engine) EnrichOnly(ctx context.Context, findings []model.Finding) []model.Finding {
	out := make([]model.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		e.enrich(ctx, &out[i])
		e.score(&out[i])
	}
	return out
}

var _ = intel.KEVEntry{}
