package intel

import (
	"math"
	"strconv"
	"strings"
)

// SeverityEntry is one severity statement from an advisory. Feeds disagree on
// what belongs here (CVSS vectors, vendor word scores, GitHub severity), so the
// type stays open and the assessor picks the most authoritative interpretation.
type SeverityEntry struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// CVSSVector is a parsed CVSS v3.x base vector.
type CVSSVector struct {
	Version    string
	AV, AC, PR string
	UI, S      string
	C, I, A    string
	Raw        string
}

// IsCVSSv3 reports whether the vector is CVSS 3.0/3.1 base-scored by this file.
func (v CVSSVector) IsCVSSv3() bool { return strings.HasPrefix(v.Version, "3.") }

// BaseScore computes the CVSS v3.1 base score. CVSS v4 has a fundamentally
// different scoring model and is intentionally not approximated here: a wrong
// score is worse than an explicit "not computed".
func (v CVSSVector) BaseScore() (float64, bool) {
	if !v.IsCVSSv3() {
		return 0, false
	}
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}[v.AV]
	ac := map[string]float64{"L": 0.77, "H": 0.44}[v.AC]
	ui := map[string]float64{"N": 0.85, "R": 0.62}[v.UI]
	if av == 0 || ac == 0 || ui == 0 {
		return 0, false
	}
	changed := strings.EqualFold(v.S, "C")
	var pr float64
	if changed {
		pr = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}[v.PR]
	} else {
		pr = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}[v.PR]
	}
	if pr == 0 {
		return 0, false
	}
	c := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[v.C]
	i := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[v.I]
	a := map[string]float64{"H": 0.56, "L": 0.22, "N": 0}[v.A]
	impactSub := 1 - ((1 - c) * (1 - i) * (1 - a))
	var impact float64
	if changed {
		impact = 7.52*(impactSub-0.029) - 3.25*math.Pow(impactSub-0.02, 15)
	} else {
		impact = 6.42 * impactSub
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	score := impact + exploitability
	if changed {
		score = score * 1.08
	}
	if score > 10 {
		score = 10
	}
	// round up to one decimal, per the specification
	return math.Ceil(score*10) / 10, true
}

// ParseCVSSVector parses "CVSS:3.1/AV:N/AC:L/..." into structured fields.
func ParseCVSSVector(raw string) (CVSSVector, bool) {
	v := CVSSVector{Raw: raw}
	parts := strings.Split(raw, "/")
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "CVSS:") {
		return v, false
	}
	v.Version = strings.TrimPrefix(parts[0], "CVSS:")
	for _, p := range parts[1:] {
		k, val, ok := strings.Cut(p, ":")
		if !ok {
			continue
		}
		switch k {
		case "AV":
			v.AV = val
		case "AC":
			v.AC = val
		case "PR":
			v.PR = val
		case "UI":
			v.UI = val
		case "S":
			v.S = val
		case "C":
			v.C = val
		case "I":
			v.I = val
		case "A":
			v.A = val
		}
	}
	return v, true
}

// SeverityFromScore buckets a CVSS score using the standard ranges.
func SeverityFromScore(score float64) string {
	switch {
	case score >= 9.0:
		return "critical"
	case score >= 7.0:
		return "high"
	case score >= 4.0:
		return "medium"
	case score > 0:
		return "low"
	default:
		return "none"
	}
}

// NormalizeSeverityWord maps vendor words to the shared severity vocabulary.
func NormalizeSeverityWord(word string) string {
	switch strings.ToLower(strings.TrimSpace(word)) {
	case "critical", "important":
		return "critical"
	case "high", "serious":
		return "high"
	case "medium", "moderate":
		return "medium"
	case "low", "minor", "negligible":
		return "low"
	case "unimportant", "none":
		return "none"
	case "unknown", "":
		return ""
	default:
		return ""
	}
}

// InterpretSeverities chooses the most defensible severity for a finding.
//
// Order of preference:
//  1. a vendor/distro word score (Ubuntu, Debian, GitHub advisories),
//  2. a CVSS v3 vector we can score ourselves,
//  3. a bare numeric score.
//
// Returns the severity, the numeric CVSS (when known) and the vector/source.
func InterpretSeverities(entries []SeverityEntry) (severity string, cvss *CVSS, vector string, source string) {
	var numeric *CVSS
	var vendorWord, vendorSource string
	for _, e := range entries {
		switch strings.ToUpper(e.Type) {
		case "CVSS_V3", "CVSS_V31", "CVSS_V30":
			if v, ok := ParseCVSSVector(e.Score); ok {
				if score, ok := v.BaseScore(); ok {
					numeric = &CVSS{Score: score, Vector: e.Score, Source: "CVSS:" + v.Version}
				}
			}
		case "CVSS_V4", "CVSS_V2":
			// Recorded but not scored: v2/v4 need their own calculators.
			if vector == "" {
				vector = e.Score
				source = e.Type
			}
		default:
			if w := NormalizeSeverityWord(e.Score); w != "" && vendorWord == "" {
				vendorWord = w
				vendorSource = e.Type
			} else if f, err := strconv.ParseFloat(strings.TrimSpace(e.Score), 64); err == nil && f > 0 && numeric == nil {
				numeric = &CVSS{Score: f, Source: e.Type}
			}
		}
	}
	// A vendor's own severity rating outranks a generic CVSS vector for
	// prioritisation, but the numeric score is still reported alongside it.
	if vendorWord != "" {
		return vendorWord, numeric, vector, vendorSource
	}
	if numeric != nil {
		return SeverityFromScore(numeric.Score), numeric, numeric.Vector, numeric.Source
	}
	if vector != "" {
		return "unknown", nil, vector, source
	}
	return "unknown", nil, "", ""
}
