package api

import (
	"net/http"
	"sort"
	"strconv"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/remediate"
)

// Process metrics, computed from stored facts rather than from a counter someone must
// remember to increment.
//
// What this answers: is the programme getting better? Time to fix, how much is late, how
// much is old, and whether things come back. Numbers that cannot be produced from the data
// are omitted rather than estimated.
type metricsResponse struct {
	Generated      string `json:"generated"`
	Open           int    `json:"open"`
	Overdue        int    `json:"overdue"`
	Unassigned     int    `json:"unassigned"`
	AcceptancesDue int    `json:"acceptances_due"`
	// Ageing buckets by first_seen, so a stalled queue is visible as a shape, not a total.
	AgeBuckets []ageBucket `json:"age_buckets"`
	// TimeToFix is per severity, computed from verification receipts.
	TimeToFix []timeToFix `json:"time_to_fix"`
	Reopened  int         `json:"reopened"`
	Verified  int         `json:"verified"`
	// Groups vs items: the ratio shows whether work is being organised or just counted.
	Units    int `json:"units"`
	Findings int `json:"findings"`
}

type ageBucket struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type timeToFix struct {
	Severity   string  `json:"severity"`
	Resolved   int     `json:"resolved"`
	MedianDays float64 `json:"median_days"`
	P90Days    float64 `json:"p90_days"`
}

// handleMetrics serves the process view.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	now := s.opts.Now().UTC()
	policy := s.currentPolicy(r)

	sum, err := s.remediate.Summary(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "metrics_error", err.Error())
		return
	}
	items, err := s.remediate.List(ctx, remediate.Filter{}, policy)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "metrics_error", err.Error())
		return
	}

	buckets := []struct {
		label string
		max   int
	}{{"under 7 days", 7}, {"7-30 days", 30}, {"30-90 days", 90}, {"over 90 days", 1 << 30}}
	counts := make([]int, len(buckets))
	for _, it := range items {
		if remediate.IsTerminal(it.State) {
			continue
		}
		age := int(now.Sub(it.FirstSeen).Hours() / 24)
		for i, b := range buckets {
			if age < b.max {
				counts[i]++
				break
			}
		}
	}
	out := metricsResponse{
		Generated: now.Format("2006-01-02T15:04:05Z"), Open: sum.Open, Overdue: sum.Overdue,
		Unassigned: sum.Unassigned, AcceptancesDue: sum.AcceptancesDue,
	}
	for i, b := range buckets {
		out.AgeBuckets = append(out.AgeBuckets, ageBucket{Label: b.label, Count: counts[i]})
	}

	// Time to fix: the gap between first detection and the verification receipt.
	bySeverity := map[string][]float64{}
	for _, it := range items {
		if it.State != remediate.StateResolved {
			continue
		}
		days := it.UpdatedAt.Sub(it.FirstSeen).Hours() / 24
		if days < 0 {
			continue
		}
		bySeverity[strings.ToLower(it.Severity)] = append(bySeverity[strings.ToLower(it.Severity)], days)
		out.Verified++
	}
	order := []string{"critical", "high", "medium", "low", "unknown"}
	for _, sev := range order {
		values := bySeverity[sev]
		if len(values) == 0 {
			continue
		}
		sort.Float64s(values)
		out.TimeToFix = append(out.TimeToFix, timeToFix{
			Severity: sev, Resolved: len(values),
			MedianDays: round1(median(values)), P90Days: round1(percentile(values, 0.9)),
		})
	}

	// Reopens: an item resolved and now open again.
	for _, it := range items {
		if it.State == remediate.StateResolved || remediate.IsTerminal(it.State) {
			continue
		}
		if strings.Contains(it.Notes, "reopened") {
			out.Reopened++
		}
	}

	// Units against findings: if this ratio stays near 1, the queue is a list, not work.
	if groups, err := s.remediate.Groups(ctx, policy); err == nil {
		out.Units = len(groups)
		for _, g := range groups {
			out.Findings += g.Items
		}
	}
	writeJSON(w, http.StatusOK, out)
}

func median(sorted []float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	mid := len(sorted) / 2
	if len(sorted)%2 == 0 {
		return (sorted[mid-1] + sorted[mid]) / 2
	}
	return sorted[mid]
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func round1(v float64) float64 {
	f, _ := strconv.ParseFloat(strconv.FormatFloat(v, 'f', 1, 64), 64)
	return f
}
