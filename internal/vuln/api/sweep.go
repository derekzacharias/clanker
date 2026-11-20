package api

import (
	"context"
	"fmt"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/remediate"
	"github.com/bgdnvk/clanker/internal/vuln/report"
)

// sweepDistroPythonDuplicates closes work items that were derived from the duplicate copies.
//
// Reports ingested before the collector stopped reading /usr/lib/python3*/dist-packages left
// findings against a package pip does not own. Those items are wrong, not merely stale: the
// ticket they produce would tell somebody to upgrade a system package with pip. They are marked
// false-positive — which is what they are — with the reason recorded and audited, rather than
// deleted, so the history stays intact.
//
// Idempotent: items already closed are skipped, so a restart changes nothing.
func (s *Server) sweepDistroPythonDuplicates(ctx context.Context) {
	if s.remediate == nil || s.store == nil {
		return
	}
	runs, err := s.store.ListRuns(ctx, 200)
	if err != nil {
		s.log.Warn("sweep: list runs failed", "err", err)
		return
	}
	seen := map[string]bool{}
	var hosts []string
	for _, r := range runs {
		if r.Host == "" || seen[r.Host] {
			continue
		}
		seen[r.Host] = true
		hosts = append(hosts, r.Host)
	}
	// asset -> "product\x00version" -> reason. One host usually has many duplicated packages
	// (every python3-* module), so this has to be a set, not a single entry.
	suppressed := map[string]map[string]string{}
	for _, host := range hosts {
		_, rep, err := s.store.LatestReportFor(ctx, host)
		if err != nil {
			continue
		}
		for _, p := range report.SuppressedPackages(rep) {
			key := strings.ToLower(host)
			if suppressed[key] == nil {
				suppressed[key] = map[string]string{}
			}
			suppressed[key][strings.ToLower(p.Name)+"\x00"+p.Version] =
				fmt.Sprintf("%s is provided by the operating system package manager (found in %s), "+
					"not by pip; the OS package is reported under its own name", p.Name, p.Origin)
		}
	}
	if len(suppressed) == 0 {
		s.log.Info("sweep: no distribution-managed Python duplicates in stored reports")
		return
	}
	s.log.Info("sweep: distribution-managed Python packages found", "assets", len(suppressed))
	items, err := s.remediate.List(ctx, remediate.Filter{}, s.currentPolicy(nil))
	if err != nil {
		s.log.Warn("sweep: list items failed", "err", err)
		return
	}
	closed := 0
	for _, item := range items {
		byKey, ok := suppressed[strings.ToLower(item.Asset)]
		if !ok {
			continue
		}
		reason, ok := byKey[strings.ToLower(item.Product)+"\x00"+item.InstalledVersion]
		if !ok {
			continue
		}
		state := remediate.StateFalsePositive
		note := strings.TrimSpace(item.Notes + " | superseded: " + reason)
		if _, err := s.remediate.Update(ctx, item.ID, remediate.Patch{State: &state, Notes: &note}); err != nil {
			s.log.Warn("sweep: item not closable", "id", item.ID, "state", item.State, "err", err)
			continue
		}
		closed++
		s.store.AppendAudit(ctx, auditEntry("system", "remediation.superseded", item.ID,
			fmt.Sprintf("asset=%s product=%s version=%s", item.Asset, item.Product, item.InstalledVersion), ""))
	}
	if closed > 0 {
		s.log.Info("closed remediation items that duplicated an OS-owned Python package", "items", closed)
	}
}
