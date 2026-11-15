package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/fleet"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/remediate"
	"github.com/bgdnvk/clanker/internal/vuln/report"
	"github.com/bgdnvk/clanker/internal/vuln/sbom"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
	"github.com/bgdnvk/clanker/internal/vuln/scope"
)

// ------------------------------------------------------------------ overview ---

type overviewResponse struct {
	HasData  bool            `json:"has_data"`
	Metrics  overviewMetrics `json:"metrics"`
	Severity []countRow      `json:"severity"`
	Priority []vulnRow       `json:"priority"`
	Coverage coverageSummary `json:"coverage"`
	Activity []activityRow   `json:"activity"`
	Feeds    []feedRow       `json:"feeds"`
	Limits   []string        `json:"limitations"`
	Errors   []string        `json:"errors"`
	// ImprovementsAvailable drives the compact "N detection improvements
	// available for review" indicator; Reviewed counts analyst-verified findings.
	ImprovementsAvailable int `json:"improvements_available"`
	Reviewed              int `json:"reviewed_findings"`
}

type overviewMetrics struct {
	Assets             int `json:"assets"`
	Critical           int `json:"critical"`
	High               int `json:"high"`
	Medium             int `json:"medium"`
	Low                int `json:"low"`
	KEV                int `json:"kev"`
	Actionable         int `json:"actionable"`
	NeedsInvestigation int `json:"needs_investigation"`
	Total              int `json:"total"`
}

type countRow struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

type coverageSummary struct {
	Assessed       int    `json:"assessed"`
	Stale          int    `json:"stale"`
	FailedRecent   int    `json:"failed_recent"`
	StaleAfterDays int    `json:"stale_after_days"`
	LastScanAt     string `json:"last_scan_at,omitempty"`
}

type activityRow struct {
	ID         string `json:"id"`
	Kind       string `json:"kind"`
	Host       string `json:"host,omitempty"`
	Status     string `json:"status"`
	Stage      string `json:"stage,omitempty"`
	Percent    int    `json:"percent"`
	FinishedAt string `json:"finished_at,omitempty"`
	Findings   int    `json:"findings,omitempty"`
	Actionable int    `json:"actionable,omitempty"`
	KEV        int    `json:"kev,omitempty"`
	Error      string `json:"error,omitempty"`
}

const staleAfterDays = 7

func (s *Server) handleOverview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	ds, err := s.buildDataset(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return
	}
	resp := overviewResponse{
		HasData:  len(ds.Hosts) > 0,
		Severity: []countRow{},
		Priority: []vulnRow{},
		Activity: []activityRow{},
		Feeds:    []feedRow{},
		Limits:   []string{},
		Errors:   []string{},
	}
	resp.Metrics.Assets = len(ds.Hosts)

	counts := map[string]int{}
	limitations := map[string]bool{}
	for _, hv := range ds.Hosts {
		for _, f := range hv.Findings {
			if f.Analyst != nil {
				resp.Reviewed++
			}
			effective := f.effective()
			if effective == string(model.ApplicabilityNotAffected) {
				continue
			}
			resp.Metrics.Total++
			counts[f.Severity]++
			switch effective {
			case string(model.ApplicabilityConfirmed), string(model.ApplicabilityValidated), string(model.ApplicabilityProbable):
				resp.Metrics.Actionable++
			case string(model.ApplicabilityNeedsInvestigation):
				resp.Metrics.NeedsInvestigation++
			}
			if f.KEV {
				resp.Metrics.KEV++
			}
		}
		for _, l := range hv.Coverage.Limitations {
			limitations[l] = true
		}
		for _, e := range hv.Errors {
			resp.Errors = append(resp.Errors, hv.Host+": "+e)
		}
	}
	resp.Metrics.Critical = counts["critical"]
	resp.Metrics.High = counts["high"]
	resp.Metrics.Medium = counts["medium"]
	resp.Metrics.Low = counts["low"]
	for _, sev := range []string{"critical", "high", "medium", "low", "unknown"} {
		resp.Severity = append(resp.Severity, countRow{Key: sev, Count: counts[sev]})
	}

	sorted := append([]vulnRow(nil), ds.Vulns...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].RiskScore > sorted[j].RiskScore })
	for i := 0; i < len(sorted) && i < 8; i++ {
		if sorted[i].effective() == string(model.ApplicabilityNotAffected) {
			continue
		}
		resp.Priority = append(resp.Priority, sorted[i])
	}
	if counts, err := s.improve.CountByStatus(ctx); err == nil {
		// Everything not yet decided is reviewable, including research-only items.
		resp.ImprovementsAvailable = counts["awaiting_approval"] + counts["proposed"] +
			counts["testing"] + counts["discovered"] + counts["researching"]
	}

	now := s.opts.Now()
	for _, hv := range ds.Hosts {
		resp.Coverage.Assessed++
		if now.Sub(hv.FinishedAt) > staleAfterDays*24*time.Hour {
			resp.Coverage.Stale++
		}
		if resp.Coverage.LastScanAt == "" || hv.FinishedAt.Format(time.RFC3339) > resp.Coverage.LastScanAt {
			resp.Coverage.LastScanAt = hv.FinishedAt.UTC().Format(time.RFC3339)
		}
	}
	resp.Coverage.StaleAfterDays = staleAfterDays

	jobs, _ := s.store.ListJobs(ctx, 12)
	for _, j := range jobs {
		row := activityRow{ID: j.ID, Kind: j.Kind, Host: j.Host, Status: j.Status,
			Stage: j.Stage, Percent: j.Percent, Error: j.Error}
		if j.FinishedAt != nil {
			row.FinishedAt = j.FinishedAt.UTC().Format(time.RFC3339)
		}
		if j.Status == intel.JobFailed && j.FinishedAt != nil && now.Sub(*j.FinishedAt) < 24*time.Hour {
			resp.Coverage.FailedRecent++
		}
		resp.Activity = append(resp.Activity, row)
	}
	// Include historical assessments that have no job record (CLI scans).
	for _, run := range ds.Runs {
		if len(resp.Activity) >= 12 {
			break
		}
		resp.Activity = append(resp.Activity, activityRow{
			ID: run.ID, Kind: "local", Host: run.Host, Status: "completed",
			FinishedAt: run.FinishedAt.UTC().Format(time.RFC3339),
			Findings:   run.Findings, Actionable: run.Actionable, KEV: run.KEVCount, Percent: 100,
		})
	}

	resp.Feeds, _ = s.feedRows(ctx)
	for l := range limitations {
		resp.Limits = append(resp.Limits, l)
	}
	sort.Strings(resp.Limits)
	writeJSON(w, http.StatusOK, resp)
}

// -------------------------------------------------------------------- assets ---

type assetRow struct {
	Host         string `json:"host"`
	OS           string `json:"os"`
	OSVersion    string `json:"os_version"`
	Arch         string `json:"arch,omitempty"`
	Packages     int    `json:"packages"`
	Findings     int    `json:"findings"`
	Actionable   int    `json:"actionable"`
	Critical     int    `json:"critical"`
	High         int    `json:"high"`
	KEV          int    `json:"kev"`
	LastScan     string `json:"last_scan"`
	Stale        bool   `json:"stale"`
	AgentVersion string `json:"agent_version,omitempty"`
	Mode         string `json:"mode,omitempty"`
	ReportID     string `json:"report_id,omitempty"`
	IsContainer  bool   `json:"is_container,omitempty"`
}

func (s *Server) handleAssets(w http.ResponseWriter, r *http.Request) {
	ds, err := s.buildDataset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return
	}
	now := s.opts.Now()
	items := make([]assetRow, 0, len(ds.Hosts))
	for _, hv := range ds.Hosts {
		row := assetRow{
			Host: hv.Host, OS: hv.Asset.OS, OSVersion: hv.Asset.OSVersion, Arch: hv.Asset.Arch,
			Packages: len(hv.Packages), LastScan: hv.FinishedAt.UTC().Format(time.RFC3339),
			Stale:        now.Sub(hv.FinishedAt) > staleAfterDays*24*time.Hour,
			AgentVersion: hv.ToolVersion, Mode: hv.Mode, ReportID: hv.ReportID,
			IsContainer: hv.Asset.IsContainer,
		}
		for _, f := range hv.Findings {
			effective := f.effective()
			if effective == string(model.ApplicabilityNotAffected) {
				continue
			}
			row.Findings++
			if effective != string(model.ApplicabilityNeedsInvestigation) {
				row.Actionable++
			}
			switch f.Severity {
			case "critical":
				row.Critical++
			case "high":
				row.High++
			}
			if f.KEV {
				row.KEV++
			}
		}
		items = append(items, row)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Actionable != items[j].Actionable {
			return items[i].Actionable > items[j].Actionable
		}
		return items[i].Host < items[j].Host
	})
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (s *Server) handleAssetDetail(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	ds, err := s.buildDataset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return
	}
	hv, ok := ds.Hosts[host]
	if !ok {
		writeError(w, http.StatusNotFound, "asset_not_found", "no assessment recorded for this asset")
		return
	}
	// scan history for this host
	var history []intel.RunSummary
	for _, run := range ds.Runs {
		if run.Host == host {
			history = append(history, run)
		}
	}
	findings := hv.Findings
	if findings == nil {
		findings = []vulnRow{}
	}
	skipped := hv.Skipped
	if skipped == nil {
		skipped = []skippedRow{}
	}
	errorsList := hv.Errors
	if errorsList == nil {
		errorsList = []string{}
	}
	if history == nil {
		history = []intel.RunSummary{}
	}
	pkgs := hv.Packages
	limit := 500
	if len(pkgs) > limit {
		pkgs = pkgs[:limit]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"host":               hv.Host,
		"asset":              hv.Asset,
		"report_id":          hv.ReportID,
		"last_scan":          hv.FinishedAt.UTC().Format(time.RFC3339),
		"mode":               hv.Mode,
		"offline":            hv.Offline,
		"agent":              map[string]any{"version": hv.ToolVersion, "last_scan": hv.FinishedAt.UTC().Format(time.RFC3339)},
		"packages":           pkgs,
		"package_count":      len(hv.Packages),
		"packages_truncated": len(hv.Packages) > limit,
		"findings":           findings,
		"coverage":           hv.Coverage,
		"skipped":            skipped,
		"errors":             errorsList,
		"policy":             hv.Policy,
		"history":            history,
	})
}

// ----------------------------------------------------------- vulnerabilities ---

type vulnListResponse struct {
	Total   int         `json:"total"`
	Items   []vulnRow   `json:"items"`
	Facets  vulnFacets  `json:"facets"`
	Applied filterState `json:"applied"`
}

type vulnFacets struct {
	Severity      []countRow `json:"severity"`
	Applicability []countRow `json:"applicability"`
	Assets        []countRow `json:"assets"`
	KEV           int        `json:"kev"`
	FixAvailable  int        `json:"fix_available"`
}

type filterState struct {
	Query         string   `json:"q,omitempty"`
	Severity      []string `json:"severity,omitempty"`
	Applicability []string `json:"applicability,omitempty"`
	KEV           bool     `json:"kev"`
	Fix           string   `json:"fix,omitempty"`
	Asset         string   `json:"asset,omitempty"`
	Sort          string   `json:"sort"`
	Order         string   `json:"order"`
}

func (s *Server) handleVulnerabilities(w http.ResponseWriter, r *http.Request) {
	ds, err := s.buildDataset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return
	}
	q := r.URL.Query()
	state := filterState{
		Query:         strings.TrimSpace(q.Get("q")),
		Severity:      splitList(q.Get("severity")),
		Applicability: splitList(q.Get("applicability")),
		KEV:           q.Get("kev") == "true",
		Fix:           q.Get("fix"),
		Asset:         q.Get("asset"),
		Sort:          q.Get("sort"),
		Order:         q.Get("order"),
	}
	if state.Sort == "" {
		state.Sort = "risk"
	}
	if state.Order == "" {
		state.Order = "desc"
	}

	all := ds.Vulns
	facets := vulnFacets{}
	sevCounts := map[string]int{}
	appCounts := map[string]int{}
	assetCounts := map[string]int{}
	for _, v := range all {
		sevCounts[v.Severity]++
		appCounts[v.effective()]++
		assetCounts[v.Asset]++
		if v.KEV {
			facets.KEV++
		}
		if v.FixedVersion != "" {
			facets.FixAvailable++
		}
	}
	for _, sev := range []string{"critical", "high", "medium", "low", "unknown"} {
		facets.Severity = append(facets.Severity, countRow{Key: sev, Count: sevCounts[sev]})
	}
	for _, app := range []string{"confirmed_applicability", "validated_behavior", "probable", "potential", "needs_investigation", "not_affected"} {
		if appCounts[app] == 0 {
			continue
		}
		facets.Applicability = append(facets.Applicability, countRow{Key: app, Count: appCounts[app]})
	}
	for host, n := range assetCounts {
		facets.Assets = append(facets.Assets, countRow{Key: host, Count: n})
	}
	sort.Slice(facets.Assets, func(i, j int) bool { return facets.Assets[i].Key < facets.Assets[j].Key })

	filtered := make([]vulnRow, 0, len(all))
	for _, v := range all {
		effective := v.effective()
		if !state.includeNotAffected() && effective == string(model.ApplicabilityNotAffected) {
			continue
		}
		if len(state.Severity) > 0 && !contains(state.Severity, v.Severity) {
			continue
		}
		if len(state.Applicability) > 0 && !contains(state.Applicability, effective) {
			continue
		}
		if state.KEV && !v.KEV {
			continue
		}
		switch state.Fix {
		case "available":
			if v.FixedVersion == "" {
				continue
			}
		case "none":
			if v.FixedVersion != "" {
				continue
			}
		}
		if state.Asset != "" && !strings.EqualFold(state.Asset, v.Asset) {
			continue
		}
		if state.Query != "" && !v.matches(state.Query) {
			continue
		}
		filtered = append(filtered, v)
	}

	sortRows(filtered, state.Sort, state.Order)
	total := len(filtered)
	offset, limit := paginate(q)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	writeJSON(w, http.StatusOK, vulnListResponse{
		Total: total, Items: filtered[offset:end], Facets: facets, Applied: state,
	})
}

func (st filterState) includeNotAffected() bool {
	return contains(st.Applicability, string(model.ApplicabilityNotAffected))
}

func (v vulnRow) matches(q string) bool {
	q = strings.ToLower(q)
	for _, field := range []string{v.CVE, v.Product, v.Asset, v.InstalledVersion, v.Ecosystem, v.AdvisoryID} {
		if strings.Contains(strings.ToLower(field), q) {
			return true
		}
	}
	for _, a := range v.Aliases {
		if strings.Contains(strings.ToLower(a), q) {
			return true
		}
	}
	return false
}

func sortRows(rows []vulnRow, sortBy, order string) {
	less := func(i, j int) bool { return rows[i].RiskScore > rows[j].RiskScore }
	switch sortBy {
	case "severity":
		rank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "unknown": 1, "none": 0}
		less = func(i, j int) bool {
			if rank[rows[i].Severity] != rank[rows[j].Severity] {
				return rank[rows[i].Severity] > rank[rows[j].Severity]
			}
			return rows[i].RiskScore > rows[j].RiskScore
		}
	case "epss":
		less = func(i, j int) bool { return epssOf(rows[i]) > epssOf(rows[j]) }
	case "kev":
		less = func(i, j int) bool {
			if rows[i].KEV != rows[j].KEV {
				return rows[i].KEV
			}
			return rows[i].RiskScore > rows[j].RiskScore
		}
	case "first_seen":
		less = func(i, j int) bool { return rows[i].FirstSeen < rows[j].FirstSeen }
	case "cve":
		less = func(i, j int) bool { return rows[i].CVE < rows[j].CVE }
	case "asset":
		less = func(i, j int) bool { return rows[i].Asset < rows[j].Asset }
	}
	sort.SliceStable(rows, func(i, j int) bool {
		if order == "asc" {
			return !less(i, j)
		}
		return less(i, j)
	})
}

func epssOf(v vulnRow) float64 {
	if v.EPSS == nil {
		return -1
	}
	return *v.EPSS
}

func (s *Server) handleVulnerabilityDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ds, err := s.buildDataset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return
	}
	v, ok := ds.ByID[id]
	if !ok {
		writeError(w, http.StatusNotFound, "finding_not_found", "no finding with that identifier in the stored assessments")
		return
	}
	// Ownership and the deadline live on the work item, not on the finding: findings are
	// evidence and never change, while who owes the fix and when can.
	if s.remediate != nil {
		item, err := s.remediate.FindForFinding(r.Context(), v.Asset, v.CVE, v.Product, v.InstalledVersion)
		switch {
		case err == nil:
			v.WorkItem = &remediationView{Item: *item, Overdue: item.Overdue(s.opts.Now())}
		case !errors.Is(err, remediate.ErrNotFound):
			s.log.Warn("look up remediation item for finding", "finding", id, "err", err)
		}
	}
	writeJSON(w, http.StatusOK, v)
}

// --------------------------------------------------------------------- scans ---

func (s *Server) handleScans(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	jobs, err := s.store.ListJobs(ctx, 50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "jobs_error", err.Error())
		return
	}
	runs, _ := s.store.ListRuns(ctx, 50)
	writeJSON(w, http.StatusOK, map[string]any{
		"jobs":   jobs,
		"runs":   runs,
		"active": s.jobs.active(),
	})
}

type startScanRequest struct {
	Kind               string `json:"kind"`
	Offline            bool   `json:"offline"`
	IncludeNotAffected bool   `json:"include_not_affected"`
	FailOn             string `json:"fail_on,omitempty"`
	FailOnKEV          bool   `json:"fail_on_kev,omitempty"`
	// Network assessment.
	ScopeYAML  string   `json:"scope_yaml,omitempty"`
	ScopeFile  string   `json:"scope_file,omitempty"`
	Targets    []string `json:"targets,omitempty"`
	Authorized bool     `json:"authorized,omitempty"`
	// Software / container assessment.
	SBOMPath string `json:"sbom_path,omitempty"`
	Image    string `json:"image,omitempty"`
}

func (s *Server) handleStartScan(w http.ResponseWriter, r *http.Request) {
	var req startScanRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	if req.Kind == "" {
		req.Kind = "local"
	}
	scanOpts := scan.Options{
		CachePath:  s.opts.CachePath,
		Offline:    req.Offline,
		SkipRender: true,
	}
	var modeDetail string

	switch req.Kind {
	case "local":
	case "network":
		sc, err := s.authorisedScope(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_scope", err.Error())
			return
		}
		scanOpts.Scope = &sc
		modeDetail = fmt.Sprintf("scope %q (%d targets, authorised by %s)", sc.Name, len(sc.Targets), sc.AuthorizedBy)
	case "sbom":
		path, err := s.sbomPath(req)
		if err != nil {
			writeError(w, http.StatusBadRequest, "invalid_sbom", err.Error())
			return
		}
		scanOpts.SBOMPath = path
		scanOpts.Image = strings.TrimSpace(req.Image)
		modeDetail = firstNonEmpty(path, req.Image)
	default:
		writeError(w, http.StatusBadRequest, "invalid_kind", "kind must be local, network or sbom")
		return
	}

	id := s.jobs.newID()
	// The job must outlive the HTTP request that started it, so it gets its own
	// context; cancellation comes from POST /api/scans/{id}/cancel.
	ctx, cancel := context.WithCancel(context.Background())
	job := intel.Job{
		ID: id, Kind: req.Kind, Status: intel.JobRunning, Host: "",
		StartedAt: s.opts.Now(), Stage: "queued", StageDetail: "starting assessment", Percent: 2,
	}
	if err := s.store.CreateJob(ctx, job); err != nil {
		cancel()
		writeError(w, http.StatusInternalServerError, "job_error", err.Error())
		return
	}
	s.jobs.register(id, cancel)

	go s.runScanJob(ctx, id, cancel, req, scanOpts, modeDetail)
	writeJSON(w, http.StatusAccepted, job)
}

// runScanJob executes an assessment and streams stage updates into the job row.
func (s *Server) runScanJob(ctx context.Context, id string, cancel context.CancelFunc, req startScanRequest, scanOpts scan.Options, detail string) {
	defer cancel()
	defer s.jobs.forget(id)

	scanOpts.IncludeNotAffected = req.IncludeNotAffected
	scanOpts.Policy = model.Policy{FailOnSeverity: req.FailOn, FailOnKEV: req.FailOnKEV}
	scanOpts.ToolVersion = s.opts.ToolVersion
	scanOpts.Stderr = os.Stderr
	scanOpts.Progress = func(st scan.Stage) {
		if err := s.store.UpdateJobProgress(ctx, id, st.Name, st.Detail, st.Percent); err != nil {
			s.log.Debug("job progress write failed", "id", id, "err", err)
		}
	}
	if detail != "" {
		_ = s.store.UpdateJobProgress(ctx, id, "queued", detail, 3)
	}

	res, err := s.opts.RunScan(ctx, scanOpts)
	if err != nil {
		status := intel.JobFailed
		if ctx.Err() != nil {
			status = intel.JobCanceled
		}
		_ = s.store.FinishJob(ctx, id, status, "", err.Error())
		s.log.Info("scan job finished", "id", id, "status", status, "error", err)
		return
	}
	_ = s.store.FinishJob(ctx, id, intel.JobDone, res.Report.ReportID, "")
	// A local assessment becomes remediation work exactly like a remote report.
	s.reconcileReport(res.Report)
	s.log.Info("scan job finished", "id", id, "report", res.Report.ReportID,
		"mode", res.Report.Metadata.Mode, "findings", len(res.Report.Findings), "incomplete", res.Incomplete)
}

// authorisedScope validates the scope supplied with a network scan.
//
// Both a pasted document and a path are accepted; the authorisation
// acknowledgement is mandatory and is checked here rather than in the UI.
func (s *Server) authorisedScope(req startScanRequest) (model.Scope, error) {
	if !req.Authorized {
		return model.Scope{}, fmt.Errorf("network assessment requires explicit authorisation: set authorized=true after confirming you may scan these targets")
	}
	var (
		sc  model.Scope
		err error
	)
	switch {
	case strings.TrimSpace(req.ScopeYAML) != "":
		sc, err = scope.Parse([]byte(req.ScopeYAML))
	case strings.TrimSpace(req.ScopeFile) != "":
		sc, err = scope.Load(req.ScopeFile)
	default:
		return model.Scope{}, fmt.Errorf("a scope document is required (scope_yaml or scope_file)")
	}
	if err != nil {
		return model.Scope{}, err
	}
	// An explicit target list narrows the authorised scope; it can never widen it.
	if len(req.Targets) > 0 {
		for _, t := range req.Targets {
			if !scope.Allows(sc, t) {
				return model.Scope{}, fmt.Errorf("target %q is outside the authorised scope %q", t, sc.Name)
			}
		}
		sc.Targets = req.Targets
	}
	return sc, nil
}

// sbomPath validates the document path for a software assessment.
func (s *Server) sbomPath(req startScanRequest) (string, error) {
	image := strings.TrimSpace(req.Image)
	path := strings.TrimSpace(req.SBOMPath)
	switch {
	case image != "" && path != "":
		return "", fmt.Errorf("supply either a document path or a container image, not both")
	case image != "":
		return "", nil // validated in the scan (docker must be present)
	case path == "":
		return "", fmt.Errorf("a CycloneDX/SPDX/Syft document, a dependency manifest, or a container image reference is required")
	}
	cleaned := filepath.Clean(path)
	for _, forbidden := range []string{"/proc", "/sys", "/dev"} {
		if strings.HasPrefix(cleaned, forbidden) {
			return "", fmt.Errorf("refusing to read %q", cleaned)
		}
	}
	info, err := os.Stat(cleaned)
	if err != nil {
		return "", fmt.Errorf("document not found: %w", err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s is a directory; point at a document", cleaned)
	}
	if info.Size() > sbom.MaxDocumentBytes {
		return "", fmt.Errorf("%s is larger than %d bytes", cleaned, int64(sbom.MaxDocumentBytes))
	}
	// Parse now so an unsupported document is a clear 400 instead of a failed
	// job the user only discovers afterwards.
	if _, err := sbom.ParseFile(cleaned); err != nil {
		return "", err
	}
	return cleaned, nil
}

func (s *Server) handleScanDetail(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, err := s.store.GetJob(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "job_error", err.Error())
		return
	}
	if job == nil {
		// Allow polling historical reports by report id.
		payload, rerr := s.store.ReportByID(r.Context(), id)
		if rerr != nil {
			writeError(w, http.StatusNotFound, "job_not_found", "no scan job or report with that id")
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"job": nil, "report_available": true, "report_id": id, "report": json.RawMessage(payload)})
		return
	}
	resp := map[string]any{"job": job, "report_available": job.ReportID != ""}
	if job.ReportID != "" {
		if payload, err := s.store.ReportByID(r.Context(), job.ReportID); err == nil {
			resp["report"] = json.RawMessage(payload)
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) handleCancelScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	job, err := s.store.GetJob(r.Context(), id)
	if err != nil || job == nil {
		writeError(w, http.StatusNotFound, "job_not_found", "no scan job with that id")
		return
	}
	if job.Status != intel.JobRunning {
		writeError(w, http.StatusConflict, "job_not_running", "this scan is not running")
		return
	}
	if !s.jobs.cancel(id) {
		writeError(w, http.StatusConflict, "job_not_running", "this scan is not running in this server process")
		return
	}
	_ = s.store.FinishJob(r.Context(), id, intel.JobCanceled, "", "canceled by user")
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "status": intel.JobCanceled})
}

// ------------------------------------------------------------------- reports ---

func (s *Server) handleReports(w http.ResponseWriter, r *http.Request) {
	runs, err := s.store.ListRuns(r.Context(), 100)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "reports_error", err.Error())
		return
	}
	if runs == nil {
		runs = []intel.RunSummary{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": runs, "total": len(runs)})
}

func (s *Server) handleReport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	payload, err := s.store.ReportByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "report_not_found", "no stored assessment with that id")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(payload)
}

func (s *Server) handleReportExport(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "json"
	}
	payload, err := s.store.ReportByID(r.Context(), id)
	if err != nil {
		writeError(w, http.StatusNotFound, "report_not_found", "no stored assessment with that id")
		return
	}
	var rep model.Report
	if err := json.Unmarshal(payload, &rep); err != nil {
		writeError(w, http.StatusInternalServerError, "report_corrupt", "stored report is unreadable")
		return
	}

	// Software inventory exports answer a different question than the findings
	// report: what is installed on this host, in the format an asset register or
	// an SBOM consumer expects.
	switch format {
	case "csv", "inventory", "software":
		body, err := report.SoftwareInventoryCSV([]model.Report{rep})
		if err != nil {
			writeError(w, http.StatusInternalServerError, "export_error", err.Error())
			return
		}
		writeAttachment(w, "text/csv; charset=utf-8", "clanker-guard-"+id+"-software.csv", body)
		return
	case "cyclonedx", "cdx", "sbom":
		body, err := sbom.ExportCycloneDX(rep.Inventory.Packages, rep.Inventory.Asset, rep.Metadata.ToolVersion, exportTimestamp(rep))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "export_error", err.Error())
			return
		}
		writeAttachment(w, "application/vnd.cyclonedx+json; charset=utf-8", "clanker-guard-"+id+".cdx.json", body)
		return
	}

	ext := map[string]string{"json": "json", "markdown": "md", "md": "md", "sarif": "sarif", "html": "html"}[format]
	if ext == "" {
		writeError(w, http.StatusBadRequest, "invalid_format",
			"format must be json, markdown, sarif, html, csv (software inventory) or cyclonedx (SBOM)")
		return
	}
	w.Header().Set("Content-Type", contentTypeFor(ext))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", "clanker-guard-"+id+"."+ext))
	if err := report.Render(w, rep, format); err != nil {
		s.log.Error("render report", "id", id, "format", format, "err", err)
	}
}

// handleSoftwareExport is the environment-wide software asset list: every host
// that has a stored assessment, newest report each, one row per package.
// Without ?host= it answers "what software is in my environment" in one file.
func (s *Server) handleSoftwareExport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "csv"
	}
	host := strings.TrimSpace(r.URL.Query().Get("host"))

	runs, err := s.store.ListRuns(ctx, 500)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "cache_error", err.Error())
		return
	}
	// Newest report per host: an asset list must not repeat a package once per
	// scan, or the register grows every day.
	seen := map[string]bool{}
	reports := []model.Report{}
	for _, run := range runs {
		if seen[run.Host] {
			continue
		}
		if host != "" && !strings.EqualFold(run.Host, host) {
			continue
		}
		seen[run.Host] = true
		payload, err := s.store.ReportByID(ctx, run.ID)
		if err != nil {
			continue
		}
		var rep model.Report
		if err := json.Unmarshal(payload, &rep); err != nil {
			continue
		}
		reports = append(reports, rep)
	}
	if len(reports) == 0 {
		if host != "" {
			writeError(w, http.StatusNotFound, "no_inventory", fmt.Sprintf("no stored assessment for host %q", host))
			return
		}
		writeError(w, http.StatusNotFound, "no_inventory", "no stored assessments yet; run a scan first")
		return
	}

	switch format {
	case "csv", "inventory", "software":
		body, err := report.SoftwareInventoryCSV(reports)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "export_error", err.Error())
			return
		}
		name := "clanker-guard-software-inventory.csv"
		if host != "" {
			name = "clanker-guard-software-" + sanitizeFilename(host) + ".csv"
		}
		writeAttachment(w, "text/csv; charset=utf-8", name, body)
	case "cyclonedx", "cdx", "sbom":
		// A CycloneDX document describes one host; asking for several would mean
		// inventing a merged component tree.
		if len(reports) != 1 {
			writeError(w, http.StatusBadRequest, "host_required",
				"a CycloneDX SBOM describes one host: pass ?host=<name>, or export per report")
			return
		}
		rep := reports[0]
		body, err := sbom.ExportCycloneDX(rep.Inventory.Packages, rep.Inventory.Asset, rep.Metadata.ToolVersion, exportTimestamp(rep))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "export_error", err.Error())
			return
		}
		writeAttachment(w, "application/vnd.cyclonedx+json; charset=utf-8",
			"clanker-guard-software-"+sanitizeFilename(firstNonEmpty(rep.Inventory.Asset.Hostname, rep.Metadata.Host))+".cdx.json", body)
	default:
		writeError(w, http.StatusBadRequest, "invalid_format", "format must be csv or cyclonedx")
	}
}

// exportTimestamp is when the inventory was collected, falling back to the end of
// the scan so an exported SBOM carries a real timestamp instead of "now".
func exportTimestamp(rep model.Report) time.Time {
	if !rep.Inventory.CollectedAt.IsZero() {
		return rep.Inventory.CollectedAt
	}
	if rep.Metadata.FinishedAt != nil {
		return *rep.Metadata.FinishedAt
	}
	if !rep.Metadata.StartedAt.IsZero() {
		return rep.Metadata.StartedAt
	}
	return time.Now().UTC()
}

func writeAttachment(w http.ResponseWriter, contentType, name string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// sanitizeFilename keeps a hostname usable as a download name.
func sanitizeFilename(s string) string {
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '-'
		}
	}, s)
	if cleaned == "" {
		return "inventory"
	}
	return cleaned
}

func contentTypeFor(ext string) string {
	switch ext {
	case "json":
		return "application/json; charset=utf-8"
	case "md":
		return "text/markdown; charset=utf-8"
	case "sarif":
		return "application/sarif+json"
	case "html":
		return "text/html; charset=utf-8"
	}
	return "application/octet-stream"
}

// --------------------------------------------------------------------- feeds ---

func (s *Server) handleFeeds(w http.ResponseWriter, r *http.Request) {
	rows, err := s.feedRows(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "feeds_error", err.Error())
		return
	}
	advisories, _ := s.store.AdvisoryCount(r.Context())
	kev, _ := s.store.KEVCount(r.Context())
	epss, _ := s.store.EPSSCount(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"feeds":  rows,
		"counts": map[string]int{"advisories": advisories, "kev": kev, "epss": epss},
	})
}

func (s *Server) handleFeedUpdate(w http.ResponseWriter, r *http.Request) {
	id := s.jobs.newID()
	ctx, cancel := context.WithCancel(r.Context())
	job := intel.Job{ID: id, Kind: "feeds", Status: intel.JobRunning, StartedAt: s.opts.Now(),
		Stage: "feeds", StageDetail: "downloading KEV and EPSS", Percent: 5}
	if err := s.store.CreateJob(ctx, job); err != nil {
		cancel()
		writeError(w, http.StatusInternalServerError, "job_error", err.Error())
		return
	}
	s.jobs.register(id, cancel)
	go func() {
		defer cancel()
		defer s.jobs.forget(id)
		_ = s.store.UpdateJobProgress(context.Background(), id, "feeds", "downloading CISA KEV", 20)
		bg := context.Background()
		if _, err := scan.UpdateFeeds(bg, s.opts.CachePath, false, os.Stderr); err != nil {
			_ = s.store.FinishJob(bg, id, intel.JobFailed, "", err.Error())
			return
		}
		_ = s.store.UpdateJobProgress(bg, id, "feeds", "cache updated", 90)
		_ = s.store.FinishJob(bg, id, intel.JobDone, "", "")
	}()
	writeJSON(w, http.StatusAccepted, job)
}

// -------------------------------------------------------------------- agents ---

func (s *Server) handleAgents(w http.ResponseWriter, r *http.Request) {
	hostname, _ := os.Hostname()
	ds, err := s.buildDataset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return
	}
	endpoints := []map[string]any{}
	for _, hv := range ds.Hosts {
		endpoints = append(endpoints, map[string]any{
			"host": hv.Host, "agent_version": hv.ToolVersion,
			"last_scan": hv.FinishedAt.UTC().Format(time.RFC3339),
			"os":        hv.Asset.OS, "os_version": hv.Asset.OSVersion,
			"findings": len(hv.Findings), "mode": hv.Mode,
		})
	}
	sort.Slice(endpoints, func(i, j int) bool {
		return fmt.Sprint(endpoints[i]["host"]) < fmt.Sprint(endpoints[j]["host"])
	})

	version := s.AgentVersion()
	// The install command is generated for *this* server: an endpoint that pastes
	// it enrolls straight back here, which is what makes "install and report" one
	// step instead of two.
	serverURL := requestBaseURL(r)
	// Enrollment tokens are minted on demand (single use, short lived), so the
	// dashboard advertises how to get one rather than printing a standing secret.
	install := map[string]any{
		"published": s.opts.ReleaseBase != "",
		"version":   version,
		"base_url":  s.opts.ReleaseBase,
	}
	if s.opts.ReleaseBase != "" {
		// Commands need a token to be usable; until one is minted the dashboard
		// shows the exact call to mint it.
		install["requires_enroll_token"] = true
		install["mint_endpoint"] = "/api/agents/enroll-token"
		install["keeps_available"] = true
		// Always show the command, with the token as a placeholder: an operator who
		// has not minted one yet still needs to see what they will paste.
		install["commands"] = s.enrollCommandTemplate(r)
		oneoff := s.enrollCommandTemplate(r)
		oneoff["linux"] += " --no-service"
		oneoff["macos"] += " --no-service"
		oneoff["windows"] += " -NoService"
		install["oneoff_commands"] = oneoff
	} else {
		// Never show a fake release URL: tell the user exactly how to publish.
		install["build_steps"] = []string{
			"./scripts/build-agent-release.sh " + version,
			"publish dist/v" + version + " as a GitHub release tagged v" + version + " (installers + SHA256SUMS are generated)",
			"restart: CLANKER_GUARD_RELEASE_BASE=https://github.com/<owner>/<repo>/releases/download/v" + version + " clanker vuln serve",
		}
	}
	local := map[string]any{
		"host": hostname, "version": version, "cache_path": s.opts.CachePath,
		"platform": runtimePlatform(), "installed": true,
	}
	if hv, ok := ds.Hosts[hostname]; ok {
		local["last_scan"] = hv.FinishedAt.UTC().Format(time.RFC3339)
	}
	// The fleet view: what is enrolled, what each endpoint is doing right now, and
	// the bootstrap secret that lets another endpoint join.
	enrolled := []map[string]any{}
	if list, err := s.fleet.List(r.Context()); err == nil {
		for _, a := range list {
			task, _ := s.fleet.LatestTask(r.Context(), a.ID)
			view := agentView(a, s.opts.Now(), s.presence.online(a.ID), task != nil && task.Status == fleet.TaskRunning)
			// The latest queued/finished scan request, so the operator can see
			// whether the endpoint has picked the work up yet.
			if task != nil {
				view["task"] = task
			}
			enrolled = append(enrolled, view)
		}
	} else {
		s.log.Warn("list agents", "err", err)
	}
	fleetView := map[string]any{
		"server_url":               serverURL,
		"reachable_window":         fleet.ReachableWindow.String(),
		"enroll_token":             "",
		"enroll_token_ttl_hours":   int(fleet.DefaultEnrollTokenTTL.Hours()),
		"enroll_tokens_single_use": true,
		"enrolled":                 enrolled,
		"count":                    len(enrolled),
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"local": local, "endpoints": endpoints, "install": install,
		"fleet":        fleetView,
		"managed_mode": true,
		"managed_note": "Endpoints enroll with a per-agent token and report findings and status to this server only. " +
			"There is no remote command channel: the server cannot ask an agent to run anything, and nothing is sent to a third party.",
	})
}

// ------------------------------------------------------------------ settings ---

func (s *Server) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	vals, err := s.store.Settings(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "settings_error", err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"policy": map[string]any{
			"fail_on":     vals["policy.fail_on"],
			"fail_on_kev": vals["policy.fail_on_kev"] == "true",
		},
		"offline_default": vals["scan.offline_default"] == "true",
		"release_base":    firstNonEmpty(vals["release_base"], s.opts.ReleaseBase),
		"cache_path":      s.opts.CachePath,
		"tool_version":    s.opts.ToolVersion,
		"token_required":  s.opts.Token != "",
		// password_required mirrors whether `clanker vuln auth set-password` has
		// been run; the Settings screen shows which sign-in methods exist.
		"password_required": s.auth != nil,
		"auth": map[string]any{
			"required":    s.authRequired(),
			"session_ttl": s.opts.SessionTTL.String(),
			"auth_file":   s.authFilePath(),
		},
		"capabilities": map[string]bool{
			"local_scan": true, "network_scan": false, "sbom_scan": false, "llm": false,
		},
	})
}

func (s *Server) handlePutSettings(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Policy struct {
			FailOn    string `json:"fail_on"`
			FailOnKEV bool   `json:"fail_on_kev"`
		} `json:"policy"`
		OfflineDefault *bool  `json:"offline_default"`
		ReleaseBase    string `json:"release_base"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	switch body.Policy.FailOn {
	case "", "critical", "high", "medium", "low":
	default:
		writeError(w, http.StatusBadRequest, "invalid_policy", "policy.fail_on must be empty, critical, high, medium or low")
		return
	}
	ctx := r.Context()
	if err := s.store.SetSetting(ctx, "policy.fail_on", body.Policy.FailOn); err != nil {
		writeError(w, http.StatusInternalServerError, "settings_error", err.Error())
		return
	}
	if err := s.store.SetSetting(ctx, "policy.fail_on_kev", boolStr(body.Policy.FailOnKEV)); err != nil {
		writeError(w, http.StatusInternalServerError, "settings_error", err.Error())
		return
	}
	if body.OfflineDefault != nil {
		_ = s.store.SetSetting(ctx, "scan.offline_default", boolStr(*body.OfflineDefault))
	}
	if body.ReleaseBase != "" {
		if !strings.HasPrefix(body.ReleaseBase, "https://") && !strings.HasPrefix(body.ReleaseBase, "http://") {
			writeError(w, http.StatusBadRequest, "invalid_release_base", "release_base must be an http(s) URL")
			return
		}
		_ = s.store.SetSetting(ctx, "release_base", body.ReleaseBase)
	}
	s.handleGetSettings(w, r)
}

// ----------------------------------------------------------------------- ask ---

func (s *Server) handleAsk(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Question string `json:"question"`
		Host     string `json:"host"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	if strings.TrimSpace(body.Question) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "question is required")
		return
	}
	ds, err := s.buildDataset(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "dataset_error", err.Error())
		return
	}
	hv, ok := ds.Hosts[body.Host]
	if !ok {
		// default to the host with the most actionable findings
		var best *hostView
		for _, cand := range ds.Hosts {
			if best == nil || len(cand.Findings) > len(best.Findings) {
				best = cand
			}
		}
		hv = best
	}
	if hv == nil {
		writeError(w, http.StatusConflict, "no_assessment", "run a scan first: Ask Guard answers from stored findings only")
		return
	}
	payload, err := s.store.ReportByID(r.Context(), hv.ReportID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "report_missing", err.Error())
		return
	}
	var rep model.Report
	if err := json.Unmarshal(payload, &rep); err != nil {
		writeError(w, http.StatusInternalServerError, "report_corrupt", "stored report is unreadable")
		return
	}
	// Questions about detection quality and improvement are answered from the
	// improvement store, then fall through to the finding-oriented assistant.
	if answer, citations, ok := s.answerImprovementQuestion(r.Context(), ds, body.Question); ok {
		writeJSON(w, http.StatusOK, map[string]any{
			"answer":    answer,
			"citations": citations,
			"grounding": map[string]any{
				"report_id": hv.ReportID, "host": hv.Host, "generated_by": "deterministic",
				"llm_used": false,
				"note":     "Answer derived from stored reviews, proposals and scan evidence. No model was consulted.",
			},
		})
		return
	}

	answer := scan.Ask(rep, body.Question)

	// Cite the findings the answer actually references, so a reader can verify.
	var citations []map[string]any
	for _, v := range hv.Findings {
		if !strings.Contains(answer, v.CVE) && !strings.Contains(answer, v.Product) {
			continue
		}
		url := ""
		if len(v.References) > 0 {
			url = v.References[0].URL
		}
		citations = append(citations, map[string]any{
			"id": v.ID, "cve": v.CVE, "product": v.Product, "severity": v.Severity,
			"affected": v.Affected, "advisory_url": url,
		})
		if len(citations) >= 10 {
			break
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"answer":    answer,
		"citations": citations,
		"grounding": map[string]any{
			"report_id": hv.ReportID, "host": hv.Host, "generated_by": "deterministic",
			"llm_used": false,
			"note":     "Answer derived from stored scan evidence only; no model was consulted.",
		},
	})
}

// ------------------------------------------------------------------- helpers ---

func splitList(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func paginate(q map[string][]string) (offset, limit int) {
	limit = 50
	if v := q["limit"]; len(v) > 0 {
		if n, err := strconv.Atoi(v[0]); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	if v := q["offset"]; len(v) > 0 {
		if n, err := strconv.Atoi(v[0]); err == nil && n >= 0 {
			offset = n
		}
	}
	return offset, limit
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func runtimePlatform() string { return runtime.GOOS }
