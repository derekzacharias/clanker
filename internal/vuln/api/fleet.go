package api

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/fleet"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/report"
)

// Endpoint fleet reporting.
//
// An agent presents a per-agent bearer token; the dashboard presents its own
// session cookie or token. These endpoints are outside dashboard auth on purpose
// (an agent has no browser session) but are never unauthenticated: enroll
// requires the shared enrollment token, everything else requires the agent's own
// credential, and enrollment attempts are rate limited per source address.
const (
	// maxAgentReportBytes bounds an uploaded report. The largest local report
	// seen is a few MB; anything beyond this is not a report.
	maxAgentReportBytes = 32 << 20
	// agentEnrollFailures is how many wrong enrollment tokens one address may
	// try before further attempts are refused.
	agentEnrollFailures = 10
)

// agentFromRequest resolves the bearer token to an enrolled agent.
func (s *Server) agentFromRequest(w http.ResponseWriter, r *http.Request) (fleet.Agent, bool) {
	auth := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(auth, prefix) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "agent requests need: Authorization: Bearer <agent token>")
		return fleet.Agent{}, false
	}
	ag, err := s.fleet.Authenticate(r.Context(), strings.TrimSpace(auth[len(prefix):]))
	switch {
	case errors.Is(err, fleet.ErrRevoked):
		writeError(w, http.StatusForbidden, "agent_revoked", "this endpoint was revoked by the operator; enroll again to reconnect")
		return fleet.Agent{}, false
	case err != nil:
		writeError(w, http.StatusUnauthorized, "unauthorized", "agent token is not valid")
		return fleet.Agent{}, false
	}
	return ag, true
}

// handleAgentEnroll exchanges the shared enrollment token for a per-agent token.
func (s *Server) handleAgentEnroll(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	now := s.opts.Now()
	if retryAfter, blocked := s.enrollLimiter.blocked(ip, now); blocked {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(retryAfter.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too_many_attempts", "too many failed enrollment attempts; wait and retry")
		return
	}
	got := strings.TrimSpace(r.Header.Get("X-Guard-Enroll-Token"))
	if got == "" {
		s.enrollLimiter.fail(ip, now)
		s.log.Warn("agent enrollment rejected: no enrollment token", "remote", ip)
		writeError(w, http.StatusUnauthorized, "unauthorized",
			"enrollment token is required; generate one in Settings → Agents")
		return
	}
	var body struct {
		Host    string `json:"host"`
		OS      string `json:"os"`
		Version string `json:"version"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	if strings.TrimSpace(body.Host) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "host is required")
		return
	}
	// Proof of possession: an already-enrolled hostname can only be re-attached by
	// a caller holding that agent's current credential. Without it the request is
	// refused, so reinstalling elsewhere cannot seize an existing identity.
	proof := ""
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		proof = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
	}
	// The token is burned before enrollment so a single installer command cannot
	// enroll two endpoints, and a replay of a captured request finds it spent.
	if err := s.fleet.ConsumeEnrollToken(r.Context(), got, body.Host); err != nil {
		s.enrollLimiter.fail(ip, now)
		code := http.StatusUnauthorized
		msg := "enrollment token is missing or wrong"
		switch {
		case errors.Is(err, fleet.ErrEnrollTokenExpired):
			msg = "enrollment token has expired; generate a new one in Settings → Agents"
		case errors.Is(err, fleet.ErrEnrollTokenUsed):
			msg = "enrollment token has already been used; generate a new one"
		case errors.Is(err, fleet.ErrEnrollTokenInvalid):
			code = http.StatusUnauthorized
			msg = "enrollment token is not valid; generate one in Settings → Agents"
		default:
			code = http.StatusInternalServerError
			msg = err.Error()
		}
		s.log.Warn("agent enrollment rejected", "remote", ip, "reason", err.Error())
		writeError(w, code, "unauthorized", msg)
		return
	}
	ag, token, err := s.fleet.Enroll(r.Context(), body.Host, body.OS, body.Version, proof)
	if err != nil {
		// The token was burned above; hand it back when the failure was not about
		// the token, so the operator can fix the hostname and retry with the same one.
		if releaseErr := s.fleet.ReleaseEnrollToken(r.Context(), got, body.Host); releaseErr != nil {
			s.log.Warn("could not release enrollment token", "err", releaseErr)
		}
	}
	switch {
	case errors.Is(err, fleet.ErrIdentityConflict):
		s.log.Warn("agent enrollment refused: hostname already enrolled", "host", body.Host, "remote", ip)
		writeError(w, http.StatusConflict, "identity_conflict",
			fmt.Sprintf("host %q is already enrolled by %s; reinstall with its existing credential, "+
				"or revoke that agent in the dashboard and enroll again", body.Host, "another agent"))
		return
	case err != nil:
		writeError(w, http.StatusBadRequest, "enroll_error", err.Error())
		return
	}
	s.enrollLimiter.reset(ip)
	s.log.Info("agent enrolled", "agent", ag.ID, "host", ag.Host, "remote", ip)
	writeJSON(w, http.StatusOK, map[string]any{
		"agent_id":    ag.ID,
		"agent_token": token,
		"host":        ag.Host,
	})
}

// handleAgentCheckin records the agent's current state: the telemetry that lets
// the dashboard answer "what is this endpoint doing right now".
func (s *Server) handleAgentCheckin(w http.ResponseWriter, r *http.Request) {
	ag, ok := s.agentFromRequest(w, r)
	if !ok {
		return
	}
	var body struct {
		State    string `json:"state"`
		Phase    string `json:"phase"`
		Percent  int    `json:"percent"`
		Message  string `json:"message"`
		Findings int    `json:"findings"`
		Version  string `json:"version"`
		OS       string `json:"os"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	if !fleet.ValidStates[body.State] {
		writeError(w, http.StatusBadRequest, "invalid_state",
			"state must be one of enrolled, idle, scanning, reporting, error")
		return
	}
	if err := s.fleet.Checkin(r.Context(), ag.ID, fleet.Checkin{
		State: body.State, Phase: body.Phase, Percent: body.Percent,
		Message: body.Message, Findings: body.Findings, Version: body.Version, OS: body.OS,
	}); err != nil {
		s.writeFleetError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleAgentReport ingests a finished report and stores it exactly like a local
// scan, so remote endpoints appear in every existing screen without special cases.
func (s *Server) handleAgentReport(w http.ResponseWriter, r *http.Request) {
	ag, ok := s.agentFromRequest(w, r)
	if !ok {
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAgentReportBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "report_too_large",
			fmt.Sprintf("report exceeds the %d byte limit", maxAgentReportBytes))
		return
	}
	// Replay protection. The digest proves these are the bytes that were hashed;
	// the sequence proves this submission is newer than the last one accepted. A
	// retry of the newest submission stays idempotent (same report id), while an
	// older sequence is refused outright.
	sequence, seqErr := submissionSequence(r)
	if seqErr != nil {
		writeError(w, http.StatusBadRequest, "invalid_submission", seqErr.Error())
		return
	}
	if digest := strings.TrimSpace(r.Header.Get("X-Guard-Payload-SHA256")); digest != "" {
		sum := sha256.Sum256(raw)
		if subtle.ConstantTimeCompare([]byte(strings.ToLower(digest)), []byte(hex.EncodeToString(sum[:]))) != 1 {
			s.log.Warn("report digest mismatch", "agent", ag.ID, "remote", s.clientIP(r))
			writeError(w, http.StatusBadRequest, "digest_mismatch", "payload digest does not match the body")
			return
		}
	}

	var rep model.Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_report", "body is not a Clanker Guard report: "+err.Error())
		return
	}
	if strings.TrimSpace(rep.ReportID) == "" {
		writeError(w, http.StatusBadRequest, "invalid_report", "report_id is required")
		return
	}
	if strings.TrimSpace(rep.Metadata.Host) == "" {
		writeError(w, http.StatusBadRequest, "invalid_report", "metadata.host is required")
		return
	}
	// A report is attributed to the enrolled identity, not to whatever hostname
	// the document claims: otherwise one enrolled agent could overwrite another
	// endpoint's findings.
	if !strings.EqualFold(strings.TrimSpace(rep.Metadata.Host), ag.Host) {
		writeError(w, http.StatusConflict, "host_mismatch",
			fmt.Sprintf("this agent is enrolled as %q but reported as %q; re-enroll if the hostname changed", ag.Host, rep.Metadata.Host))
		return
	}

	// Sequence handling happens after the report id is known, so a plain retry of
	// an already-stored report is accepted idempotently instead of looking like a
	// replay attempt.
	if sequence > 0 && sequence < ag.LastSequence {
		s.log.Warn("replayed report rejected", "agent", ag.ID, "sequence", sequence, "last", ag.LastSequence)
		writeError(w, http.StatusConflict, "replay_detected",
			fmt.Sprintf("submission sequence %d is older than the last accepted submission (%d)", sequence, ag.LastSequence))
		return
	}

	// Recompute the counts from the findings themselves rather than trusting the
	// summary an agent sent: history and the delta view must not be spoofable.
	rep.Summary = report.Summarize(rep.Findings)
	finished := s.opts.Now()
	if rep.Metadata.FinishedAt != nil {
		finished = *rep.Metadata.FinishedAt
	}
	started := rep.Metadata.StartedAt
	if started.IsZero() || started.After(finished) {
		started = finished
	}
	payload, err := report.MarshalJSON(rep)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "store_error", "could not encode the report")
		return
	}
	rec := model.RunRecord{
		ID:           rep.ReportID,
		Host:         ag.Host,
		StartedAt:    started,
		FinishedAt:   finished,
		FindingIDs:   report.FindingFingerprints(rep.Findings),
		FindingCount: len(rep.Findings),
		Actionable:   rep.Summary.Actionable,
		KEVCount:     rep.Summary.KEVCount,
	}
	if err := s.store.SaveRun(r.Context(), rec, payload); err != nil {
		s.log.Error("store agent report", "agent", ag.ID, "err", err)
		writeError(w, http.StatusInternalServerError, "store_error", "could not store the report")
		return
	}
	if sequence > ag.LastSequence {
		if err := s.fleet.AdvanceSequence(r.Context(), ag.ID, sequence); err != nil {
			s.log.Warn("record submission sequence", "agent", ag.ID, "err", err)
		}
	}
	if err := s.fleet.MarkReport(r.Context(), ag.ID, rep.ReportID, len(rep.Findings)); err != nil {
		s.log.Warn("record agent report", "agent", ag.ID, "err", err)
	}
	s.log.Info("agent report ingested", "agent", ag.ID, "host", ag.Host, "report", rep.ReportID, "findings", len(rep.Findings))
	// 200 even for a retry: SaveRun upserts by report id, so a network retry is
	// idempotent and must not look like a failure to the agent.
	writeJSON(w, http.StatusOK, map[string]any{
		"run_id":   rec.ID,
		"findings": len(rep.Findings),
		"accepted": true,
	})
}

// handleAgentRevoke is the operator action that invalidates one endpoint's token.
func (s *Server) handleAgentRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.fleet.Revoke(r.Context(), id); err != nil {
		s.writeFleetError(w, err)
		return
	}
	s.log.Info("agent revoked", "agent", id, "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"revoked": id})
}

// handleAgentEvents returns the recent activity of one endpoint.
func (s *Server) handleAgentEvents(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ag, err := s.fleet.Get(r.Context(), id)
	if err != nil {
		s.writeFleetError(w, err)
		return
	}
	events, err := s.fleet.Events(r.Context(), id, 25)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_error", err.Error())
		return
	}
	tasks, _ := s.fleet.Tasks(r.Context(), id, 10)
	writeJSON(w, http.StatusOK, map[string]any{
		"agent": agentView(ag, s.opts.Now(), s.presence.online(id), runningTask(tasks)), "events": events, "tasks": tasks,
	})
}

// handleEnrollTokenRotate mints a single-use enrollment token.
//
// There is no permanent shared secret any more: the operator generates a token
// when they actually enroll an endpoint, it expires (default 24h) and it is burned
// on first use. Already-enrolled agents are unaffected — they have their own
// credentials.
func (s *Server) handleEnrollTokenRotate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		TTLHours int    `json:"ttl_hours"`
		Label    string `json:"label"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&body)
	}
	ttl := fleet.DefaultEnrollTokenTTL
	if body.TTLHours > 0 && body.TTLHours <= 720 {
		ttl = time.Duration(body.TTLHours) * time.Hour
	}
	token, expires, err := s.fleet.MintEnrollToken(r.Context(), ttl, body.Label)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "agent_error", err.Error())
		return
	}
	s.log.Info("enrollment token minted", "expires", expires.Format(time.RFC3339), "remote", s.clientIP(r))
	commands := s.enrollCommands(r, token)
	writeJSON(w, http.StatusOK, map[string]any{
		"enroll_token":    token,
		"expires_at":      expires.Format(time.RFC3339),
		"single_use":      true,
		"commands":        commands,
		"oneoff_commands": s.enrollCommands(r, token, "--no-service"),
		"keeps_available": true,
	})
}

func (s *Server) writeFleetError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, fleet.ErrNotFound):
		writeError(w, http.StatusNotFound, "agent_not_found", "no such agent")
	default:
		writeError(w, http.StatusInternalServerError, "agent_error", err.Error())
	}
}

// agentView is the dashboard projection of an enrolled endpoint.
//
// `online` answers "can this endpoint be asked to do something right now".
//
//   - a held claim request: yes, work is dispatched instantly;
//   - a running scan: yes, it is reporting progress;
//   - anything else: only within a one-minute grace of its last contact, because an
//     endpooint with no watcher cannot be reached at all. Offline therefore means
//     unreachable (network or process), never "has not reported recently".
func agentView(a fleet.Agent, now time.Time, watching bool, scanning bool) map[string]any {
	view := map[string]any{
		"id":             a.ID,
		"host":           a.Host,
		"os":             a.OS,
		"version":        a.Version,
		"state":          a.State,
		"phase":          a.Phase,
		"percent":        a.Percent,
		"message":        a.Message,
		"findings":       a.Findings,
		"last_report_id": a.LastReport,
		"enrolled_at":    a.EnrolledAt.Format(time.RFC3339),
		"revoked":        a.Revoked,
		"watching":       watching,
		"online":         !a.Revoked && (watching || (a.Online(now) && (scanning || a.State == fleet.StateScanning || a.State == fleet.StateReporting))),
	}
	if a.LastSeen != nil {
		view["last_seen"] = a.LastSeen.Format(time.RFC3339)
		view["seconds_since_seen"] = int(now.Sub(*a.LastSeen).Seconds())
	}
	return view
}

// runningTask reports whether the newest task for an endpoint is in flight.
func runningTask(tasks []fleet.Task) bool {
	for _, t := range tasks {
		if t.Status == fleet.TaskRunning {
			return true
		}
	}
	return false
}

// requestBaseURL is the origin the operator reached the dashboard on, so the
// generated install command points at this server rather than a guessed host.
func requestBaseURL(r *http.Request) string {
	host := r.Host
	if host == "" {
		return ""
	}
	scheme := "http"
	if requestIsHTTPS(r) {
		scheme = "https"
	}
	return scheme + "://" + host
}

// ------------------------------------------------------------- task queue ---

// handleAgentQueueScan asks one enrolled endpoint for a scan. The server does not
// connect out: the agent picks the task up at its next check-in, which is the
// only way this can work without an inbound channel to the endpoint.
func (s *Server) handleAgentQueueScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	task, created, err := s.fleet.QueueScan(r.Context(), id)
	switch {
	case errors.Is(err, fleet.ErrNotFound):
		writeError(w, http.StatusNotFound, "agent_not_found", "no such agent")
		return
	case errors.Is(err, fleet.ErrRevoked):
		writeError(w, http.StatusConflict, "agent_revoked", "this endpoint was revoked; it cannot be asked to scan")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "agent_error", err.Error())
		return
	}
	status := http.StatusAccepted
	if !created {
		status = http.StatusOK
	}
	// Wake the held claim request, if any: an available endpoint starts the scan
	// now instead of at its next poll.
	if created {
		s.presence.notify(id, task)
	}
	s.log.Info("agent scan queued", "agent", id, "task", task.ID, "already_pending", !created,
		"dispatched_to_watcher", s.presence.online(id), "remote", s.clientIP(r))
	writeJSON(w, status, map[string]any{"task": task, "created": created})
}

// handleAgentClaimTask is how an agent asks for work.
//
// The request is *held* open (long poll) while there is nothing to do, and the
// admin queueing a scan answers that held request within milliseconds. That is
// what makes an administrator's scan start immediately, and the held request is
// also what proves the endpoint is reachable — the server still never connects to
// the agent, so no inbound port is opened on the endpoint.
func (s *Server) handleAgentClaimTask(w http.ResponseWriter, r *http.Request) {
	ag, ok := s.agentFromRequest(w, r)
	if !ok {
		return
	}
	wait := claimWaitSeconds(r)
	ctx := r.Context()

	// Register before looking for work: a task queued a microsecond from now must
	// reach this waiter, and one queued just before registration must not be
	// missed by sleeping.
	hold := s.presence.register(ag.ID)
	defer s.presence.cancel(ag.ID, hold)

	deadline := time.NewTimer(wait)
	defer deadline.Stop()

	for {
		task, err := s.fleet.ClaimTask(ctx, ag.ID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "agent_error", err.Error())
			return
		}
		if task != nil {
			s.log.Info("agent claimed task", "agent", ag.ID, "task", task.ID)
			writeJSON(w, http.StatusOK, map[string]any{"task": task})
			return
		}
		if wait <= 0 {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		select {
		case <-ctx.Done():
			// The endpoint went away (process exit, network drop). Presence is
			// dropped by the deferred cancel, so the dashboard stops calling it
			// online immediately.
			return
		case <-deadline.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-hold.ch:
			// Work arrived: loop and claim it.
		}
	}
}

// claimWaitSeconds bounds how long a claim request may be held. Callers may ask
// for less; the ceiling keeps a stuck request from pinning a connection forever.
func claimWaitSeconds(r *http.Request) time.Duration {
	const maxWait = 30
	raw := strings.TrimSpace(r.URL.Query().Get("wait"))
	if raw == "" {
		return 0 // no wait: claim-and-return, used by older agents
	}
	secs, err := strconv.Atoi(raw)
	if err != nil || secs <= 0 {
		return 0
	}
	if secs > maxWait {
		secs = maxWait
	}
	return time.Duration(secs) * time.Second
}

// handleAgentCompleteTask records the outcome so the dashboard can show it.
func (s *Server) handleAgentCompleteTask(w http.ResponseWriter, r *http.Request) {
	ag, ok := s.agentFromRequest(w, r)
	if !ok {
		return
	}
	var body struct {
		TaskID   string `json:"task_id"`
		Status   string `json:"status"`
		Note     string `json:"note"`
		ReportID string `json:"report_id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<10)).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", "request body is not valid JSON")
		return
	}
	if strings.TrimSpace(body.TaskID) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", "task_id is required")
		return
	}
	if body.Status != fleet.TaskDone && body.Status != fleet.TaskFailed {
		writeError(w, http.StatusBadRequest, "invalid_request", "status must be done or failed")
		return
	}
	if err := s.fleet.CompleteTask(r.Context(), ag.ID, body.TaskID, body.Status, body.Note, body.ReportID); err != nil {
		s.writeFleetError(w, err)
		return
	}
	s.log.Info("agent task completed", "agent", ag.ID, "task", body.TaskID, "status", body.Status)
	w.WriteHeader(http.StatusNoContent)
}

// handleAgentCancelScan withdraws a queued scan request.
func (s *Server) handleAgentCancelScan(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	n, err := s.fleet.CancelTask(r.Context(), id)
	switch {
	case errors.Is(err, fleet.ErrNotFound):
		writeError(w, http.StatusNotFound, "nothing_queued",
			"no queued scan for this endpoint (a scan already running cannot be cancelled from here)")
		return
	case err != nil:
		writeError(w, http.StatusInternalServerError, "agent_error", err.Error())
		return
	}
	s.log.Info("queued agent scan cancelled", "agent", id, "remote", s.clientIP(r))
	writeJSON(w, http.StatusOK, map[string]any{"cancelled": n})
}

// enrollCommands renders the copy-and-paste installers for this server and token.
// extra is appended to the shell command and translated for PowerShell, so the
// one-off variant (--no-service) stays in sync with the default.
// enrollCommandTemplate renders the installers with a visible placeholder instead
// of a token, so the dashboard can show the command before one is minted.
func (s *Server) enrollCommandTemplate(r *http.Request) map[string]string {
	return s.enrollCommands(r, "<enroll-token>")
}

func (s *Server) enrollCommands(r *http.Request, enrollToken string, extra ...string) map[string]string {
	base := strings.TrimRight(s.opts.ReleaseBase, "/")
	version := s.opts.ToolVersion
	serverURL := requestBaseURL(r)
	shellExtra, winExtra := "", ""
	// Only the flags the installers actually understand are accepted here, and
	// each has an explicit PowerShell spelling rather than a guessed one.
	winNames := map[string]string{"--no-service": "NoService", "--watch": "Watch"}
	for _, flag := range extra {
		if name, ok := winNames[flag]; ok {
			shellExtra += " " + flag
			winExtra += " -" + name
		}
	}
	args := "--version " + version
	winArgs := "-Version " + version
	if serverURL != "" && enrollToken != "" {
		args += fmt.Sprintf(" --server %s --enroll-token %s", serverURL, enrollToken)
		winArgs += fmt.Sprintf(` -Server "%s" -EnrollToken "%s"`, serverURL, enrollToken)
	}
	return map[string]string{
		"linux": fmt.Sprintf("curl -fsSL %s/install-agent.sh | bash -s -- %s%s", base, args, shellExtra),
		"macos": fmt.Sprintf("curl -fsSL %s/install-agent.sh | bash -s -- %s%s", base, args, shellExtra),
		"windows": fmt.Sprintf(
			`iwr %s/install-agent.ps1 -OutFile "$env:TEMP\install-agent.ps1" -UseBasicParsing; `+
				`& "$env:TEMP\install-agent.ps1" %s%s`, base, winArgs, winExtra),
	}
}

// submissionSequence parses the replay-protection sequence. Absent means a legacy
// client (accepted, and the gateway logs nothing); present must be a positive
// integer, so a malformed header cannot silently disable the check.
func submissionSequence(r *http.Request) (int64, error) {
	raw := strings.TrimSpace(r.Header.Get("X-Guard-Sequence"))
	if raw == "" {
		return 0, nil
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("X-Guard-Sequence must be a positive integer")
	}
	return n, nil
}
