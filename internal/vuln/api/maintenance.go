package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// Maintenance: the jobs nobody remembers to run by hand.
//
// Three sweeps share one ticker because they are all "make the stored state match
// reality": expire exceptions whose review date passed, prune history past its retention,
// and tell the configured webhook about work that is late. Each is idempotent, so a
// restart or a double tick cannot corrupt anything.

// startMaintenance runs the sweeps at startup and then on an interval.
func (s *Server) startMaintenance() {
	if s.opts.DisableBackgroundJobs {
		return
	}
	interval := s.maintenanceInterval()
	go func() {
		// Startup pass: an acceptance that expired while the server was down must not wait
		// for the first tick, and neither must a stale queue.
		s.runMaintenance(context.Background())
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			s.runMaintenance(context.Background())
		}
	}()
	s.log.Info("maintenance loop started", "interval", interval.String())
}

func (s *Server) maintenanceInterval() time.Duration {
	raw := s.mustSettings()["maintenance.interval_minutes"]
	if raw != "" {
		var n int
		if _, err := fmt.Sscanf(raw, "%d", &n); err == nil && n >= 1 && n <= 1440 {
			return time.Duration(n) * time.Minute
		}
	}
	return 15 * time.Minute
}

func (s *Server) runMaintenance(ctx context.Context) {
	if s.remediate != nil {
		expired, err := s.remediate.ExpireAcceptances(ctx)
		if err != nil {
			s.log.Warn("expire acceptances failed", "err", err)
		}
		for _, item := range expired {
			s.log.Info("risk acceptance expired; finding reopened", "id", item.ID,
				"asset", item.Asset, "vulnerability", item.VulnerabilityID)
			s.store.AppendAudit(ctx, auditEntry("system", "remediation.acceptance_expired", item.ID,
				fmt.Sprintf("asset=%s vuln=%s state=%s", item.Asset, item.VulnerabilityID, item.State), ""))
		}
	}
	if s.opts.RetentionDays > 0 {
		cutoff := time.Now().UTC().AddDate(0, 0, -s.opts.RetentionDays).Format(time.RFC3339)
		if removed, err := s.store.PruneRuns(ctx, cutoff); err != nil {
			s.log.Warn("prune history failed", "err", err)
		} else if removed > 0 {
			s.log.Info("pruned stored assessments", "removed", removed, "older_than_days", s.opts.RetentionDays)
			s.store.AppendAudit(ctx, auditEntry("system", "maintenance.prune",
				fmt.Sprintf("%d assessments", removed),
				fmt.Sprintf("retention=%d days", s.opts.RetentionDays), ""))
		}
	}
	s.refreshFeedsIfDue(ctx)
	s.notifyDigest(ctx)
}

// refreshFeedsIfDue keeps KEV and EPSS current on a schedule.
//
// Priority and SLA depend on them: a stale "known exploited" list quietly downgrades work
// that is being exploited right now. The dashboard shows freshness, but showing it is not
// the same as keeping it fresh.
func (s *Server) refreshFeedsIfDue(ctx context.Context) {
	settings := s.mustSettings()
	hours := 24
	if raw := strings.TrimSpace(settings["feeds.refresh_hours"]); raw != "" {
		if _, err := fmt.Sscanf(raw, "%d", &hours); err != nil || hours < 1 {
			hours = 24
		}
	}
	if last := strings.TrimSpace(settings["feeds.last_refresh"]); last != "" {
		if ts, err := time.Parse(time.RFC3339, last); err == nil && time.Since(ts) < time.Duration(hours)*time.Hour {
			return
		}
	}
	if _, err := scan.UpdateFeeds(ctx, s.opts.CachePath, false, io.Discard); err != nil {
		s.log.Warn("scheduled feed refresh failed", "err", err)
		return
	}
	s.store.SetSetting(ctx, "feeds.last_refresh", time.Now().UTC().Format(time.RFC3339))
	s.store.AppendAudit(ctx, auditEntry("system", "feeds.refresh", "", fmt.Sprintf("interval=%dh", hours), ""))
	s.log.Info("vulnerability intelligence refreshed on schedule", "interval_hours", hours)
}

// handleMaintenanceRun lets an operator trigger the sweeps (useful after changing policy).
func (s *Server) handleMaintenanceRun(w http.ResponseWriter, r *http.Request) {
	s.runMaintenance(r.Context())
	s.audit(r, "maintenance.run", "", "manual sweep")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "at": time.Now().UTC().Format(time.RFC3339)})
}

// handleBackup writes a consistent copy of the database using SQLite's own backup path.
//
// Copying a live SQLite file with `cp` can capture a half-written page; VACUUM INTO is the
// supported way to get a snapshot that will open.
func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if s.opts.BackupDir == "" {
		writeError(w, http.StatusConflict, "backup_disabled",
			"no backup directory is configured; start the server with --backup-dir")
		return
	}
	if err := os.MkdirAll(s.opts.BackupDir, 0o700); err != nil {
		writeError(w, http.StatusInternalServerError, "backup_error", err.Error())
		return
	}
	name := "intel-" + time.Now().UTC().Format("20060102T150405Z") + ".db"
	path := s.opts.BackupDir + string(os.PathSeparator) + name
	if err := s.store.BackupTo(r.Context(), path); err != nil {
		writeError(w, http.StatusInternalServerError, "backup_error", err.Error())
		return
	}
	s.audit(r, "maintenance.backup", path, name)
	s.log.Info("database backed up", "path", path)
	writeJSON(w, http.StatusOK, map[string]any{"path": path, "name": name})
}

// auditEntry is the shared shape for actions performed by the system itself.
func auditEntry(actor, action, target, detail, remote string) intel.AuditEntry {
	return intel.AuditEntry{
		At: time.Now().UTC().Format(time.RFC3339), Actor: actor, Action: action,
		Target: target, Detail: detail, Remote: remote,
	}
}

// postWebhook delivers a JSON body with a short timeout and a size cap on the answer.
//
// The destination is operator-configured, so it is validated like any other outbound
// target: no plain HTTP to the public internet, and no redirects that would carry the
// secret elsewhere.
func postWebhook(ctx context.Context, rawURL string, body []byte, secret string) error {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("notification url must be http(s)")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "clanker-guard/notify")
	if secret != "" {
		req.Header.Set("X-Guard-Signature", hmacHex(secret, body))
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("webhook redirects are not followed")
		},
	}
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer res.Body.Close()
	io.Copy(io.Discard, io.LimitReader(res.Body, 4<<10))
	if res.StatusCode >= 300 {
		return fmt.Errorf("webhook answered %d", res.StatusCode)
	}
	return nil
}

// hmacHex signs the payload so the receiver can tell a real digest from a forged one.
func hmacHex(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// notifyDigest posts overdue and expiring work to the configured webhook.
//
// One generic endpoint, honestly labelled: this is not Slack-specific, it does not retry
// forever, and it says in the payload exactly what it is. Notably it never includes
// package versions or evidence — a notification should say "you have 4 overdue items on
// web01", not exfiltrate the estate to a chat log.
func (s *Server) notifyDigest(ctx context.Context) {
	settings := s.mustSettings()
	raw := strings.TrimSpace(settings["notify.webhook_url"])
	if raw == "" || s.remediate == nil {
		return
	}
	if !s.digestDue(settings) {
		return
	}
	sum, err := s.remediate.Summary(ctx)
	if err != nil {
		return
	}
	if sum.Overdue == 0 && sum.AcceptancesDue == 0 {
		return
	}
	payload := map[string]any{
		"source":          "clanker-guard",
		"generated":       time.Now().UTC().Format(time.RFC3339),
		"overdue":         sum.Overdue,
		"unassigned":      sum.Unassigned,
		"open":            sum.Open,
		"triage":          sum.TriageAssets,
		"acceptances_due": sum.AcceptancesDue,
	}
	body, _ := json.Marshal(payload)
	if err := postWebhook(ctx, raw, body, settings["notify.webhook_secret"]); err != nil {
		s.log.Warn("notification webhook failed", "err", err)
		return
	}
	s.store.SetSetting(ctx, "notify.last_sent", time.Now().UTC().Format(time.RFC3339))
	s.log.Info("notification sent", "overdue", sum.Overdue, "acceptances_due", sum.AcceptancesDue)
}

// digestDue keeps the digest to one message per interval rather than one per tick.
func (s *Server) digestDue(settings map[string]string) bool {
	last := strings.TrimSpace(settings["notify.last_sent"])
	if last == "" {
		return true
	}
	ts, err := time.Parse(time.RFC3339, last)
	if err != nil {
		return true
	}
	hours := 24
	if raw := strings.TrimSpace(settings["notify.digest_hours"]); raw != "" {
		fmt.Sscanf(raw, "%d", &hours)
		if hours < 1 {
			hours = 1
		}
	}
	return time.Since(ts) >= time.Duration(hours)*time.Hour
}
