package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/agent"
	"github.com/bgdnvk/clanker/internal/vuln/report"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// cmdEnroll exchanges the dashboard's enrollment token for this endpoint's own
// credential and stores it. Nothing is sent anywhere until this succeeds.
func cmdEnroll(args []string) int {
	fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	server := fs.String("server", "", "Clanker Guard server URL, e.g. https://guard.example:8787")
	token := fs.String("enroll-token", "", "enrollment token shown in Settings → Agents")
	host := fs.String("host", "", "hostname to enroll as (default: this host's name)")
	allowInsecure := fs.Bool("allow-insecure-http", false,
		"permit a plain-HTTP server URL on a non-loopback address (lab networks only; not recommended)")
	configPath := fs.String("config", "", "config file (default: user config dir/clanker-guard/agent.json)")
	autoUpdate := fs.Bool("auto-update", false, "check the signed release origin about once a day and replace this agent when a newer version exists")
	releaseBase := fs.String("release-base", "", "release origin for self-updates (default: the built-in GitHub releases)")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if strings.TrimSpace(*server) == "" || strings.TrimSpace(*token) == "" {
		fmt.Fprintln(os.Stderr, "error: --server and --enroll-token are required")
		return 3
	}
	hostname := strings.TrimSpace(*host)
	if hostname == "" {
		if h, err := os.Hostname(); err == nil {
			hostname = h
		} else {
			hostname = "unknown"
		}
	}
	if err := agent.ValidateTransport(*server, *allowInsecure); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 3
	}
	// Reinstalling a machine that is already enrolled proves ownership of the
	// existing identity by presenting its current credential. Without this a
	// legitimate reinstall would be blocked (the server refuses to hand the
	// hostname to a caller that cannot show it already had it).
	proof := ""
	if existing, err := agent.LoadConfig(agent.ConfigPath()); err == nil {
		// Present the credential even when the server URL changed: moving an
		// endpoint to a new address must not cost it its identity. The server
		// scopes the proof to the agent that owns this hostname, so a credential
		// for a different endpoint simply fails closed.
		proof = existing.Token
		if strings.TrimRight(existing.Server, "/") != strings.TrimRight(*server, "/") {
			fmt.Fprintf(os.Stderr, "re-enrolling %s and switching it from %s to %s\n",
				existing.AgentID, existing.Server, *server)
		} else {
			fmt.Fprintf(os.Stderr, "re-enrolling as %s (presenting the existing credential)\n", existing.AgentID)
		}
	}
	client := agent.New(*server, proof)
	if client.PlainHTTP() {
		fmt.Fprintln(os.Stderr, "warning: enrolling over plain HTTP; the agent token crosses the network in clear text")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cfg, err := client.Enroll(ctx, strings.TrimSpace(*token), hostname, osName(), version)
	if err == nil {
		cfg.AllowInsecureHTTP = *allowInsecure
		cfg.AutoUpdate = *autoUpdate
		cfg.ReleaseBase = strings.TrimSpace(*releaseBase)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 4
	}
	if *configPath == "" {
		*configPath = agent.ConfigPath()
	}
	if err := agent.SaveConfig(*configPath, cfg); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 4
	}
	fmt.Fprintf(os.Stderr, "enrolled as %s (%s)\n  server: %s\n  config: %s\n",
		cfg.AgentID, cfg.Host, cfg.Server, *configPath)
	return 0
}

// cmdStatus shows the local enrollment state of this endpoint.
func cmdStatus(args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "config file (default: user config dir/clanker-guard/agent.json)")
	asJSON := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	path := *configPath
	if path == "" {
		path = agent.ConfigPath()
	}
	cfg, err := agent.LoadConfig(path)
	if errors.Is(err, agent.ErrNotEnrolled) {
		if *asJSON {
			_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"enrolled": false, "config": path})
		} else {
			fmt.Fprintf(os.Stderr, "not enrolled (%s does not exist)\n", path)
			fmt.Fprintln(os.Stderr, "this agent runs fully offline; to report to a dashboard:")
			fmt.Fprintln(os.Stderr, "  clanker-guard-agent enroll --server URL --enroll-token TOKEN")
		}
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 4
	}
	if *asJSON {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{
			"enrolled": true, "server": cfg.Server, "agent_id": cfg.AgentID,
			"host": cfg.Host, "enrolled_at": cfg.EnrolledAt, "config": path,
		})
		return 0
	}
	fmt.Fprintf(os.Stdout, "enrolled:  %s\tserver: %s\nhost: %s\tversion: %s\nconfig: %s\n",
		cfg.AgentID, cfg.Server, cfg.Host, version, path)
	return 0
}

// reporting is the scan-side helper: it announces what the endpoint is doing
// while the assessment runs and uploads the finished report.
type reporting struct {
	cfg        agent.Config
	configPath string
	reporter   *agent.Reporter
	warned     bool
}

// startReporting loads the enrollment. A missing config is not an error: the
// agent stays local-only, which is the default posture.
func startReporting(configPath string, disabled bool) (*reporting, error) {
	if disabled {
		return nil, nil
	}
	cfg, err := agent.LoadConfig(configPath)
	if errors.Is(err, agent.ErrNotEnrolled) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if err := agent.ValidateTransport(cfg.Server, cfg.AllowInsecureHTTP); err != nil {
		return nil, fmt.Errorf("%w (re-enroll with an https:// server URL)", err)
	}
	if configPath == "" {
		configPath = agent.ConfigPath()
	}
	return &reporting{cfg: cfg, configPath: configPath, reporter: agent.NewReporter(agent.New(cfg.Server, cfg.Token))}, nil
}

// progress is wired into scan.Options.Progress.
func (r *reporting) progress(st scan.Stage) {
	if r == nil {
		return
	}
	err := r.reporter.Send(context.Background(), agent.Status{
		State: agentStateScanning, Phase: st.Name, Percent: st.Percent,
		Message: st.Detail, Version: version, OS: osName(),
	}, false)
	r.note(err)
}

// upload sends the finished report and leaves the endpoint marked idle.
func (r *reporting) upload(ctx context.Context, res scan.Result, stderr io.Writer) string {
	if r == nil {
		return ""
	}
	if err := r.reporter.Send(ctx, agent.Status{
		State: agentStateReporting, Phase: "upload", Percent: 99,
		Message: "uploading report", Findings: len(res.Report.Findings), Version: version, OS: osName(),
	}, true); err != nil {
		r.note(err)
		fmt.Fprintf(stderr, "warning: could not report status to %s: %v\n", r.cfg.Server, err)
		return ""
	}
	payload, err := report.MarshalJSON(res.Report)
	if err != nil {
		fmt.Fprintf(stderr, "warning: could not encode the report: %v\n", err)
		return ""
	}
	// Each successful upload consumes one sequence number. It is persisted so a
	// restart cannot re-use an old one, which the server treats as a replay.
	sequence := r.cfg.NextSequence + 1
	ack, err := r.reporter.Client.ReportWithSequence(ctx, payload, sequence)
	// A reset local counter (upgrade, restored config, new user profile) would otherwise be
	// rejected as a replay for ever. Take the server's number, persist it, and try once more.
	var replay *agent.ReplayError
	if errors.As(err, &replay) {
		sequence = replay.LastSequence + 1
		fmt.Fprintf(stderr, "notice: local report counter was behind %s; resuming at sequence %d\n",
			r.cfg.Server, sequence)
		ack, err = r.reporter.Client.ReportWithSequence(ctx, payload, sequence)
	}
	if err != nil {
		// A rejected report (bad request, replay, revoked credential) will not get
		// better by retrying; a transport failure might, so only that is queued.
		if isTransportError(err) {
			if qerr := r.spool(payload, sequence, res.Report.ReportID); qerr == nil {
				fmt.Fprintf(stderr, "warning: %s is unreachable (%v); report queued locally and will be retried\n",
					r.cfg.Server, err)
			} else {
				fmt.Fprintf(stderr, "warning: report not accepted (%v) and could not be queued (%v)\n", err, qerr)
			}
		} else {
			fmt.Fprintf(stderr, "warning: report was rejected by %s: %v\n", r.cfg.Server, err)
		}
		return ""
	}
	r.cfg.NextSequence = sequence
	if err := agent.SaveConfig(r.configPath, r.cfg); err != nil {
		fmt.Fprintf(stderr, "warning: could not persist the submission sequence: %v\n", err)
	}
	fmt.Fprintf(stderr, "reported to %s: %s (%d findings)\n", r.cfg.Server, ack.RunID, ack.Findings)
	// The server marks the endpoint idle when it accepts a report; a final status
	// keeps the dashboard truthful even if the report was deduplicated.
	_ = r.reporter.Send(ctx, agent.Status{
		State: agentStateIdle, Phase: "idle", Percent: 100,
		Message: fmt.Sprintf("idle; last report %s", ack.RunID), Findings: ack.Findings,
		Version: version, OS: osName(),
	}, true)
	return ack.RunID
}

// spool stores a report for later delivery, advancing the persisted sequence so the
// queued copy keeps its place in the replay-protected order.
func (r *reporting) spool(payload []byte, sequence int64, reportID string) error {
	q, err := agent.OpenQueue(agent.QueuePath(r.configPath))
	if err != nil {
		return err
	}
	if err := q.Enqueue(payload, sequence, reportID, time.Now().UTC()); err != nil {
		return err
	}
	r.cfg.NextSequence = sequence
	return agent.SaveConfig(r.configPath, r.cfg)
}

// flushQueue uploads spooled reports in order, stopping at the first failure so the
// server's monotonic sequence check stays satisfied.
func (r *reporting) flushQueue(ctx context.Context, stderr io.Writer) {
	q, err := agent.OpenQueue(agent.QueuePath(r.configPath))
	if err != nil {
		return
	}
	items, err := q.List()
	if err != nil || len(items) == 0 {
		return
	}
	sent := 0
	for _, item := range items {
		_, err := r.reporter.Client.ReportWithSequence(ctx, item.Payload, item.Sequence)
		if err != nil {
			if !isTransportError(err) {
				// The server will never accept this one; drop it rather than blocking
				// every later report behind it.
				_ = q.Remove(item.Path)
				fmt.Fprintf(stderr, "warning: dropped a queued report the server rejected (%v)\n", err)
				continue
			}
			fmt.Fprintf(stderr, "note: %d report(s) still queued for %s\n", len(items)-sent, r.cfg.Server)
			return
		}
		_ = q.Remove(item.Path)
		sent++
	}
	if sent > 0 {
		fmt.Fprintf(stderr, "uploaded %d queued report(s)\n", sent)
	}
}

// isTransportError distinguishes "could not deliver" from "server said no".
// agent.Client wraps request failures with "cannot reach".
func isTransportError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "cannot reach")
}

func (r *reporting) note(err error) {
	if r == nil || err == nil || r.warned {
		return
	}
	r.warned = true
	fmt.Fprintf(os.Stderr, "warning: status updates are not reaching %s: %v\n", r.cfg.Server, err)
}

func osName() string {
	if v, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(v), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				return strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), `"`)
			}
		}
	}
	return runtime.GOOS
}

// Agent-reported states are the server's closed set; named here so the CLI and
// the API cannot drift.
const (
	agentStateScanning  = "scanning"
	agentStateReporting = "reporting"
	agentStateIdle      = "idle"
)
