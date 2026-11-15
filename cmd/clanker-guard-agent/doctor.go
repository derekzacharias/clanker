package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/agent"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
	"github.com/bgdnvk/clanker/internal/vuln/service"
)

// check is one doctor result. Status is "ok", "warn" or "fail".
type check struct {
	name   string
	status string
	detail string
}

func (c check) String() string {
	mark := "OK  "
	switch c.status {
	case "warn":
		mark = "WARN"
	case "fail":
		mark = "FAIL"
	}
	return fmt.Sprintf("%s  %-22s %s", mark, c.name, c.detail)
}

// cmdDoctor answers "why is this endpoint not reporting?" without guesswork: it
// checks each link in the chain (config, transport, connectivity, service, cache,
// queue) and reports what it finds. It never prints the credential.
func cmdDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	configPath := fs.String("config", "", "agent enrollment config path")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	path := *configPath
	if path == "" {
		path = agent.ConfigPath()
	}
	checks := []check{{name: "binary", status: "ok", detail: fmt.Sprintf("clanker-guard-agent %s", version)}}

	cfg, err := agent.LoadConfig(path)
	switch {
	case errors.Is(err, agent.ErrNotEnrolled):
		checks = append(checks, check{"enrollment", "fail", "not enrolled; run: clanker-guard-agent enroll --server URL --enroll-token TOKEN"})
		printChecks(checks)
		return 4
	case err != nil:
		checks = append(checks, check{"enrollment", "fail", err.Error()})
		printChecks(checks)
		return 4
	default:
		checks = append(checks, check{"enrollment", "ok", fmt.Sprintf("%s at %s", cfg.AgentID, cfg.Server)})
	}

	if err := agent.ValidateTransport(cfg.Server, cfg.AllowInsecureHTTP); err != nil {
		checks = append(checks, check{"transport", "fail", err.Error()})
	} else if strings.HasPrefix(cfg.Server, "http://") {
		checks = append(checks, check{"transport", "warn", "plain HTTP (loopback or explicitly allowed); prefer an https:// server"})
	} else {
		checks = append(checks, check{"transport", "ok", "HTTPS"})
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client := agent.New(cfg.Server, cfg.Token)
	if health, err := client.Health(ctx); err != nil {
		checks = append(checks, check{"server", "fail", err.Error()})
	} else {
		checks = append(checks, check{"server", "ok", health})
	}
	// Authenticated probe: distinguishes "server up, credential rejected".
	if _, err := client.ClaimTaskWait(ctx, 0); err != nil {
		checks = append(checks, check{"credential", "fail", err.Error()})
	} else {
		checks = append(checks, check{"credential", "ok", "accepted by the server"})
	}

	exe, _ := os.Executable()
	mgr := service.New(exe, path)
	st := mgr.Current(ctx)
	switch {
	case !st.Installed:
		checks = append(checks, check{"service", "warn", "not installed; the endpoint is only reachable while `watch` runs"})
	case st.Running:
		checks = append(checks, check{"service", "ok", fmt.Sprintf("%s running, enabled=%v", st.Platform, st.Enabled)})
	default:
		checks = append(checks, check{"service", "fail", fmt.Sprintf("installed but not running (%s); run: clanker-guard-agent service start", st.Platform)})
	}

	// The cache directory must be writable: the scan stores intelligence there.
	cacheDir := filepath.Dir(scan.DefaultCachePath())
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		checks = append(checks, check{"cache", "fail", err.Error()})
	} else if probe, err := os.CreateTemp(cacheDir, ".doctor-*"); err != nil {
		checks = append(checks, check{"cache", "fail", "not writable: " + err.Error()})
	} else {
		probe.Close()
		os.Remove(probe.Name())
		checks = append(checks, check{"cache", "ok", cacheDir})
	}

	// Offline queue depth: pending reports explain a stale dashboard.
	if q, err := agent.OpenQueue(agent.QueuePath(path)); err == nil {
		pending := q.Len()
		status := "ok"
		detail := "empty"
		if pending > 0 {
			status = "warn"
			detail = fmt.Sprintf("%d report(s) waiting to upload", pending)
		}
		checks = append(checks, check{"offline queue", status, detail})
	}

	printChecks(checks)
	for _, c := range checks {
		if c.status == "fail" {
			return 4
		}
	}
	return 0
}

func printChecks(checks []check) {
	for _, c := range checks {
		fmt.Fprintln(os.Stdout, c.String())
	}
}
