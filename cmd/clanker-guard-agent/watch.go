package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/agent"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// cmdWatch makes the endpoint available for scans requested from the dashboard.
//
// It holds a claim request open instead of polling on a timer: the server answers
// the held request the instant an administrator asks for a scan, so the scan
// starts immediately. The held request is also what marks the endpoint as online —
// an endpoint with no watcher is genuinely unreachable and is shown as offline.
func cmdWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	hold := fs.Duration("hold", 25*time.Second, "how long to hold each claim request open (max 30s)")
	once := fs.Bool("once", false, "claim and run at most one task, then exit")
	configPath := fs.String("config", "", "agent enrollment config path")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if *hold < time.Second {
		*hold = time.Second
	}
	if *hold > 30*time.Second {
		*hold = 30 * time.Second
	}

	cfg, err := agent.LoadConfig(*configPath)
	if errors.Is(err, agent.ErrNotEnrolled) {
		fmt.Fprintln(os.Stderr, "error: watch needs an enrolled agent; run:")
		fmt.Fprintln(os.Stderr, "  clanker-guard-agent enroll --server URL --enroll-token TOKEN")
		return 3
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 3
	}
	if err := agent.ValidateTransport(cfg.Server, cfg.AllowInsecureHTTP); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 3
	}
	client := agent.New(cfg.Server, cfg.Token)
	fmt.Fprintf(os.Stderr, "watching %s as %s — scans requested from the dashboard start immediately\n",
		cfg.Server, cfg.AgentID)

	ctx := context.Background()
	backoff := time.Second
	for {
		task, err := client.ClaimTaskWait(ctx, *hold)
		if err != nil {
			if ctx.Err() != nil {
				return 0
			}
			// Connection lost: that is exactly when the dashboard should show the
			// endpoint as unreachable, so back off quietly rather than spamming.
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
			time.Sleep(backoff)
			if backoff < 30*time.Second {
				backoff *= 2
			}
			continue
		}
		backoff = time.Second
		if task != nil {
			runTask(ctx, cfg, task)
			if *once {
				return 0
			}
		}
		if *once {
			return 0
		}
	}
}

// runTask executes one claimed scan and reports the outcome.
func runTask(ctx context.Context, cfg agent.Config, task *agent.Task) {
	fmt.Fprintf(os.Stderr, "task %s: running scan\n", task.ID)
	client := agent.New(cfg.Server, cfg.Token)
	rep, err := startReporting("", false)
	if err != nil || rep == nil {
		_ = client.CompleteTask(ctx, task.ID, "failed", "agent could not load its config", "")
		return
	}
	res, err := scan.Run(ctx, scan.Options{
		Format:      "json",
		SkipRender:  true,
		ToolVersion: version,
		Progress:    rep.progress,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
	})
	if err != nil {
		_ = client.CompleteTask(ctx, task.ID, "failed", err.Error(), "")
		return
	}
	runID := rep.upload(ctx, res, os.Stderr)
	if runID == "" {
		_ = client.CompleteTask(ctx, task.ID, "failed", "report was not accepted", "")
		return
	}
	printSummary(res)
	_ = client.CompleteTask(ctx, task.ID, "done", "scan finished", runID)
}
