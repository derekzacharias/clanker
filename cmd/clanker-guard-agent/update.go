package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/agent"
)

// cmdUpdate checks for and installs a newer signed agent release.
//
//	clanker-guard-agent update              # check, install, restart the watcher
//	clanker-guard-agent update --check      # report only
//	clanker-guard-agent update --yes        # skip the confirmation prompt
func cmdUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	checkOnly := fs.Bool("check", false, "report whether a newer release exists without installing it")
	yes := fs.Bool("yes", false, "install without asking")
	base := fs.String("release-base", "", "release origin (default: the one recorded at enrollment, or the built-in default)")
	configPath := fs.String("config", "", "config file (default: user config dir/clanker-guard/agent.json)")
	if err := fs.Parse(args); err != nil {
		return 3
	}

	cfg, err := agent.LoadConfig(configPathOr(configPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 3
	}

	updater := &agent.Updater{
		ReleaseBase: firstNonEmpty(*base, cfg.ReleaseBase),
		Version:     version,
		Logf:        func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) },
	}
	ctx := context.Background()
	res, err := updater.Check(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 3
	}
	if res.Reason != "" {
		fmt.Println(res.Reason)
		return 0
	}
	fmt.Printf("running %s, latest %s\n", res.Current, res.Latest)
	if *checkOnly {
		return 0
	}
	if !*yes {
		fmt.Fprintf(os.Stderr, "install %s and restart the watcher? [y/N] ", res.Latest)
		var answer string
		fmt.Fscanln(os.Stdin, &answer)
		if answer != "y" && answer != "Y" && answer != "yes" {
			fmt.Println("cancelled")
			return 0
		}
	}

	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 3
	}
	res, err = updater.Update(ctx, exe, configPathOr(configPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 3
	}
	if res.Updated {
		fmt.Printf("updated to %s; the watcher (if running) was restarted\n", res.Latest)
		return 0
	}
	fmt.Println(res.Reason)
	return 0
}

// cmdUpdateSwap performs the deferred rename on Windows. It runs from the
// staged binary after the previous version has exited.
func cmdUpdateSwap(args []string) int {
	fs := flag.NewFlagSet("update-swap", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	from := fs.String("from", "", "staged binary")
	to := fs.String("to", "", "target binary")
	configPath := fs.String("config", "", "agent config path")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if *from == "" || *to == "" {
		fmt.Fprintln(os.Stderr, "error: --from and --to are required")
		return 3
	}
	if err := agent.RunSwapHelper(*from, *to); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 3
	}
	// Restart the watcher under the new binary (detached, no console).
	cfgPath := configPathOr(configPath)
	if cfgPath != "" {
		if err := agent.RestartWatcherDetached(*to, cfgPath); err != nil {
			fmt.Fprintf(os.Stderr, "warning: the new binary is installed but the watcher did not start: %v\n", err)
		}
	}
	return 0
}

// configPathOr resolves the config path flag against the default.
func configPathOr(p *string) string {
	if p != nil && *p != "" {
		return *p
	}
	return agent.ConfigPath()
}

// maybeAutoUpdate runs the opted-in daily self-update check. It returns true
// when the binary was replaced and this process must exit (the swap helper
// starts the new watcher).
func maybeAutoUpdate(cfg agent.Config, exePath string) bool {
	if !cfg.AutoUpdate {
		return false
	}
	now := time.Now()
	if !cfg.LastUpdateCheck.IsZero() && now.Sub(cfg.LastUpdateCheck) < 23*time.Hour {
		return false
	}
	cfg.LastUpdateCheck = now
	if err := agent.SaveConfig(agent.ConfigPath(), cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not record the update check: %v\n", err)
	}
	updater := &agent.Updater{
		ReleaseBase: cfg.ReleaseBase,
		Version:     version,
		Logf:        func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...) },
	}
	res, err := updater.Update(context.Background(), exePath, agent.ConfigPath())
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: self-update check failed: %v\n", err)
		return false
	}
	if res.Reason != "" {
		fmt.Fprintf(os.Stderr, "self-update: %s\n", res.Reason)
		return false
	}
	return res.Updated
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

var _ = filepath.Join
