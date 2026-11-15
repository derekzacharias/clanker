package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/bgdnvk/clanker/internal/vuln/agent"
	"github.com/bgdnvk/clanker/internal/vuln/service"
)

// cmdService manages the background service that keeps an enrolled endpoint
// reachable. It exists so an operator never has to write a unit file: the
// installer calls `service install` and the endpoint is simply online.
func cmdService(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: clanker-guard-agent service install|uninstall|status")
		return 3
	}
	action := args[0]
	fs := flag.NewFlagSet("service "+action, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	configPath := fs.String("config", "", "agent enrollment config path")
	asJSON := fs.Bool("json", false, "machine-readable output (status)")
	if err := fs.Parse(args[1:]); err != nil {
		return 3
	}
	if *configPath == "" {
		*configPath = agent.ConfigPath()
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot determine this binary's path: "+err.Error())
		return 4
	}
	mgr := service.New(exe, *configPath)
	ctx := context.Background()

	switch action {
	case "install":
		// The service runs `watch`, which needs an enrollment to be meaningful.
		if _, err := agent.LoadConfig(*configPath); err != nil {
			if errors.Is(err, agent.ErrNotEnrolled) {
				fmt.Fprintln(os.Stderr, "error: this agent is not enrolled, so there is nothing to keep available")
				fmt.Fprintln(os.Stderr, "  clanker-guard-agent enroll --server URL --enroll-token TOKEN")
				return 3
			}
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return 3
		}
		st, err := mgr.Install(ctx)
		if errors.Is(err, service.ErrUnsupported) {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
			fmt.Fprintln(os.Stderr, "run the watcher yourself instead, e.g. in a supervisor:")
			fmt.Fprintf(os.Stderr, "  %s watch\n", exe)
			return 0
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: could not install the service: "+err.Error())
			return 4
		}
		fmt.Fprintf(os.Stderr, "service installed: %s\n", st.Path)
		fmt.Fprintf(os.Stderr, "  enabled=%v running=%v platform=%s\n", st.Enabled, st.Running, st.Platform)
		if st.Detail != "" {
			fmt.Fprintln(os.Stderr, "  "+st.Detail)
		}
		return 0

	case "uninstall":
		if _, err := mgr.Uninstall(ctx); err != nil {
			if errors.Is(err, service.ErrUnsupported) {
				return 0
			}
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return 4
		}
		fmt.Fprintln(os.Stderr, "service removed")
		return 0

	case "status":
		st := mgr.Current(ctx)
		if *asJSON {
			_ = json.NewEncoder(os.Stdout).Encode(st)
			return 0
		}
		fmt.Fprintf(os.Stdout, "platform:  %s\ninstalled: %v\nenabled:   %v\nrunning:   %v\n", st.Platform, st.Installed, st.Enabled, st.Running)
		if st.Path != "" {
			fmt.Fprintf(os.Stdout, "path:      %s\n", st.Path)
		}
		if st.Detail != "" {
			fmt.Fprintf(os.Stdout, "note:      %s\n", st.Detail)
		}
		return 0

	default:
		fmt.Fprintln(os.Stderr, "usage: clanker-guard-agent service install|uninstall|status")
		return 3
	}
}
