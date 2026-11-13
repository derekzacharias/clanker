// Command clanker-guard-agent is the standalone endpoint agent.
//
// It performs local software inventory and vulnerability assessment with no
// cloud dependency, no service installation and no privileges by default.
//
//	clanker-guard-agent scan --local
//	clanker-guard-agent feeds update
//	clanker-guard-agent scan --local --format json --output findings.json
//	clanker-guard-agent uninstall --yes
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
)

// version is injected at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage("")
		return 0
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:])
	case "feeds":
		return cmdFeeds(args[1:])
	case "inventory":
		return cmdInventory(args[1:])
	case "ask":
		return cmdAsk(args[1:])
	case "uninstall":
		return cmdUninstall(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("clanker-guard-agent %s\n", version)
		return 0
	case "help", "--help", "-h":
		usage("")
		return 0
	default:
		usage("unknown command: " + args[0])
		return 3
	}
}

func usage(errMsg string) {
	if errMsg != "" {
		fmt.Fprintln(os.Stderr, "error: "+errMsg)
	}
	fmt.Fprint(os.Stderr, `clanker-guard-agent — local, evidence-based vulnerability assessment

Usage:
  clanker-guard-agent scan [--local] [--offline] [--format json|markdown|sarif|html]
                           [--output FILE] [--fail-on SEVERITY] [--fail-on-kev]
                           [--cache FILE] [--no-python] [--no-npm] [--no-ruby] [--quiet]
  clanker-guard-agent inventory [--format json|markdown]
  clanker-guard-agent feeds update [--with-osv] | feeds status
  clanker-guard-agent ask "question"
  clanker-guard-agent uninstall [--yes]
  clanker-guard-agent version

Exit codes: 0 clean, 2 findings above policy, 3 configuration error,
4 incomplete assessment (reduced coverage).
`)
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var (
		local       = fs.Bool("local", true, "assess this endpoint")
		offline     = fs.Bool("offline", false, "use only cached intelligence")
		format      = fs.String("format", "json", "json, markdown, sarif or html")
		output      = fs.String("output", "", "report path ('-' for stdout)")
		cachePath   = fs.String("cache", "", "intelligence cache path")
		failOn      = fs.String("fail-on", "", "exit 2 at or above this severity")
		failOnKEV   = fs.Bool("fail-on-kev", false, "exit 2 for KEV findings")
		noPython    = fs.Bool("no-python", false, "skip Python inventory")
		noNPM       = fs.Bool("no-npm", false, "skip npm inventory")
		noRuby      = fs.Bool("no-ruby", false, "skip Ruby inventory")
		quiet       = fs.Bool("quiet", false, "suppress the human summary")
		notAffected = fs.Bool("include-not-affected", false, "include not-affected records")
		criticality = fs.Float64("asset-criticality", 0, "asset criticality 0..1")
	)
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if !*local {
		fmt.Fprintln(os.Stderr, "error: only endpoint assessment (--local) is implemented in this build")
		return 3
	}
	res, err := scan.Run(context.Background(), scan.Options{
		CachePath:          *cachePath,
		Offline:            *offline,
		Format:             *format,
		OutputPath:         *output,
		IncludeNotAffected: *notAffected,
		NoPython:           *noPython,
		NoNpm:              *noNPM,
		NoRuby:             *noRuby,
		Policy:             model.Policy{FailOnSeverity: *failOn, FailOnKEV: *failOnKEV},
		ToolVersion:        version,
		AssetCriticality:   *criticality,
		Stdout:             os.Stdout,
		Stderr:             os.Stderr,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 4
	}
	if !*quiet {
		printSummary(res)
	}
	return res.ExitCode
}

func printSummary(res scan.Result) {
	rep := res.Report
	fmt.Fprintf(os.Stderr, "clanker-guard-agent %s — %s (%s %s)\n", rep.Metadata.ToolVersion,
		rep.Metadata.Host, rep.Inventory.Asset.OS, rep.Inventory.Asset.OSVersion)
	fmt.Fprintf(os.Stderr, "packages: %d  |  actionable findings: %d/%d  |  KEV: %d\n",
		rep.Metadata.Coverage.PackagesInspected, rep.Summary.Actionable, rep.Summary.Total, rep.Summary.KEVCount)
	for i, f := range rep.Findings {
		if i >= 5 {
			break
		}
		fmt.Fprintf(os.Stderr, "  %-28s %-18s %-18s %-8s risk %.1f\n",
			f.Product, f.InstalledVersion, f.VulnerabilityID, f.Severity, f.RiskScore)
	}
	if res.OutputPath != "" {
		fmt.Fprintf(os.Stderr, "report: %s\n", res.OutputPath)
	}
}

func cmdFeeds(args []string) int {
	if len(args) == 0 {
		usage("feeds requires update or status")
		return 3
	}
	switch args[0] {
	case "update":
		fs := flag.NewFlagSet("feeds update", flag.ContinueOnError)
		withOSV := fs.Bool("with-osv", false, "also cache OSV advisories for this host")
		cachePath := fs.String("cache", "", "intelligence cache path")
		if err := fs.Parse(args[1:]); err != nil {
			return 3
		}
		if _, err := scan.UpdateFeeds(context.Background(), *cachePath, *withOSV, os.Stderr); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return 4
		}
		return 0
	case "status":
		fs := flag.NewFlagSet("feeds status", flag.ContinueOnError)
		cachePath := fs.String("cache", "", "intelligence cache path")
		if err := fs.Parse(args[1:]); err != nil {
			return 3
		}
		if err := scan.FeedStatus(context.Background(), *cachePath, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "error: "+err.Error())
			return 4
		}
		return 0
	default:
		usage("unknown feeds subcommand: " + args[0])
		return 3
	}
}

func cmdInventory(args []string) int {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	format := fs.String("format", "json", "json or markdown")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	if err := scan.InventoryOnly(context.Background(), "", *format, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 4
	}
	return 0
}

func cmdAsk(args []string) int {
	if len(args) == 0 {
		usage(`ask requires a question, e.g. ask "what should I patch first?"`)
		return 3
	}
	cachePath := scan.DefaultCachePath()
	// allow --cache before or after the question
	var parts []string
	for i := 0; i < len(args); i++ {
		if args[i] == "--cache" && i+1 < len(args) {
			cachePath = args[i+1]
			i++
			continue
		}
		parts = append(parts, args[i])
	}
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		return 4
	}
	defer store.Close()
	_, payload, err := store.LatestRun(context.Background(), "")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: no stored assessment; run `clanker-guard-agent scan --local` first")
		return 3
	}
	var rep model.Report
	if err := json.Unmarshal(payload, &rep); err != nil {
		fmt.Fprintln(os.Stderr, "error: stored report is unreadable")
		return 4
	}
	fmt.Println(scan.Ask(rep, strings.Join(parts, " ")))
	return 0
}

// cmdUninstall removes the agent binary and its cache, nothing else. It never
// touches package-manager state and leaves no service behind because none is
// installed by default.
func cmdUninstall(args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "confirm removal")
	keepCache := fs.Bool("keep-cache", false, "keep the intelligence cache")
	if err := fs.Parse(args); err != nil {
		return 3
	}
	cacheDir := filepath.Dir(scan.DefaultCachePath())
	exe, _ := os.Executable()
	if !*yes {
		fmt.Fprintf(os.Stderr, "This will remove:\n  - %s\n  - %s (unless --keep-cache)\nRe-run with --yes to confirm.\n",
			exe, cacheDir)
		return 3
	}
	if !*keepCache {
		if err := os.RemoveAll(cacheDir); err != nil {
			fmt.Fprintln(os.Stderr, "warning: could not remove cache: "+err.Error())
		} else {
			fmt.Fprintf(os.Stderr, "removed %s\n", cacheDir)
		}
	}
	// Remove the binary last so failure above still leaves a usable agent.
	if err := os.Remove(exe); err != nil {
		fmt.Fprintf(os.Stderr, "could not remove %s: %v\nRemove it manually.\n", exe, err)
		return 4
	}
	fmt.Fprintf(os.Stderr, "removed %s\n", exe)
	return 0
}
