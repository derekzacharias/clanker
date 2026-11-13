package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/bgdnvk/clanker/internal/vuln/api"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
	"github.com/bgdnvk/clanker/internal/vuln/scope"
)

// ExitCode reports the exit code requested by the last subcommand.
func ExitCode() int { return guardExitCode }

// guardExitCode is consumed by main() so commands can express policy results
// (findings above threshold, incomplete assessment) without exiting mid-run.
var guardExitCode int

func newVulnCmd() *cobra.Command {
	vuln := &cobra.Command{
		Use:   "vuln",
		Short: "Assess endpoints for applicable vulnerabilities (Clanker Guard)",
		Long: `Clanker Guard is the vulnerability assessment subsystem.

It is separate from "clanker scan" (cost analysis) and "clanker security"
(HTTP/API posture review). Detection is deterministic and evidence-based:

  inventory -> public intelligence -> version/configuration applicability
           -> confidence classification -> risk prioritisation -> report

Nothing is scanned over the network without an explicit scope file, and a
completed scan never means "no vulnerabilities exist" — reports state exactly
what was and was not covered.`,
	}
	vuln.AddCommand(
		newVulnScanCmd(),
		newVulnFeedsCmd(),
		newVulnInventoryCmd(),
		newVulnReportCmd(),
		newVulnAskCmd(),
		newVulnScopeCmd(),
		newVulnAgentCmd(),
		newVulnServeCmd(),
	)
	return vuln
}

// vulnCommonFlags registers flags shared by scan/feeds/inventory.
type vulnCommonFlags struct {
	cache string
}

func (f *vulnCommonFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.cache, "cache", "", "intelligence cache path (default: user cache dir/clanker-guard/intel.db)")
}

func (f *vulnCommonFlags) path() string {
	if f.cache != "" {
		return f.cache
	}
	return scan.DefaultCachePath()
}

func newVulnScanCmd() *cobra.Command {
	var (
		common             vulnCommonFlags
		local              bool
		offline            bool
		format             string
		output             string
		failOn             string
		failOnKEV          bool
		includeNotAffected bool
		noPython           bool
		noNPM              bool
		noRuby             bool
		criticality        float64
		targets            []string
		scopeFile          string
		authorized         bool
		quiet              bool
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Assess the local endpoint (or an explicitly scoped network target)",
		Long: `Assess installed software against public vulnerability intelligence.

Local assessment (default) reads package-manager metadata only: dpkg/rpm/apk,
Python dist-info, npm global packages, Ruby gems. It performs no network
scanning and needs no privileges.

Remote assessment is gated: it requires --scope <file> and --i-authorize, and is
reported as not implemented in this build (see the roadmap).`,
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := c.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			// Remote paths are deliberately refused until Phase 3 lands, but the
			// authorisation machinery is exercised so the guard cannot regress.
			if scopeFile != "" || len(targets) > 0 {
				return handleRemoteScan(ctx, scopeFile, targets, authorized)
			}
			if !local {
				return configError("nothing to scan: pass --local or an authorised --scope")
			}

			res, err := scan.Run(ctx, scan.Options{
				CachePath:          common.path(),
				Offline:            offline,
				Format:             format,
				OutputPath:         output,
				IncludeNotAffected: includeNotAffected,
				Policy:             model.Policy{FailOnSeverity: failOn, FailOnKEV: failOnKEV},
				NoPython:           noPython,
				NoNpm:              noNPM,
				NoRuby:             noRuby,
				ToolVersion:        Version,
				AssetCriticality:   criticality,
			})
			if err != nil {
				return err
			}
			if !quiet {
				printScanSummary(res)
			}
			guardExitCode = res.ExitCode
			return nil
		},
	}
	cmd.Flags().BoolVar(&local, "local", true, "assess this endpoint (default)")
	cmd.Flags().BoolVar(&offline, "offline", false, "use only cached intelligence (no network calls)")
	cmd.Flags().StringVar(&format, "format", "json", "report format: json, markdown, sarif, html")
	cmd.Flags().StringVar(&output, "output", "", "report path ('-' for stdout; default ./clanker-guard-report.<ext>)")
	cmd.Flags().StringVar(&failOn, "fail-on", "", "exit 2 when a finding at or above this severity is actionable (critical|high|medium|low)")
	cmd.Flags().BoolVar(&failOnKEV, "fail-on-kev", false, "exit 2 when an actionable finding is listed in CISA KEV")
	cmd.Flags().BoolVar(&includeNotAffected, "include-not-affected", false, "include checked-and-not-affected records (false-positive review)")
	cmd.Flags().BoolVar(&noPython, "no-python", false, "skip Python package inventory")
	cmd.Flags().BoolVar(&noNPM, "no-npm", false, "skip npm package inventory")
	cmd.Flags().BoolVar(&noRuby, "no-ruby", false, "skip Ruby gem inventory")
	cmd.Flags().Float64Var(&criticality, "asset-criticality", 0, "asset criticality 0..1, raises risk scores for important hosts")
	cmd.Flags().StringSliceVar(&targets, "target", nil, "authorised network target(s) — requires --scope; not implemented in this build")
	cmd.Flags().StringVar(&scopeFile, "scope", "", "scope file authorising remote assessment")
	cmd.Flags().BoolVar(&authorized, "i-authorize", false, "acknowledge that you are authorised to scan the scope targets")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress the human summary")
	common.register(cmd)
	return cmd
}

func handleRemoteScan(ctx context.Context, scopeFile string, targets []string, authorized bool) error {
	if scopeFile == "" {
		return configError("--target requires --scope <file>: Clanker Guard never scans an address that is not in an approved scope")
	}
	sc, err := scope.Load(scopeFile)
	if err != nil {
		return configError(err.Error())
	}
	if !authorized {
		return configError("remote assessment requires --i-authorize to confirm you are authorised to scan: " + strings.Join(sc.Targets, ", "))
	}
	for _, t := range targets {
		if !scope.Allows(sc, t) {
			return configError(fmt.Sprintf("target %q is outside the authorised scope %q", t, sc.Name))
		}
	}
	_ = ctx
	return configError(fmt.Sprintf(
		"scope %q is valid (%d targets, authorised by %s), but network assessment is not implemented in this build.\n"+
			"Phase 3 (service discovery, fingerprinting, safe validation) is tracked in docs/VULN.md; "+
			"the authorisation gate above is enforced and tested so it cannot be bypassed when that lands.",
		sc.Name, len(sc.Targets), sc.AuthorizedBy))
}

// Exit code contract shared with the standalone agent.
const (
	exitOK          = 0
	exitFindings    = 2
	exitConfigError = 3
	exitIncomplete  = 4
)

func configError(msg string) error {
	guardExitCode = exitConfigError
	return errors.New(msg)
}

func printScanSummary(res scan.Result) {
	rep := res.Report
	fmt.Fprintf(os.Stderr, "clanker-guard %s — %s (%s %s)\n", rep.Metadata.ToolVersion,
		rep.Metadata.Host, rep.Inventory.Asset.OS, rep.Inventory.Asset.OSVersion)
	fmt.Fprintf(os.Stderr, "packages inspected: %d  |  matched: %d  |  advisories: %d (%s)\n",
		rep.Metadata.Coverage.PackagesInspected, rep.Metadata.Coverage.PackagesMatched,
		rep.Metadata.Coverage.AdvisoriesChecked, strings.Join(rep.Metadata.Coverage.Sources, ", "))
	fmt.Fprintf(os.Stderr, "findings: %d actionable of %d  |  critical %d  high %d  medium %d  low %d  |  KEV %d  |  needs investigation %d\n",
		rep.Summary.Actionable, rep.Summary.Total,
		rep.Summary.BySeverity[model.SeverityCritical], rep.Summary.BySeverity[model.SeverityHigh],
		rep.Summary.BySeverity[model.SeverityMedium], rep.Summary.BySeverity[model.SeverityLow],
		rep.Summary.KEVCount, rep.Summary.ByAffected[string(model.ApplicabilityNeedsInvestigation)])
	if len(rep.Findings) > 0 {
		fmt.Fprintln(os.Stderr, "top by risk:")
		for i, f := range rep.Findings {
			if i >= 5 {
				break
			}
			fmt.Fprintf(os.Stderr, "  %s %s → %s (%s, risk %.1f, %s)\n",
				f.Product, f.InstalledVersion, f.VulnerabilityID, f.Severity, f.RiskScore, f.Affected)
		}
	}
	if res.OutputPath != "" {
		fmt.Fprintf(os.Stderr, "report written: %s\n", res.OutputPath)
	}
	if res.Incomplete {
		fmt.Fprintln(os.Stderr, "WARNING: this assessment is incomplete; see metadata.errors and coverage.limitations")
	}
}

func newVulnFeedsCmd() *cobra.Command {
	var (
		common  vulnCommonFlags
		withOSV bool
	)
	feeds := &cobra.Command{
		Use:   "feeds",
		Short: "Manage the local vulnerability intelligence cache",
	}
	update := &cobra.Command{
		Use:   "update",
		Short: "Download CISA KEV and EPSS (and optionally OSV advisories for this host)",
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := context.Background()
			if _, err := scan.UpdateFeeds(ctx, common.path(), withOSV, os.Stderr); err != nil {
				return err
			}
			return nil
		},
	}
	update.Flags().BoolVar(&withOSV, "with-osv", false, "also cache OSV advisories for packages installed on this host (enables offline scans)")
	common.register(update)

	status := &cobra.Command{
		Use:   "status",
		Short: "Show intelligence cache freshness",
		RunE: func(c *cobra.Command, _ []string) error {
			return scan.FeedStatus(context.Background(), common.path(), os.Stdout)
		},
	}
	common.register(status)

	feeds.AddCommand(update, status)
	return feeds
}

func newVulnInventoryCmd() *cobra.Command {
	var (
		common vulnCommonFlags
		format string
	)
	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Collect and print the endpoint software inventory",
		RunE: func(c *cobra.Command, _ []string) error {
			return scan.InventoryOnly(context.Background(), "", format, os.Stdout)
		},
	}
	cmd.Flags().StringVar(&format, "format", "json", "json or markdown")
	common.register(cmd)
	return cmd
}

func newVulnReportCmd() *cobra.Command {
	var (
		common vulnCommonFlags
		format string
		host   string
		out    string
	)
	cmd := &cobra.Command{
		Use:   "report",
		Short: "Re-render the most recent stored assessment",
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := context.Background()
			store, err := intel.OpenStore(common.path())
			if err != nil {
				return err
			}
			defer store.Close()
			_, payload, err := store.LatestRun(ctx, host)
			if err != nil {
				return fmt.Errorf("no stored assessment for %q: %w", host, err)
			}
			var rep model.Report
			if err := json.Unmarshal(payload, &rep); err != nil {
				return err
			}
			if out == "" || out == "-" {
				return scan.RenderStored(ctx, "", &rep, format, os.Stdout)
			}
			f, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
			if err != nil {
				return err
			}
			defer f.Close()
			return scan.RenderStored(ctx, "", &rep, format, f)
		},
	}
	cmd.Flags().StringVar(&format, "format", "markdown", "json, markdown, sarif or html")
	cmd.Flags().StringVar(&host, "host", "", "restrict to a hostname (default: most recent run)")
	cmd.Flags().StringVar(&out, "output", "-", "output path ('-' for stdout)")
	common.register(cmd)
	return cmd
}

func newVulnAskCmd() *cobra.Command {
	var (
		common vulnCommonFlags
		host   string
	)
	cmd := &cobra.Command{
		Use:   "ask \"question\"",
		Short: "Answer questions grounded in the most recent assessment",
		Long: `Answer questions from stored findings only.

Answers are deterministic and cite finding identifiers; no model is consulted and
no data leaves the host. Supported questions include "what should I patch
first?", "which findings are in CISA KEV?", "which packages have vendor fixes?"
and "explain CVE-YYYY-NNNN".`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := context.Background()
			store, err := intel.OpenStore(common.path())
			if err != nil {
				return err
			}
			defer store.Close()
			_, payload, err := store.LatestRun(ctx, host)
			if err != nil {
				return fmt.Errorf("no stored assessment available; run `clanker vuln scan --local` first: %w", err)
			}
			var rep model.Report
			if err := json.Unmarshal(payload, &rep); err != nil {
				return err
			}
			fmt.Fprintln(os.Stdout, scan.Ask(rep, strings.Join(args, " ")))
			return nil
		},
	}
	cmd.Flags().StringVar(&host, "host", "", "restrict to a hostname")
	common.register(cmd)
	return cmd
}

func newVulnScopeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scope",
		Short: "Validate an authorisation scope file",
	}
	validate := &cobra.Command{
		Use:   "validate <file>",
		Short: "Validate a scope file and print the normalised scope",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			sc, err := scope.Load(args[0])
			if err != nil {
				return configError(err.Error())
			}
			out := map[string]any{
				"name":          sc.Name,
				"authorized_by": sc.AuthorizedBy,
				"authorized_at": sc.AuthorizedAt.Format(time.RFC3339),
				"targets":       sc.Targets,
				"ports":         sc.Ports,
				"max_hosts":     sc.MaxHosts,
				"allow_public":  sc.AllowPublic,
				"valid":         true,
			}
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(out)
		},
	}
	cmd.AddCommand(validate)
	return cmd
}

func newVulnAgentCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Endpoint agent installation helpers",
	}
	cmd.AddCommand(&cobra.Command{
		Use:   "install",
		Short: "Print verified installation commands for clanker-guard-agent",
		Run: func(c *cobra.Command, _ []string) {
			fmt.Print(agentInstallHelp())
		},
	})
	return cmd
}

func agentInstallHelp() string {
	return `Endpoint agent installation (artifacts are verified with SHA-256):

  Linux / macOS
    curl -fsSL <release-base>/install-agent.sh | bash -s -- --version <version>

  Windows (PowerShell)
    iwr <release-base>/install-agent.ps1 -UseBasicParsing | iex

  Offline / manual
    1. download clanker-guard-agent_<os>_<arch> and its .sha256 from the release
    2. verify: sha256sum -c clanker-guard-agent_<os>_<arch>.sha256
    3. install to a directory on PATH, then run: clanker-guard-agent scan --local

The agent installs no service and no scheduled task by default. Uninstall:
    clanker-guard-agent uninstall --yes

Note: this build does not publish release artifacts yet; build them with
scripts/build-agent-release.sh and host them under your own release base URL.
`
}

func newVulnServeCmd() *cobra.Command {
	var (
		common      vulnCommonFlags
		listen      string
		webDir      string
		releaseBase string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the Clanker Guard web interface and JSON API",
		Long: `Serve the Clanker Guard web UI and API.

Binds to loopback by default. Binding to any other address requires a token
(CLANKER_GUARD_TOKEN), which the UI sends as the X-Guard-Token header, because
the API can start scans.

The web assets are served from --web-dir (default web/dist). Build them once:

  cd web && npm install && npm run build`,
		RunE: func(c *cobra.Command, _ []string) error {
			if releaseBase == "" {
				releaseBase = os.Getenv("CLANKER_GUARD_RELEASE_BASE")
			}
			srv, err := api.New(api.Options{
				CachePath:   common.path(),
				WebDir:      webDir,
				ToolVersion: Version,
				Token:       os.Getenv("CLANKER_GUARD_TOKEN"),
				ReleaseBase: releaseBase,
			})
			if err != nil {
				return err
			}
			defer srv.Close()
			fmt.Fprintf(os.Stderr, "clanker vuln serve → http://%s\n", listen)
			fmt.Fprintf(os.Stderr, "  cache:   %s\n", common.path())
			fmt.Fprintf(os.Stderr, "  web dir: %s\n", valueOrDash(webDir))
			if os.Getenv("CLANKER_GUARD_TOKEN") != "" {
				fmt.Fprintln(os.Stderr, "  auth:    X-Guard-Token required (CLANKER_GUARD_TOKEN is set)")
			}
			return srv.Listen(listen)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8787", "address to listen on (non-loopback requires CLANKER_GUARD_TOKEN)")
	cmd.Flags().StringVar(&webDir, "web-dir", "web/dist", "directory containing the built web UI")
	cmd.Flags().StringVar(&releaseBase, "release-base", "", "published agent artifact base URL (or CLANKER_GUARD_RELEASE_BASE)")
	common.register(cmd)
	return cmd
}

func valueOrDash(s string) string {
	if s == "" {
		return "(none: API only)"
	}
	return s
}
