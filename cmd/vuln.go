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
	"github.com/bgdnvk/clanker/internal/vuln/improve"
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
		newVulnFeedbackCmd(),
		newVulnImproveCmd(),
		newVulnQualityCmd(),
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

// ---------------------------------------------------------------- feedback ---

func newVulnFeedbackCmd() *cobra.Command {
	var (
		common  vulnCommonFlags
		verdict string
		reason  string
		note    string
		analyst string
	)
	cmd := &cobra.Command{
		Use:   "feedback <finding-id>",
		Short: "Record an analyst review for a finding",
		Long: `Record an analyst review. A false-positive claim is verified against cached
advisory data before it changes anything; when no evidence can decide it, the
scanner classification is kept and the gap is recorded for the improvement loop.

Finding ids are the stable ids shown in reports and the web interface.`,
		Args: cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			ctx := context.Background()
			store, err := intel.OpenStore(common.path())
			if err != nil {
				return err
			}
			defer store.Close()
			eng, err := improve.New(store)
			if err != nil {
				return err
			}
			ref, err := findFindingRef(ctx, store, args[0])
			if err != nil {
				return err
			}
			fb, err := eng.ApplyFeedback(ctx, improve.Feedback{
				Finding:    ref,
				Verdict:    improve.Verdict(verdict),
				ReasonCode: improve.ReasonCode(reason),
				ReasonText: note,
				Analyst:    firstNonEmpty(analyst, os.Getenv("USER"), "cli"),
			})
			if err != nil {
				return configError(err.Error())
			}
			fmt.Fprintf(os.Stderr, "recorded %s for %s (%s)\n", fb.Verdict, ref.Product, ref.CVE)
			if fb.Verification != nil {
				status := "inconclusive"
				if fb.Verification.Supported {
					status = "supported"
				} else if fb.Verification.Confidence == "high" {
					status = "contradicted"
				}
				fmt.Fprintf(os.Stderr, "verification: %s (confidence %s)\n", status, fb.Verification.Confidence)
				fmt.Fprintf(os.Stderr, "  %s\n", fb.Verification.Explanation)
				if fb.Verification.Changed {
					fmt.Fprintf(os.Stderr, "classification: %s → %s\n", fb.Verification.Original, fb.Verification.Reassessed)
				} else if fb.Verification.Supported {
					fmt.Fprintf(os.Stderr, "classification unchanged (%s)\n", fb.Verification.Original)
				}
			}
			if improvements, err := eng.Analyze(ctx); err == nil && len(improvements) > 0 {
				for _, imp := range improvements {
					for _, fid := range imp.AffectedFindings {
						if fid == ref.ID {
							fmt.Fprintf(os.Stderr, "improvement %s: %s [%s]\n", imp.ID, imp.Title, imp.Status)
						}
					}
				}
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&verdict, "verdict", "false_positive", "confirmed | false_positive | needs_investigation | remediated | request_verification")
	cmd.Flags().StringVar(&reason, "reason", "", "vendor_patch_installed | incorrect_identification | feature_not_enabled | advisory_not_applicable | other")
	cmd.Flags().StringVar(&note, "note", "", "free-text note (stored as data)")
	cmd.Flags().StringVar(&analyst, "analyst", "", "analyst name recorded in the audit trail")
	common.register(cmd)
	return cmd
}

// findFindingRef resolves a stable finding id against the stored reports.
func findFindingRef(ctx context.Context, store *intel.Store, id string) (improve.FindingRef, error) {
	hosts, err := store.LatestRunsPerHost(ctx)
	if err != nil {
		return improve.FindingRef{}, err
	}
	for _, run := range hosts {
		payload, err := store.ReportByID(ctx, run.ID)
		if err != nil {
			continue
		}
		var rep model.Report
		if err := json.Unmarshal(payload, &rep); err != nil {
			continue
		}
		for _, f := range rep.Findings {
			stable := f.StableID
			if stable == "" {
				stable = model.FindingStableID(rep.Metadata.Host, f)
			}
			if stable != id {
				continue
			}
			return improve.FindingRef{
				ID: stable, ReportID: rep.ReportID, Host: rep.Metadata.Host, CVE: f.VulnerabilityID,
				AdvisoryID: f.AdvisoryID, Product: f.Product, Version: f.InstalledVersion,
				Ecosystem: f.Ecosystem, Severity: f.Severity,
				Applicability: string(f.Affected), Confidence: string(f.Confidence),
				Explanation: f.Explanation,
			}, nil
		}
	}
	return improve.FindingRef{}, configError("finding " + id + " not found in stored reports; run `clanker vuln scan --local` first")
}

// ------------------------------------------------------------- improvements ---

func newVulnImproveCmd() *cobra.Command {
	var common vulnCommonFlags
	cmd := &cobra.Command{
		Use:   "improve",
		Short: "Review, test, approve and deploy detection improvements",
		Long: `The improvement loop is deterministic and versioned.

Reviewed findings generate proposals; a proposal carries a detection-policy
change and a fixture suite. Tests run against the shipped baseline, approval is
an explicit human action, deployment activates a numbered rule, and rollback
restores the previous rule. Nothing is deployed automatically.`,
	}
	cmd.PersistentFlags().StringVar(&common.cache, "cache", "", "intelligence cache path")

	list := &cobra.Command{
		Use:   "list",
		Short: "List improvement proposals",
		RunE: func(c *cobra.Command, _ []string) error {
			eng, store, err := openImprove(common.path())
			if err != nil {
				return err
			}
			defer store.Close()
			items, err := eng.ListImprovements(context.Background(), 100)
			if err != nil {
				return err
			}
			if len(items) == 0 {
				fmt.Println("no improvement proposals yet — record feedback with `clanker vuln feedback`")
				return nil
			}
			fmt.Printf("%-12s %-18s %-10s %-14s %s\n", "ID", "STATUS", "TESTS", "CATEGORY", "TITLE")
			for _, imp := range items {
				tests := "—"
				if imp.Evaluation != nil {
					tests = "failed"
					if imp.Evaluation.Passed {
						tests = "passed"
					}
				}
				fmt.Printf("%-12s %-18s %-10s %-14s %s\n", imp.ID, imp.Status, tests, imp.Category, imp.Title)
			}
			return nil
		},
	}

	show := &cobra.Command{
		Use:   "show <id>",
		Short: "Show a proposal, its fixtures and its audit trail",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			eng, store, err := openImprove(common.path())
			if err != nil {
				return err
			}
			defer store.Close()
			ctx := context.Background()
			imp, err := eng.GetImprovement(ctx, args[0])
			if err != nil || imp == nil {
				return configError("improvement not found: " + args[0])
			}
			fmt.Printf("%s [%s] %s\n", imp.ID, imp.Status, imp.Title)
			fmt.Printf("category: %s · risk: %s · affected findings: %d\n\n", imp.Category, imp.RiskLevel, len(imp.AffectedFindings))
			fmt.Printf("problem:\n  %s\n\n", imp.Problem)
			fmt.Printf("proposed change:\n  %s\n\n", imp.ProposedChange)
			fmt.Printf("expected benefit:\n  %s\n\n", imp.ExpectedBenefit)
			if imp.Policy != nil {
				fmt.Printf("detection policy change: %s\n\n", strings.Join(imp.PolicyNotes, ", "))
			}
			if imp.Evaluation != nil {
				fmt.Printf("tests: %s (%d fixtures, %d corrected, %d regressions)\n",
					map[bool]string{true: "passed", false: "failed"}[imp.Evaluation.Passed],
					len(imp.Evaluation.Cases), len(imp.Evaluation.Fixed), len(imp.Evaluation.Regressions))
				for _, c := range imp.Evaluation.Cases {
					mark := "pass"
					if !c.Pass {
						mark = "FAIL"
					}
					fmt.Printf("  %-4s %-32s expected %-22s baseline %-22s candidate %s\n",
						mark, c.Fixture, c.Expected, c.Baseline, c.Candidate)
				}
				fmt.Println()
			}
			events, _ := eng.Events(ctx, imp.ID)
			fmt.Println("history:")
			for _, ev := range events {
				fmt.Printf("  %s  %s → %s  (%s)  %s\n", ev.CreatedAt.Format("2006-01-02 15:04"),
					ev.From, ev.To, ev.Actor, ev.Note)
			}
			return nil
		},
	}

	analyze := &cobra.Command{
		Use:   "analyze",
		Short: "Regenerate proposals from recorded reviews",
		RunE: func(c *cobra.Command, _ []string) error {
			eng, store, err := openImprove(common.path())
			if err != nil {
				return err
			}
			defer store.Close()
			items, err := eng.Analyze(context.Background())
			if err != nil {
				return err
			}
			for _, imp := range items {
				fmt.Printf("%s [%s] %s\n", imp.ID, imp.Status, imp.Title)
			}
			if len(items) == 0 {
				fmt.Println("no verified reviews to derive proposals from")
			}
			return nil
		},
	}

	evaluate := &cobra.Command{
		Use:   "evaluate <id>",
		Short: "Run the fixture suite for a proposal",
		Args:  cobra.ExactArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			eng, store, err := openImprove(common.path())
			if err != nil {
				return err
			}
			defer store.Close()
			imp, err := eng.EvaluateImprovement(context.Background(), args[0])
			if err != nil {
				return configError(err.Error())
			}
			fmt.Printf("%s → %s\n", imp.ID, imp.Status)
			if imp.Evaluation != nil {
				fmt.Printf("%s: %d fixtures, %d corrected, %d regressions\n",
					map[bool]string{true: "passed", false: "failed"}[imp.Evaluation.Passed],
					len(imp.Evaluation.Cases), len(imp.Evaluation.Fixed), len(imp.Evaluation.Regressions))
			}
			return nil
		},
	}

	transition := func(name, to, short string, requireNote bool) *cobra.Command {
		var actor, note string
		cmd := &cobra.Command{
			Use:   name + " <id>",
			Short: short,
			Args:  cobra.ExactArgs(1),
			RunE: func(c *cobra.Command, args []string) error {
				eng, store, err := openImprove(common.path())
				if err != nil {
					return err
				}
				defer store.Close()
				imp, err := eng.Transition(context.Background(), args[0], improve.Status(to),
					firstNonEmpty(actor, os.Getenv("USER"), "cli"), note)
				if err != nil {
					return configError(err.Error())
				}
				fmt.Printf("%s → %s\n", imp.ID, imp.Status)
				if imp.RuleID != "" && to == "deployed" {
					fmt.Printf("active rule: %s\n", imp.RuleID)
				}
				return nil
			},
		}
		cmd.Flags().StringVar(&actor, "actor", "", "who is performing this action (recorded)")
		cmd.Flags().StringVar(&note, "note", "", "note recorded in the audit trail")
		if requireNote {
			_ = cmd.MarkFlagRequired("note")
		}
		return cmd
	}

	cmd.AddCommand(
		list,
		show,
		analyze,
		evaluate,
		transition("approve", "approved", "Approve a tested proposal (human decision)", false),
		transition("deploy", "deployed", "Deploy an approved proposal as a versioned rule", false),
		transition("rollback", "rolled_back", "Roll back a deployed proposal to the previous rule", false),
		transition("reject", "rejected", "Reject a proposal with a reason", true),
	)
	return cmd
}

func openImprove(cachePath string) (*improve.Engine, *intel.Store, error) {
	if cachePath == "" {
		cachePath = scan.DefaultCachePath()
	}
	store, err := intel.OpenStore(cachePath)
	if err != nil {
		return nil, nil, err
	}
	eng, err := improve.New(store)
	if err != nil {
		store.Close()
		return nil, nil, err
	}
	return eng, store, nil
}

func newVulnQualityCmd() *cobra.Command {
	var common vulnCommonFlags
	cmd := &cobra.Command{
		Use:   "quality",
		Short: "Show detection-quality metrics from reviewed findings",
		RunE: func(c *cobra.Command, _ []string) error {
			eng, store, err := openImprove(common.path())
			if err != nil {
				return err
			}
			defer store.Close()
			q, err := eng.Quality(context.Background(), improve.FindingStats{})
			if err != nil {
				return err
			}
			fmt.Printf("reviewed findings:        %d\n", q.Reviewed)
			fmt.Printf("  confirmed:              %d\n", q.Confirmed)
			fmt.Printf("  false positive:         %d\n", q.FalsePositives)
			fmt.Printf("  needs investigation:    %d\n", q.NeedsInvestigation)
			fmt.Printf("  remediated:             %d\n", q.Remediated)
			fmt.Printf("verification supported:   %d\n", q.VerificationSupported)
			fmt.Printf("verification contradicted:%d\n", q.VerificationContradicted)
			fmt.Printf("verification inconclusive:%d\n", q.VerificationInconclusive)
			if q.FalsePositiveRate != nil {
				fmt.Printf("false-positive rate:      %.0f%% of reviewed findings\n", *q.FalsePositiveRate*100)
			} else {
				fmt.Println("false-positive rate:      not available (no reviews)")
			}
			fmt.Printf("improvements:             %d open, %d deployed, %d rejected\n",
				q.OpenImprovements, q.DeployedImprovements, q.RejectedImprovements)
			for _, n := range q.Notes {
				fmt.Println("note:", n)
			}
			return nil
		},
	}
	common.register(cmd)
	return cmd
}
