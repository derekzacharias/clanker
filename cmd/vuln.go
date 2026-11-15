package cmd

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/bgdnvk/clanker/internal/vuln/api"
	"github.com/bgdnvk/clanker/internal/vuln/auth"
	"github.com/bgdnvk/clanker/internal/vuln/improve"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/inventory"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/sbom"
	"github.com/bgdnvk/clanker/internal/vuln/scan"
	"github.com/bgdnvk/clanker/internal/vuln/scope"
	"github.com/bgdnvk/clanker/internal/vuln/ticketing"
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
		newVulnAuthCmd(),
		newVulnSBOMCmd(),
		newVulnFeedbackCmd(),
		newVulnImproveCmd(),
		newVulnQualityCmd(),
	)
	return vuln
}

// vulnScanOptions carries scan flags between subcommands.
type vulnScanOptions struct {
	offline            bool
	format             string
	output             string
	includeNotAffected bool
	failOn             string
	failOnKEV          bool
	sbomPath           string
	image              string
	ports              []int
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
		sbomPath           string
		imageRef           string
		portList           []int
	)
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Assess the local endpoint (or an explicitly scoped network target)",
		Long: `Assess software against public vulnerability intelligence.

Modes:
  --local              this endpoint's packages (default, unprivileged)
  --scope <file>       explicitly authorised network assessment: TCP discovery,
                       service fingerprinting, TLS inspection, NVD correlation
  --sbom <file>        CycloneDX/SPDX/Syft document or a dependency manifest
  --image <ref>        container image, read via "docker save" (never executed)

Network assessment requires --i-authorize and a scope naming who approved the
targets. Nothing is exploited; validation is limited to observing what each
service returns.`,
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := c.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			// Remote paths are deliberately refused until Phase 3 lands, but the
			// authorisation machinery is exercised so the guard cannot regress.
			scanOpts := vulnScanOptions{
				offline: offline, format: format, output: output,
				includeNotAffected: includeNotAffected, failOn: failOn, failOnKEV: failOnKEV,
				sbomPath: sbomPath, image: imageRef, ports: portList,
			}
			if scopeFile != "" || len(targets) > 0 {
				return runNetworkScan(ctx, common.path(), scopeFile, targets, authorized, scanOpts)
			}
			if sbomPath != "" || imageRef != "" {
				return runSBOMScan(ctx, common.path(), scanOpts)
			}
			if !local {
				return configError("nothing to scan: pass --local, --scope, --sbom or --image")
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
	cmd.Flags().StringSliceVar(&targets, "target", nil, "authorised network target(s); must be inside --scope")
	cmd.Flags().StringVar(&scopeFile, "scope", "", "scope file authorising remote assessment")
	cmd.Flags().BoolVar(&authorized, "i-authorize", false, "acknowledge that you are authorised to scan the scope targets")
	cmd.Flags().StringVar(&sbomPath, "sbom", "", "CycloneDX/SPDX/Syft document or dependency manifest to assess")
	cmd.Flags().StringVar(&imageRef, "image", "", "container image reference to inventory (requires a local Docker daemon)")
	cmd.Flags().IntSliceVar(&portList, "ports", nil, "override the scope's TCP port list")
	cmd.Flags().BoolVar(&quiet, "quiet", false, "suppress the human summary")
	common.register(cmd)
	return cmd
}

// runNetworkScan performs an explicitly authorised network assessment.
func runNetworkScan(ctx context.Context, cachePath, scopeFile string, targets []string, authorized bool, opts vulnScanOptions) error {
	if scopeFile == "" {
		return configError("network assessment requires --scope <file>: Clanker Guard never scans an address that is not in an approved scope")
	}
	sc, err := scope.Load(scopeFile)
	if err != nil {
		return configError(err.Error())
	}
	if !authorized {
		return configError("network assessment requires --i-authorize to confirm you are authorised to scan: " + strings.Join(sc.Targets, ", "))
	}
	if len(targets) > 0 {
		for _, t := range targets {
			if !scope.Allows(sc, t) {
				return configError(fmt.Sprintf("target %q is outside the authorised scope %q", t, sc.Name))
			}
		}
		// Explicit targets may only narrow the scope.
		sc.Targets = targets
	}

	res, err := scan.Run(ctx, scan.Options{
		CachePath:          cachePath,
		Offline:            opts.offline,
		Format:             opts.format,
		OutputPath:         opts.output,
		IncludeNotAffected: opts.includeNotAffected,
		Policy:             model.Policy{FailOnSeverity: opts.failOn, FailOnKEV: opts.failOnKEV},
		ToolVersion:        Version,
		Scope:              &sc,
		TargetPorts:        opts.ports,
	})
	if err != nil {
		return err
	}
	printScanSummary(res)
	guardExitCode = res.ExitCode
	return nil
}

// runSBOMScan correlates a bill of materials or container image.
func runSBOMScan(ctx context.Context, cachePath string, opts vulnScanOptions) error {
	res, err := scan.Run(ctx, scan.Options{
		CachePath:          cachePath,
		Offline:            opts.offline,
		Format:             opts.format,
		OutputPath:         opts.output,
		IncludeNotAffected: opts.includeNotAffected,
		Policy:             model.Policy{FailOnSeverity: opts.failOn, FailOnKEV: opts.failOnKEV},
		ToolVersion:        Version,
		SBOMPath:           opts.sbomPath,
		Image:              opts.image,
	})
	if err != nil {
		return err
	}
	printScanSummary(res)
	guardExitCode = res.ExitCode
	return nil
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
		Use: "status",
		// A rejected credential is a one-line problem, not a flag mistake.
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Show intelligence cache freshness",
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
    iwr <release-base>/install-agent.ps1 -OutFile $env:TEMP\install-agent.ps1 -UseBasicParsing;
    & $env:TEMP\install-agent.ps1 -Version <version>

  Enroll while installing (Settings -> Agents shows the real command)
    ... --server <dashboard-url> --enroll-token <token>
    The endpoint then scans itself once and reports findings and status to that
    server only. --no-scan installs and enrolls without the first assessment.

  Offline / manual
    1. download clanker-guard-agent_<os>_<arch> and its .sha256 from the release
    2. verify: sha256sum -c clanker-guard-agent_<os>_<arch>.sha256
    3. install to a directory on PATH, then run: clanker-guard-agent scan --local

With --server/--enroll-token the installer also installs a background service
(systemd user unit, LaunchAgent or logon task) so the endpoint stays reachable for
dashboard-requested scans; --no-service skips it. Without --server nothing is
uploaded and no service is installed. Uninstall:
    clanker-guard-agent uninstall --yes

Note: this build does not publish release artifacts yet; build them with
scripts/build-agent-release.sh and host them under your own release base URL.
`
}

func newVulnServeCmd() *cobra.Command {
	var (
		common         vulnCommonFlags
		listen         string
		webDir         string
		releaseBase    string
		authFile       string
		gitlabFile     string
		sessionTTL     time.Duration
		trustedProxies string
		agentVersion   string
	)
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Serve the Clanker Guard web interface and JSON API",
		Long: `Serve the Clanker Guard web UI and API.

Binds to loopback by default. Binding to any other address requires a
credential, which the UI sends as the X-Guard-Token header (or, after sign-in,
as a session cookie), because the API can start scans.

Two ways in:

  clanker vuln auth set-password   browser sign-in, stays signed in for --session-ttl
                                   (default 30 days) across server restarts
  CLANKER_GUARD_TOKEN              shared secret for scripts and the agent
                                   (X-Guard-Token header)

Either one satisfies the non-loopback guard; both may be configured at once.
The web assets are served from --web-dir (default web/dist). Build them once:

  cd web && npm install && npm run build`,
		RunE: func(c *cobra.Command, _ []string) error {
			if releaseBase == "" {
				releaseBase = os.Getenv("CLANKER_GUARD_RELEASE_BASE")
			}
			srv, err := api.New(api.Options{
				CachePath:      common.path(),
				WebDir:         webDir,
				ToolVersion:    Version,
				Token:          os.Getenv("CLANKER_GUARD_TOKEN"),
				ReleaseBase:    releaseBase,
				AuthPath:       authFile,
				GitLabPath:     gitlabFile,
				SessionTTL:     sessionTTL,
				TrustedProxies: splitList(trustedProxies),
				AgentVersion:   agentVersion,
			})
			if err != nil {
				return err
			}
			defer srv.Close()
			fmt.Fprintf(os.Stderr, "clanker vuln serve → http://%s\n", listen)
			fmt.Fprintf(os.Stderr, "  cache:   %s\n", common.path())
			fmt.Fprintf(os.Stderr, "  web dir: %s\n", valueOrDash(webDir))
			// Report the real authentication mode instead of a single boolean: a
			// password-protected server and a token-protected one behave differently
			// in the browser.
			if st, err := auth.Load(authFile); err == nil {
				fmt.Fprintf(os.Stderr, "  auth:    password for %q (sessions last %s) — %s\n",
					st.Username(), sessionTTL, st.Path())
				if os.Getenv("CLANKER_GUARD_TOKEN") != "" {
					fmt.Fprintln(os.Stderr, "           X-Guard-Token also accepted")
				}
			} else if os.Getenv("CLANKER_GUARD_TOKEN") != "" {
				fmt.Fprintln(os.Stderr, "  auth:    X-Guard-Token required (CLANKER_GUARD_TOKEN is set)")
				fmt.Fprintf(os.Stderr, "           no dashboard password yet: clanker vuln auth set-password\n")
			}
			// Say which installer host the Agents tab will advertise, so a wrong or
			// missing release base is visible at startup instead of on a 404.
			if releaseBase != "" {
				fmt.Fprintf(os.Stderr, "  agent:   installers from %s\n", releaseBase)
			} else {
				fmt.Fprintln(os.Stderr, "  agent:   no release base configured (Agents tab shows how to publish)")
			}
			return srv.Listen(listen)
		},
	}
	cmd.Flags().StringVar(&listen, "listen", "127.0.0.1:8787", "address to listen on (non-loopback requires CLANKER_GUARD_TOKEN or a password)")
	cmd.Flags().StringVar(&webDir, "web-dir", "web/dist", "directory containing the built web UI")
	cmd.Flags().StringVar(&releaseBase, "release-base", "", "published agent artifact base URL (or CLANKER_GUARD_RELEASE_BASE)")
	cmd.Flags().StringVar(&authFile, "auth-file", auth.DefaultPath(), "password credential file (empty disables password sign-in)")
	cmd.Flags().StringVar(&gitlabFile, "gitlab-config", ticketing.DefaultConfigPath(),
		"GitLab integration file (0600; holds the access token) or CLANKER_GUARD_GITLAB_FILE")
	cmd.Flags().DurationVar(&sessionTTL, "session-ttl", auth.DefaultSessionTTL, "how long a browser sign-in stays valid")
	cmd.Flags().StringVar(&agentVersion, "agent-version", os.Getenv("CLANKER_GUARD_AGENT_VERSION"),
		"agent release version advertised in install commands (default: the tag in --release-base, else this build's version)")
	cmd.Flags().StringVar(&trustedProxies, "trusted-proxies", os.Getenv("CLANKER_GUARD_TRUSTED_PROXIES"),
		"comma-separated proxy IPs/CIDRs whose X-Forwarded-For is trusted (needed behind a TLS-terminating proxy so rate limits and logs see real client addresses)")
	common.register(cmd)
	return cmd
}

// newVulnAuthCmd manages the dashboard password: a one-time browser sign-in
// instead of pasting the API token into every tab.
func newVulnAuthCmd() *cobra.Command {
	var (
		file      string
		username  string
		fromStdin bool
		generate  bool
		length    int
		yes       bool
	)
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage the dashboard sign-in password",
		Long: `Manage the password the Clanker Guard web interface signs in with.

The password is stored as a bcrypt hash in a 0600 file under the user config
directory, separate from the scan cache so clearing the cache never locks you
out. A session cookie (HttpOnly, SameSite=Strict) keeps the browser signed in
for --session-ttl, default 30 days, and survives a server restart.

The X-Guard-Token header keeps working for scripts and the endpoint agent.
Changing the password signs out every existing browser session.`,
	}

	setPassword := &cobra.Command{
		Use: "set-password",
		// A rejected credential is a one-line problem, not a flag mistake.
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Create or change the password used by the web interface",
		Long: `Set the dashboard password.

With no flags the password is prompted for twice without echoing. Use
--generate to have a strong one generated and printed once, or --password-stdin
to read it from a pipe so it never enters shell history:

  clanker vuln auth set-password --generate
  printf '%s' "$PW" | clanker vuln auth set-password --password-stdin`,
		Args: cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			path := authFileOrDefault(file)
			// Keep the account name already in use unless one was given.
			user := strings.TrimSpace(username)
			if user == "" {
				if existing, err := auth.Load(path); err == nil {
					user = existing.Username()
				} else {
					user = "admin"
				}
			}
			password, err := resolvePassword(fromStdin, generate, length)
			if err != nil {
				return configError(err.Error())
			}
			if err := auth.ValidateCredentials(user, password); err != nil {
				return configError(err.Error())
			}
			st, err := auth.Write(path, user, password)
			if err != nil {
				return err
			}
			fmt.Printf("password set for %q\n  file: %s\n", st.Username(), st.Path())
			if generate {
				fmt.Printf("  password: %s\n", password)
				fmt.Fprintln(os.Stderr, "store it in a password manager now — it is not saved in plain text anywhere.")
			}
			fmt.Fprintln(os.Stderr, "restart `clanker vuln serve` to apply it; every existing session is signed out.")
			return nil
		},
	}
	setPassword.Flags().StringVar(&file, "file", "", "credential file (default: user config dir/clanker-guard/auth.json)")
	setPassword.Flags().StringVar(&username, "username", "", "account name (default: keep the existing one, or \"admin\")")
	setPassword.Flags().BoolVar(&fromStdin, "password-stdin", false, "read the password from stdin instead of prompting")
	setPassword.Flags().BoolVar(&generate, "generate", false, "generate a strong password and print it once")
	setPassword.Flags().IntVar(&length, "length", 24, "length of the generated password")

	status := &cobra.Command{
		Use:   "status",
		Short: "Show whether a dashboard password is configured",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			path := authFileOrDefault(file)
			st, err := auth.Load(path)
			if errors.Is(err, auth.ErrNotConfigured) {
				fmt.Printf("no dashboard password configured (%s does not exist)\n", path)
				fmt.Println("the web UI needs CLANKER_GUARD_TOKEN instead; create a password with:")
				fmt.Println("  clanker vuln auth set-password")
				return nil
			}
			if err != nil {
				return err
			}
			fmt.Printf("user:     %s\n", st.Username())
			fmt.Printf("file:     %s\n", st.Path())
			fmt.Printf("updated:  %s\n", st.UpdatedAt().Format(time.RFC3339))
			if mode, insecure := st.InsecurePerms(); insecure {
				fmt.Fprintf(os.Stderr, "warning: %s has mode %s; run: chmod 600 %s\n", st.Path(), mode, st.Path())
			}
			return nil
		},
	}
	status.Flags().StringVar(&file, "file", "", "credential file (default: user config dir/clanker-guard/auth.json)")

	clear := &cobra.Command{
		Use: "clear",
		// A rejected credential is a one-line problem, not a flag mistake.
		SilenceUsage:  true,
		SilenceErrors: true,
		Short:         "Remove the dashboard password (sign-in becomes token-only again)",
		Args:          cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			path := authFileOrDefault(file)
			if !yes {
				if !term.IsTerminal(int(os.Stdin.Fd())) {
					return configError("refusing to delete a credential without confirmation: pass --yes")
				}
				fmt.Fprintf(os.Stderr, "delete %s? [y/N] ", path)
				answer, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil {
					return err
				}
				switch strings.ToLower(strings.TrimSpace(answer)) {
				case "y", "yes":
				default:
					fmt.Fprintln(os.Stderr, "cancelled")
					return nil
				}
			}
			if err := auth.Remove(path); err != nil {
				return err
			}
			fmt.Printf("removed %s\n", path)
			fmt.Fprintln(os.Stderr, "restart `clanker vuln serve`; browsers must use X-Guard-Token again.")
			return nil
		},
	}
	clear.Flags().StringVar(&file, "file", "", "credential file (default: user config dir/clanker-guard/auth.json)")
	clear.Flags().BoolVar(&yes, "yes", false, "delete without prompting")

	cmd.AddCommand(setPassword, status, clear)
	return cmd
}

func authFileOrDefault(file string) string {
	if strings.TrimSpace(file) != "" {
		return file
	}
	return auth.DefaultPath()
}

// resolvePassword implements the three ways to supply a password, in the order
// that avoids leaking it: generated, piped, or prompted without echo.
func resolvePassword(fromStdin, generate bool, length int) (string, error) {
	switch {
	case generate:
		return randomPassword(length)
	case fromStdin:
		raw, err := io.ReadAll(io.LimitReader(os.Stdin, auth.MaxPasswordBytes*4))
		if err != nil {
			return "", fmt.Errorf("read password from stdin: %w", err)
		}
		// Only the trailing newline is stripped: spaces are legitimate
		// characters in a password.
		return strings.TrimRight(string(raw), "\r\n"), nil
	default:
		return promptPasswordTwice()
	}
}

func promptPasswordTwice() (string, error) {
	// One reader for both prompts: a piped "pw\npw\n" can arrive in a single
	// buffer, and a second reader would lose the second line.
	reader := bufio.NewReader(os.Stdin)
	first, err := promptPassword(reader, "New password: ")
	if err != nil {
		return "", err
	}
	if first == "" {
		return "", errors.New("password must not be empty")
	}
	second, err := promptPassword(reader, "Repeat password: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errors.New("passwords do not match")
	}
	return first, nil
}

// promptPassword reads a secret without echoing it when stdin is a terminal.
func promptPassword(reader *bufio.Reader, label string) (string, error) {
	fmt.Fprint(os.Stderr, label)
	if term.IsTerminal(int(os.Stdin.Fd())) {
		secret, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		return string(secret), nil
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("read password: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// passwordAlphabet omits look-alike characters (l/I/1, O/0) so a generated
// password survives being typed from a printed note.
const passwordAlphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

func randomPassword(length int) (string, error) {
	if length <= 0 {
		length = 24
	}
	if length < auth.MinPasswordLength {
		length = auth.MinPasswordLength
	}
	if length > auth.MaxPasswordBytes {
		length = auth.MaxPasswordBytes
	}
	max := big.NewInt(int64(len(passwordAlphabet)))
	out := make([]byte, length)
	for i := range out {
		// crypto/rand.Int avoids the modulo bias that taking a byte % len would
		// introduce, which would make some positions more likely.
		n, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", fmt.Errorf("generate password: %w", err)
		}
		out[i] = passwordAlphabet[n.Int64()]
	}
	return string(out), nil
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

// ------------------------------------------------------------------- sbom ----

func newVulnSBOMCmd() *cobra.Command {
	var common vulnCommonFlags
	cmd := &cobra.Command{
		Use:   "sbom",
		Short: "Produce and inspect software bills of materials",
	}
	var (
		output   string
		sbomPath string
		image    string
	)
	export := &cobra.Command{
		Use:   "export",
		Short: "Export a CycloneDX SBOM (1.5) from this endpoint, a document or an image",
		Long: `Write a CycloneDX 1.5 document describing the assessed software.

By default the local endpoint inventory is exported. --sbom re-exports a document
that is already in a supported format; --image inventories a container image.`,
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := context.Background()
			inv := model.Inventory{}
			warnings := []string{}
			switch {
			case sbomPath != "":
				doc, err := sbom.ParseFile(sbomPath)
				if err != nil {
					return configError(err.Error())
				}
				inv.Asset = model.Asset{Hostname: "sbom:" + filepath.Base(sbomPath), OS: string(doc.Format)}
				inv.Packages = doc.Packages
				warnings = append(warnings, doc.Warnings...)
			case image != "":
				res, err := sbom.ScanImage(ctx, image, sbom.ImageOptions{})
				if err != nil {
					return configError(err.Error())
				}
				inv.Asset = model.Asset{Hostname: "image:" + image, OS: firstNonEmptyValue(res.OS, "container image")}
				inv.Packages = res.Packages
				warnings = append(warnings, res.Warnings...)
			default:
				collected, err := (&inventory.Runner{Collectors: inventory.DefaultCollectors()}).Run(ctx, inventory.DefaultOptions())
				if err != nil {
					return err
				}
				inv = collected
			}
			if len(inv.Packages) == 0 {
				return configError("no packages found; refusing to write an empty bill of materials")
			}
			payload, err := sbom.ExportCycloneDX(inv.Packages, inv.Asset, Version, time.Now().UTC())
			if err != nil {
				return err
			}
			if output == "" || output == "-" {
				_, err = os.Stdout.Write(payload)
				return err
			}
			if err := os.WriteFile(output, payload, 0o600); err != nil {
				return err
			}
			for _, w := range warnings {
				fmt.Fprintln(os.Stderr, "warning:", w)
			}
			fmt.Fprintf(os.Stderr, "wrote %d components to %s\n", len(inv.Packages), output)
			return nil
		},
	}
	export.Flags().StringVar(&output, "output", "-", "output path ('-' for stdout)")
	export.Flags().StringVar(&sbomPath, "sbom", "", "re-export an existing supported document")
	export.Flags().StringVar(&image, "image", "", "inventory a container image")
	common.register(export)
	cmd.AddCommand(export)
	return cmd
}

func firstNonEmptyValue(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// splitList turns a comma-separated flag value into a slice, dropping empties.
func splitList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
