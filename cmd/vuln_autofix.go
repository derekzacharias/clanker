package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/bgdnvk/clanker/internal/vuln/autofix"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/remediate"
	"github.com/bgdnvk/clanker/internal/vuln/ticketing"
)

// newVulnAutofixCmd is the automated remediation loop: triage, deterministic upgrades,
// applicability investigation, guarded patches and verification.
//
// It writes nothing unless --apply is given. The default is a dry run because the first
// thing an operator should see is the decision the tool would have made, not the
// consequence of it having made one.
func newVulnAutofixCmd() *cobra.Command {
	var (
		common         vulnCommonFlags
		phase          string
		reportPath     string
		host           string
		projectID      int
		gitlabConfig   string
		targetBranch   string
		apply          bool
		limit          int
		applyVerdicts  bool
		acceptedBy     string
		allowPaths     []string
		contextFiles   []string
		labels         []string
		modelName      string
		modelEndpoint  string
		modelKeyEnv    string
		asJSON         bool
		dryRunExplicit bool
		maxPatchBytes  int
	)

	cmd := &cobra.Command{
		Use:   "autofix",
		Short: "Remediate findings: triage, upgrade, investigate, patch, verify",
		Long: `Run the automated remediation loop against the most recent assessment.

Phases, each useful on its own:

  triage       comment a verdict on findings that have no published fix (P1)
  upgrade      open a draft MR that moves a dependency to its fixed version (P2)
  investigate  produce an applicability verdict for ambiguous findings (P3)
  patch        propose a guarded file-level fix as a draft MR (P4)
  verify       resolve work items absent from a later assessment (P5)
  all          every phase, in that order

Nothing is written without --apply. The first run should always be a dry run: it prints
the decisions (and, with --json, the exact payloads) without touching GitLab or the
workflow store.

What this never does, by design:
  - it never picks a version; the version comes from the advisory's fixed_version
  - it never merges, force-pushes or closes a ticket
  - it never edits CI configuration, credentials or keys
  - it never resolves a finding; only a later assessment that stops reporting it does

The model is optional. Without it, triage posts the facts and the upgrade phase still
works, because "move this package to the fixed version" is not a question for a model.`,
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error {
			ctx := context.Background()

			parsedPhase, err := autofix.ParsePhase(phase)
			if err != nil {
				return err
			}

			store, err := intel.OpenStore(common.path())
			if err != nil {
				return err
			}
			defer store.Close()

			rep, err := loadAutofixReport(ctx, store, reportPath, host)
			if err != nil {
				return err
			}
			if len(rep.Findings) == 0 {
				return fmt.Errorf("the assessment %q contains no findings; nothing to do", rep.ReportID)
			}

			settings, err := ticketing.Load(resolveGitlabConfigPath(gitlabConfig))
			if err != nil {
				return fmt.Errorf("read GitLab settings: %w", err)
			}
			if projectID > 0 {
				settings.ProjectID = projectID
			}

			var tracker autofix.Tracker
			if settings.URL != "" && settings.Token != "" {
				client, err := ticketing.NewClient(settings.ClientConfig(), nil)
				if err != nil {
					return fmt.Errorf("GitLab client: %w", err)
				}
				tracker = client
			}

			var workflow autofix.Workflow
			if remStore, err := remediate.New(store.DB()); err == nil {
				workflow = remStore
			}

			var llm autofix.LLM
			if strings.TrimSpace(modelName) != "" && strings.TrimSpace(modelEndpoint) != "" {
				key := ""
				if modelKeyEnv != "" {
					key = os.Getenv(modelKeyEnv)
				}
				client, err := autofix.NewOpenAICompatible(modelEndpoint, key, modelName)
				if err != nil {
					return err
				}
				llm = client
			} else if strings.TrimSpace(modelName) != "" || strings.TrimSpace(modelEndpoint) != "" {
				return fmt.Errorf("--model and --model-endpoint must be given together")
			}

			dryRun := !apply
			if dryRunExplicit {
				dryRun = true
			}

			cfg := autofix.Config{
				Phase:         parsedPhase,
				ProjectID:     settings.ProjectID,
				TargetBranch:  targetBranch,
				DryRun:        dryRun,
				Limit:         limit,
				AllowPaths:    allowPaths,
				MaxPatchBytes: maxPatchBytes,
				ApplyVerdicts: applyVerdicts,
				AcceptedBy:    acceptedBy,
				ContextFiles:  contextFiles,
				Labels:        labels,
				LLM:           llm,
			}

			runner := autofix.New(cfg, tracker, workflow)
			results, runErr := runner.Run(ctx, rep)

			if err := printAutofixResults(results, asJSON, dryRun); err != nil {
				return err
			}
			if runErr != nil {
				return runErr
			}
			if len(results) == 0 {
				fmt.Fprintf(os.Stderr, "no findings matched phase %q\n", parsedPhase)
			}
			if dryRun && len(results) > 0 {
				fmt.Fprintln(os.Stderr, "\ndry run: nothing was written. Re-run with --apply to write.")
			}
			return nil
		},
	}

	common.register(cmd)
	cmd.Flags().StringVar(&phase, "phase", string(autofix.PhaseTriage), "triage | upgrade | investigate | patch | verify | all")
	cmd.Flags().StringVar(&reportPath, "report", "", "assessment JSON to use (default: most recent stored run)")
	cmd.Flags().StringVar(&host, "host", "", "restrict the stored assessment to one hostname")
	cmd.Flags().IntVar(&projectID, "project", 0, "GitLab project id (overrides the configured default)")
	cmd.Flags().StringVar(&gitlabConfig, "gitlab-config", "", "path to the GitLab credential file")
	cmd.Flags().StringVar(&targetBranch, "target-branch", "main", "branch that fix branches are cut from")
	cmd.Flags().BoolVar(&apply, "apply", false, "write to GitLab and the workflow store (default: dry run)")
	cmd.Flags().BoolVar(&dryRunExplicit, "dry-run", false, "force a dry run even if --apply is given")
	cmd.Flags().IntVar(&limit, "limit", 0, "maximum findings to handle in this run (0 = all)")
	cmd.Flags().BoolVar(&applyVerdicts, "apply-verdicts", false, "let triage verdicts change workflow state")
	cmd.Flags().StringVar(&acceptedBy, "accepted-by", "", "who to record on an automated risk acceptance")
	cmd.Flags().StringSliceVar(&allowPaths, "allow-path", nil, "override the writable file allow-list")
	cmd.Flags().StringSliceVar(&contextFiles, "context-file", nil, "repository file offered to the model as context")
	cmd.Flags().StringSliceVar(&labels, "label", nil, "extra labels for opened merge requests")
	cmd.Flags().StringVar(&modelName, "model", "", "model name for triage/patch phases")
	cmd.Flags().StringVar(&modelEndpoint, "model-endpoint", "", "OpenAI-compatible endpoint, e.g. http://127.0.0.1:8080/v1")
	cmd.Flags().StringVar(&modelKeyEnv, "model-key-env", "CLANKER_AUTOFIX_API_KEY", "environment variable holding the model API key")
	cmd.Flags().IntVar(&maxPatchBytes, "max-patch-bytes", 0, "maximum size of one generated file (default 200 KiB)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit results as JSON")

	return cmd
}

// resolveGitlabConfigPath mirrors the integration's own default so the CLI and the API
// read the same credential file.
func resolveGitlabConfigPath(explicit string) string {
	if strings.TrimSpace(explicit) != "" {
		return explicit
	}
	return ticketing.DefaultConfigPath()
}

// loadAutofixReport prefers an explicit file, then the newest stored assessment.
func loadAutofixReport(ctx context.Context, store *intel.Store, path, host string) (model.Report, error) {
	if strings.TrimSpace(path) != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return model.Report{}, fmt.Errorf("read assessment: %w", err)
		}
		var rep model.Report
		if err := json.Unmarshal(raw, &rep); err != nil {
			return model.Report{}, fmt.Errorf("decode assessment %s: %w", path, err)
		}
		return rep, nil
	}
	_, payload, err := store.LatestRun(ctx, host)
	if err != nil {
		return model.Report{}, fmt.Errorf("no stored assessment; run `clanker vuln scan --local` or pass --report: %w", err)
	}
	var rep model.Report
	if err := json.Unmarshal(payload, &rep); err != nil {
		return model.Report{}, fmt.Errorf("decode stored assessment: %w", err)
	}
	return rep, nil
}

// printAutofixResults writes the audit line for every decision.
func printAutofixResults(results []autofix.Result, asJSON, dryRun bool) error {
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(struct {
			DryRun  bool             `json:"dry_run"`
			Results []autofix.Result `json:"results"`
		}{DryRun: dryRun, Results: results})
	}
	if len(results) == 0 {
		return nil
	}
	for _, r := range results {
		line := fmt.Sprintf("%-11s %-22s %-12s %s", r.Phase, r.FindingID, r.Action, r.Detail)
		if r.Rejected != "" {
			line = fmt.Sprintf("%-11s %-22s %-12s %s", r.Phase, r.FindingID, "rejected", r.Rejected)
		}
		fmt.Println(strings.TrimRight(line, " "))
		if r.MRURL != "" {
			fmt.Println(strings.Repeat(" ", 12) + "→ " + r.MRURL)
		}
		if r.NoteURL != "" {
			fmt.Println(strings.Repeat(" ", 12) + "→ " + r.NoteURL)
		}
	}
	return nil
}
