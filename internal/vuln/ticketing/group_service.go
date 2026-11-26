package ticketing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// CreateGroup files (or updates) the single ticket for one remediation action.
//
// Three behaviours, all idempotent:
//   - no ticket yet            → create the issue and record the action's digest;
//   - ticket exists, same CVEs → reuse it, say so, touch nothing;
//   - ticket exists, new CVEs  → rewrite the issue (title/description) and store the new digest.
//
// The third case is the reason this is not just "create": one cumulative update is installed
// once, and later assessments will keep discovering more CVEs it closes. Rewriting one issue is
// the truthful representation; opening a second is noise.
func (c *Creator) CreateGroup(ctx context.Context, g Group) (CreateResult, error) {
	if c.Store == nil || c.Client == nil {
		return CreateResult{}, ErrNotConfigured
	}
	if strings.TrimSpace(g.Asset) == "" || strings.TrimSpace(g.Fixed) == "" {
		return CreateResult{}, errors.New("a group ticket needs an asset and a fixed version or KB")
	}
	if len(g.Findings) == 0 {
		return CreateResult{}, errors.New("a group ticket needs at least one finding to close")
	}
	key := GroupKey(g.Asset, g.Product, g.Fixed)
	title := GroupTitle(g)
	body := RenderGroup(g)
	labels := groupLabels(g)
	digest := GroupDigest(g)

	unlock := c.lockFor(fmt.Sprintf("%s/%d", key, c.ProjectID))
	defer unlock()

	reserved, fresh, err := c.Store.Reserve(ctx, Ticket{
		FindingKey: key, Asset: g.Asset,
		VulnerabilityID: firstNonEmpty(g.Action, g.Fixed),
		ProjectID:       c.ProjectID, ProjectPath: c.ProjectPath,
		Title: title, Labels: labelString(labels),
		Assignee: c.AssigneeName, CreatedBy: c.CreatedBy,
		RemediationStatus: string(StatusVerified),
	})
	if err != nil {
		return CreateResult{}, err
	}
	if !fresh && reserved.IssueIID > 0 {
		stored, err := c.Store.ContentDigest(ctx, reserved.ID)
		if err != nil {
			return CreateResult{}, err
		}
		if stored == digest {
			return CreateResult{Ticket: reserved, Reused: true,
				Message: fmt.Sprintf("Issue #%d already covers this action", reserved.IssueIID)}, nil
		}
		// The action is already ticketed but now closes more: update the issue in place.
		issue, err := c.Client.UpdateIssue(ctx, reserved.ProjectID, reserved.IssueIID, IssueInput{
			Title: title, Description: body, Labels: labelString(labels),
		})
		if err != nil {
			return CreateResult{}, err
		}
		if err := c.Store.SetContentDigest(ctx, reserved.ID, digest); err != nil {
			c.logf("could not record ticket digest", "ticket", reserved.ID, "err", err)
		}
		updated, err := c.Store.Complete(ctx, reserved.ID, issue, c.ProjectPath, c.AssigneeName)
		if err != nil {
			return CreateResult{}, err
		}
		if c.Log != nil {
			c.Log.Info("gitlab issue updated with newly covered CVEs", "ticket", updated.ID,
				"issue_iid", updated.IssueIID, "cves", len(g.Findings))
		}
		return CreateResult{Ticket: updated, Created: false, Reused: true,
			Message: fmt.Sprintf("Updated issue #%d: %d CVEs", updated.IssueIID, len(g.Findings))}, nil
	}
	if !fresh && reserved.IssueIID == 0 {
		// A previous attempt left an ambiguous reservation for this action; adopt it rather than
		// creating a second issue.
		reserved.Note = "resumed after an earlier attempt that did not confirm"
	}

	issue, err := c.Client.CreateIssue(ctx, c.ProjectID, IssueInput{
		Title: title, Description: body, Labels: labelString(labels),
	})
	if err != nil {
		c.handleCreateError(ctx, reserved, err)
		return CreateResult{}, err
	}
	if issue.IID == 0 || issue.WebURL == "" {
		c.note(ctx, reserved.ID, "GitLab accepted the request but returned no issue reference")
		return CreateResult{}, errors.New("GitLab did not return an issue reference")
	}
	ticket, err := c.Store.Complete(ctx, reserved.ID, issue, c.ProjectPath, c.AssigneeName)
	if err != nil {
		return CreateResult{}, fmt.Errorf("issue %s was created but could not be recorded: %w", issue.WebURL, err)
	}
	if err := c.Store.SetContentDigest(ctx, reserved.ID, digest); err != nil {
		c.logf("could not record ticket digest", "ticket", reserved.ID, "err", err)
	}
	if c.Log != nil {
		c.Log.Info("gitlab group ticket created", "issue_iid", ticket.IssueIID, "asset", g.Asset,
			"action", firstNonEmpty(g.Action, g.Fixed), "cves", len(g.Findings))
	}
	return CreateResult{Ticket: ticket, Created: true,
		Message: fmt.Sprintf("Created issue #%d for %s (%d CVEs)", ticket.IssueIID, firstNonEmpty(g.Action, g.Fixed), len(g.Findings))}, nil
}

// groupLabels derives labels from the worst severity and KEV content.
func groupLabels(g Group) []string {
	out := []string{"security"}
	sev := groupSeverity(g)
	if sev.Label != "" {
		out = append(out, strings.ToLower(sev.Label))
	}
	if kevCount(g) > 0 {
		out = append(out, "cisa-kev")
	}
	if g.Kind == "windows_update" {
		out = append(out, "windows-update")
	}
	return out
}

// labelString joins labels without import cycles from the render file.
func labelString(labels []string) string { return strings.Join(labels, ",") }

var _ = slog.Default
