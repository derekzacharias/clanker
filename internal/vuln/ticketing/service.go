package ticketing

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// Creator is the one place that turns a finding into a GitLab issue.
//
// It exists so the handler has no branching about duplicates, recoveries or partial
// failures, and so that behaviour is testable against a fake GitLab without HTTP.
type Creator struct {
	Store       *Store
	Client      *Client
	ProjectID   int
	ProjectPath string
	// Labels are the operator's configured defaults; severity labels are derived.
	Labels    []string
	CreatedBy string
	// AssigneeID is a resolved GitLab user id (0 = nobody). The username is kept for the
	// record, because ids are meaningless to a human reading the ticket row.
	AssigneeID   int
	AssigneeName string
	// RemediationStatus is the plan's verdict at filing time, stored for traceability.
	RemediationStatus string
	Log               *slog.Logger

	// inflight serialises creations for the same (finding, project) inside this process.
	// The unique index in the store stops two rows; this stops two issues. A deployment
	// with several server replicas would need a shared lock instead.
	mu       sync.Mutex
	inflight map[string]*sync.Mutex
}

// lockFor takes the per-finding lock and returns its release function.
func (c *Creator) lockFor(key string) func() {
	c.mu.Lock()
	if c.inflight == nil {
		c.inflight = map[string]*sync.Mutex{}
	}
	m, ok := c.inflight[key]
	if !ok {
		m = &sync.Mutex{}
		c.inflight[key] = m
	}
	c.mu.Unlock()
	m.Lock()
	return func() {
		m.Unlock()
		c.mu.Lock()
		if cur, ok := c.inflight[key]; ok && cur == m {
			delete(c.inflight, key)
		}
		c.mu.Unlock()
	}
}

// CreateResult reports what happened, including whether an existing ticket was reused.
type CreateResult struct {
	Ticket Ticket `json:"ticket"`
	// Reused means GitLab was not asked to create anything: either the ticket was
	// already tracked, or a retry found the issue a previous attempt had created.
	Reused  bool   `json:"reused"`
	Created bool   `json:"created"`
	Message string `json:"message"`
}

// Create opens an issue for the finding, or returns the one that already exists.
//
// The order is deliberate: reserve the (finding, project) pair first, then look for a
// recovery candidate, then create. Every path that could create twice is covered:
//
//   - the reservation's unique index stops two concurrent requests;
//   - a pending reservation from an earlier ambiguous attempt triggers a marker search,
//     so an issue GitLab already created is adopted instead of duplicated;
//   - a definite failure removes the reservation, so a correction can be retried.
func (c *Creator) Create(ctx context.Context, f Finding, input IssueInput) (CreateResult, error) {
	if c.Store == nil || c.Client == nil {
		return CreateResult{}, ErrNotConfigured
	}
	if strings.TrimSpace(f.FindingKey) == "" {
		return CreateResult{}, errors.New("a finding key is required: it is what prevents duplicate tickets")
	}
	if strings.TrimSpace(input.Title) == "" {
		input.Title = Title(f)
	}
	if strings.TrimSpace(input.Description) == "" {
		input.Description = RenderDescription(f)
	}
	unlock := c.lockFor(fmt.Sprintf("%s/%d", f.FindingKey, c.ProjectID))
	defer unlock()

	reserved, fresh, err := c.Store.Reserve(ctx, Ticket{
		FindingKey:        f.FindingKey,
		Asset:             f.Asset,
		VulnerabilityID:   f.VulnerabilityID,
		ProjectID:         c.ProjectID,
		ProjectPath:       c.ProjectPath,
		Title:             input.Title,
		Labels:            input.Labels,
		Assignee:          c.AssigneeName,
		CreatedBy:         c.CreatedBy,
		RemediationStatus: c.RemediationStatus,
	})
	if err != nil {
		return CreateResult{}, err
	}
	if !fresh {
		if reserved.IssueIID > 0 {
			return CreateResult{Ticket: reserved, Reused: true,
				Message: fmt.Sprintf("Issue #%d already exists for this finding", reserved.IssueIID)}, nil
		}
		// A pending row: something was attempted and we do not know how it ended.
		// Look for the marker before creating a second issue.
		adopted, found, err := c.recover(ctx, reserved)
		if err != nil {
			return CreateResult{}, err
		}
		if found {
			return CreateResult{Ticket: adopted, Reused: true,
				Message: fmt.Sprintf("Recovered issue #%d from an earlier attempt", adopted.IssueIID)}, nil
		}
	}

	if c.AssigneeID > 0 && len(input.AssigneeIDs) == 0 {
		input.AssigneeIDs = []int{c.AssigneeID}
	}
	issue, err := c.Client.CreateIssue(ctx, c.ProjectID, input)
	if err != nil {
		c.handleCreateError(ctx, reserved, err)
		return CreateResult{}, err
	}
	if issue.IID == 0 || issue.WebURL == "" {
		c.note(ctx, reserved.ID, "GitLab accepted the request but returned no issue reference; check the project before retrying")
		return CreateResult{}, errors.New("GitLab did not return an issue reference, so the ticket could not be recorded")
	}
	ticket, err := c.Store.Complete(ctx, reserved.ID, issue, c.ProjectPath, c.AssigneeName)
	if err != nil {
		// The issue exists; failing to store it is serious but must not read as "nothing
		// happened". The live URL is in the message so the operator can act.
		c.logf("ticket created but not recorded", "issue", issue.WebURL, "err", err)
		return CreateResult{}, fmt.Errorf("issue %s was created but could not be recorded: %w", issue.WebURL, err)
	}
	if c.Log != nil {
		c.Log.Info("gitlab issue created", "ticket", ticket.ID, "project", c.ProjectID,
			"issue_iid", ticket.IssueIID, "asset", ticket.Asset, "vulnerability", ticket.VulnerabilityID,
			"by", c.CreatedBy)
	}
	return CreateResult{Ticket: ticket, Created: true,
		Message: fmt.Sprintf("Created issue #%d in %s", ticket.IssueIID, firstNonEmpty(ticket.ProjectPath, fmt.Sprint(c.ProjectID)))}, nil
}

// recover searches the destination project for an issue carrying this finding's marker.
func (c *Creator) recover(ctx context.Context, t Ticket) (Ticket, bool, error) {
	issues, err := c.Client.SearchIssues(ctx, c.ProjectID, MarkerSearch(t.FindingKey))
	if err != nil {
		// A failed search is not a reason to create a duplicate: report it and stop.
		return Ticket{}, false, fmt.Errorf("%w (a previous attempt may already have created an issue; "+
			"the search that would prove it also failed)", err)
	}
	for _, issue := range issues {
		if !strings.Contains(issue.Description, Marker(t.FindingKey)) {
			continue
		}
		updated, err := c.Store.Complete(ctx, t.ID, issue, c.ProjectPath, "")
		if err != nil {
			return Ticket{}, false, err
		}
		c.logf("adopted existing gitlab issue", "ticket", updated.ID, "issue_iid", updated.IssueIID)
		return updated, true, nil
	}
	return Ticket{}, false, nil
}

// handleCreateError separates "definitely not created" from "unknown".
//
// The distinction decides whether a retry is safe. A rejected token, a forbidden request
// or a validation error means nothing was created, so the reservation is released. A
// timeout, a dropped connection or a 5xx means an issue may exist, so the reservation is
// kept and the next attempt searches for it first.
func (c *Creator) handleCreateError(ctx context.Context, t Ticket, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized), errors.Is(err, ErrForbidden),
		errors.Is(err, ErrProjectMissing), errors.Is(err, ErrNoIssuePerms):
		if abandonErr := c.Store.Abandon(ctx, t.ID); abandonErr != nil {
			c.logf("could not release ticket reservation", "ticket", t.ID, "err", abandonErr)
		}
	case isAmbiguous(err):
		c.note(ctx, t.ID, "GitLab did not confirm the issue; a retry will search for it before creating another")
	default:
		// A 4xx from GitLab is a decided answer: nothing was created.
		var apiErr *APIError
		if errors.As(err, &apiErr) && apiErr.Status >= 400 && apiErr.Status < 500 {
			if abandonErr := c.Store.Abandon(ctx, t.ID); abandonErr != nil {
				c.logf("could not release ticket reservation", "ticket", t.ID, "err", abandonErr)
			}
			return
		}
		c.note(ctx, t.ID, "GitLab did not confirm the issue; a retry will search for it before creating another")
	}
}

// isAmbiguous reports whether a creation attempt could have succeeded server-side.
func isAmbiguous(err error) bool {
	if errors.Is(err, ErrUnreachable) {
		return true
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr.Status >= 500
	}
	return false
}

func (c *Creator) note(ctx context.Context, id, msg string) {
	if err := c.Store.MarkUnknown(ctx, id, msg); err != nil {
		c.logf("could not record ticket note", "ticket", id, "err", err)
	}
}

func (c *Creator) logf(msg string, args ...any) {
	if c.Log != nil {
		c.Log.Warn(msg, args...)
	}
}

// RefreshTicket reads the issue from GitLab and stores what it found.
func (c *Creator) RefreshTicket(ctx context.Context, id string) (Ticket, error) {
	t, err := c.Store.Get(ctx, id)
	if err != nil {
		return Ticket{}, err
	}
	if t.IssueIID == 0 {
		return t, errors.New("this ticket has no issue yet: creation never completed")
	}
	issue, err := c.Client.Issue(ctx, t.ProjectID, t.IssueIID)
	if err != nil {
		return t, err
	}
	updated, err := c.Store.UpdateState(ctx, id, stateOrOpened(issue.State), issue.AssigneeName())
	if err != nil {
		return t, err
	}
	if c.Log != nil {
		c.Log.Info("gitlab issue state refreshed", "ticket", id, "state", updated.State, "issue_iid", updated.IssueIID)
	}
	return updated, nil
}
