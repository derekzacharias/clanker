package ticketing

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// This file is the write surface an automated fixer needs: it can create a branch,
// commit several files to it, open a merge request and comment on the issue that
// tracks the finding. Everything is deliberately narrow.
//
// It does NOT merge, force-push, delete branches or touch protected refs. Those are
// decisions for a person, and a bot token that can do them is a bot token that will
// eventually do them by accident.

// FileAction is one entry in a multi-file commit.
type FileAction struct {
	Action   string `json:"action"` // create | update | delete
	FilePath string `json:"file_path"`
	Content  string `json:"content,omitempty"`
}

// Branch is the subset of a created branch that a caller needs.
type Branch struct {
	Name   string `json:"name"`
	WebURL string `json:"web_url"`
	Commit struct {
		ID string `json:"id"`
	} `json:"commit"`
}

// MergeRequestInput is what POST /projects/:id/merge_requests takes.
type MergeRequestInput struct {
	SourceBranch       string `json:"source_branch"`
	TargetBranch       string `json:"target_branch"`
	Title              string `json:"title"`
	Description        string `json:"description,omitempty"`
	Labels             string `json:"labels,omitempty"`
	RemoveSourceBranch bool   `json:"remove_source_branch,omitempty"`
	Squash             bool   `json:"squash,omitempty"`
	// Draft is expressed to GitLab as a title prefix, so it is not serialised.
	Draft bool `json:"-"`
}

// MergeRequest is the subset of an MR that gets stored or displayed.
type MergeRequest struct {
	ID           int    `json:"id"`
	IID          int    `json:"iid"`
	WebURL       string `json:"web_url"`
	State        string `json:"state"`
	SourceBranch string `json:"source_branch"`
	TargetBranch string `json:"target_branch"`
	Title        string `json:"title"`
	Draft        bool   `json:"draft"`
}

// Note is one issue comment.
type Note struct {
	ID   int    `json:"id"`
	Body string `json:"body"`
}

// CreateBranch creates a branch from ref.
func (c *Client) CreateBranch(ctx context.Context, projectID int, name, ref string) (Branch, error) {
	name, ref = strings.TrimSpace(name), strings.TrimSpace(ref)
	if name == "" || ref == "" {
		return Branch{}, errors.New("a branch needs a name and a starting ref")
	}
	path := "/projects/" + strconv.Itoa(projectID) + "/repository/branches?branch=" +
		url.QueryEscape(name) + "&ref=" + url.QueryEscape(ref)
	var out Branch
	err := c.do(ctx, http.MethodPost, path, nil, &out)
	return out, err
}

// CommitFiles writes several files in one commit.
//
// The caller decides create vs update; this function never guesses, because a wrong
// "create" on an existing path fails loudly while a wrong "update" is a silent no-op
// that looks like success.
func (c *Client) CommitFiles(ctx context.Context, projectID int, branch, message string, actions []FileAction) (string, error) {
	if strings.TrimSpace(branch) == "" {
		return "", errors.New("a commit needs a branch")
	}
	if strings.TrimSpace(message) == "" {
		return "", errors.New("a commit needs a message")
	}
	if len(actions) == 0 {
		return "", errors.New("a commit needs at least one file action")
	}
	for _, a := range actions {
		switch a.Action {
		case "create", "update", "delete":
		default:
			return "", fmt.Errorf("unsupported file action %q (want create, update or delete)", a.Action)
		}
		if strings.TrimSpace(a.FilePath) == "" {
			return "", errors.New("every file action needs a path")
		}
	}
	body := map[string]any{
		"branch":         branch,
		"commit_message": message,
		"actions":        actions,
	}
	var out struct {
		ID string `json:"id"`
	}
	err := c.do(ctx, http.MethodPost, "/projects/"+strconv.Itoa(projectID)+"/repository/commits", body, &out)
	return out.ID, err
}

// CreateMergeRequest opens a merge request. Hand-written checks only: GitLab is the
// authority on whether the branches diverge.
func (c *Client) CreateMergeRequest(ctx context.Context, projectID int, in MergeRequestInput) (MergeRequest, error) {
	if strings.TrimSpace(in.SourceBranch) == "" || strings.TrimSpace(in.TargetBranch) == "" {
		return MergeRequest{}, errors.New("a merge request needs a source and a target branch")
	}
	if strings.TrimSpace(in.Title) == "" {
		return MergeRequest{}, errors.New("a merge request needs a title")
	}
	if in.Draft && !strings.HasPrefix(strings.ToLower(in.Title), "draft:") {
		in.Title = "Draft: " + in.Title
	}
	var out MergeRequest
	err := c.do(ctx, http.MethodPost, "/projects/"+strconv.Itoa(projectID)+"/merge_requests", in, &out)
	return out, err
}

// MergeRequestsFor lists merge requests by source branch. It is the idempotency check:
// a re-run finds the MR it already opened instead of opening a second one.
func (c *Client) MergeRequestsFor(ctx context.Context, projectID int, sourceBranch string) ([]MergeRequest, error) {
	path := "/projects/" + strconv.Itoa(projectID) + "/merge_requests?state=all&per_page=20&source_branch=" +
		url.QueryEscape(sourceBranch)
	var out []MergeRequest
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// CreateNote appends a comment to an issue. It is how every automated decision becomes
// visible on the ticket without ever rewriting the ticket body.
func (c *Client) CreateNote(ctx context.Context, projectID, iid int, body string) (Note, error) {
	if strings.TrimSpace(body) == "" {
		return Note{}, errors.New("a note needs a body")
	}
	path := "/projects/" + strconv.Itoa(projectID) + "/issues/" + strconv.Itoa(iid) + "/notes"
	var out Note
	err := c.do(ctx, http.MethodPost, path, map[string]string{"body": body}, &out)
	return out, err
}

// FileContent reads one file at a ref.
//
// GitLab answers with base64 JSON rather than raw bytes, so the decoding happens here;
// callers deal in bytes and never have to know the encoding exists.
func (c *Client) FileContent(ctx context.Context, projectID int, filePath, ref string) ([]byte, error) {
	filePath = strings.TrimSpace(filePath)
	if filePath == "" {
		return nil, errors.New("a file path is required")
	}
	path := "/projects/" + strconv.Itoa(projectID) + "/repository/files/" +
		url.PathEscape(filePath) + "?ref=" + url.QueryEscape(ref)
	var out struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
	}
	if err := c.do(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	if out.Encoding != "base64" {
		return []byte(out.Content), nil
	}
	raw, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(out.Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", filePath, err)
	}
	return raw, nil
}

// BranchExists reports whether a branch is already there. Used to make re-runs
// idempotent without treating "already exists" as a failure.
func (c *Client) BranchExists(ctx context.Context, projectID int, name string) (bool, error) {
	path := "/projects/" + strconv.Itoa(projectID) + "/repository/branches/" + url.PathEscape(name)
	var out Branch
	err := c.do(ctx, http.MethodGet, path, nil, &out)
	if err == nil {
		return true, nil
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.Status == http.StatusNotFound {
		return false, nil
	}
	return false, err
}
