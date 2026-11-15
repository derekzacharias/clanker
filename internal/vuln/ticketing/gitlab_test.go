package ticketing

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// --- URL validation: the SSRF and token-leak guards -------------------------------

func TestValidateBaseURLRefusesTokenLeaksAndMetadata(t *testing.T) {
	cases := []struct {
		name        string
		url         string
		allowHTTP   bool
		wantErr     error
		wantContain string
	}{
		// The internal test instance: private, plain HTTP, explicitly allowed.
		{name: "private http when allowed", url: "http://127.0.0.1:8929", allowHTTP: true},
		{name: "public http always refused", url: "http://gitlab.example.com", allowHTTP: true,
			wantErr: ErrInsecureURL},
		{name: "http refused unless allowed", url: "http://10.1.2.3:8929", allowHTTP: false,
			wantErr: ErrInsecureURL},
		// A token must never travel to a cloud metadata endpoint, in either scheme.
		{name: "metadata ip refused", url: "http://169.254.169.254", allowHTTP: true,
			wantContain: "link-local"},
		{name: "credentials in url refused", url: "https://user:pw@gitlab.example.com",
			wantContain: "must not embed credentials"},
		{name: "query string refused", url: "https://gitlab.example.com?token=abc",
			wantContain: "query or fragment"},
		{name: "wrong scheme refused", url: "gitlab.example.com", wantContain: "http:// or https://"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ValidateBaseURL(tc.url, tc.allowHTTP)
			if tc.wantErr == nil && tc.wantContain == "" {
				if err != nil {
					t.Fatalf("ValidateBaseURL(%q) = %v, want nil", tc.url, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateBaseURL(%q) succeeded, want an error", tc.url)
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Fatalf("error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantContain != "" && !strings.Contains(err.Error(), tc.wantContain) {
				t.Fatalf("error = %q, want it to mention %q", err, tc.wantContain)
			}
		})
	}
}

// The URL may be written with or without the API suffix; both must work.
func TestBaseURLNormalisesAPISuffix(t *testing.T) {
	u, err := ValidateBaseURL("http://127.0.0.1:8929/api/v4/", true)
	if err != nil {
		t.Fatalf("ValidateBaseURL: %v", err)
	}
	if got := u.String(); got != "http://127.0.0.1:8929" {
		t.Fatalf("normalised URL = %q", got)
	}
}

// --- Connectivity, auth and error taxonomy ----------------------------------------

func TestVersionProvesReachabilityAndSendsTokenInHeader(t *testing.T) {
	f := newFake()
	client, _ := newServerWithFake(t, f)
	version, _, err := client.Version(context.Background())
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if version != "19.5.5" {
		t.Fatalf("version = %q", version)
	}
	// The token travels in a header, never in the URL.
	last := f.last()
	if last.Token != "test-token" {
		t.Fatalf("PRIVATE-TOKEN header = %q", last.Token)
	}
	if strings.Contains(last.Path, "test-token") {
		t.Fatal("the token appeared in the request path")
	}
}

func TestInvalidTokenIsReportedAsUnauthorized(t *testing.T) {
	f := newFake()
	f.versionStatus = http.StatusUnauthorized
	client, _ := newServerWithFake(t, f)
	_, _, err := client.Version(context.Background())
	if !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if !strings.Contains(err.Error(), "401") {
		t.Fatalf("error should name the status: %v", err)
	}
}

func TestUnreachableServerIsDistinctFromBadCredentials(t *testing.T) {
	// A port that nothing listens on: the client must say "unreachable", not "unauthorized".
	client, err := NewClient(Config{BaseURL: "http://127.0.0.1:1", Token: "t", Timeout: time.Second,
		AllowInsecureHTTP: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	_, _, err = client.Version(context.Background())
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
}

func TestTimeoutSurfacesAsUnreachableAndRespectsDeadline(t *testing.T) {
	f := newFake()
	f.createDelay = 300 * time.Millisecond
	srv := httptest.NewServer(f.handler())
	t.Cleanup(srv.Close)
	client, err := NewClient(Config{BaseURL: srv.URL, Token: "t", Timeout: 50 * time.Millisecond,
		AllowInsecureHTTP: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	start := time.Now()
	_, err = client.CreateIssue(context.Background(), 42, IssueInput{Title: "t", Description: "d"})
	if err == nil {
		t.Fatal("expected a timeout")
	}
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("err = %v, want ErrUnreachable", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("timeout took %v, so the client timeout is not enforced", elapsed)
	}
}

func TestMissingProjectIsReportedAsProjectNotFound(t *testing.T) {
	f := newFake()
	f.project = nil // 404
	client, _ := newServerWithFake(t, f)
	_, err := client.Project(context.Background(), 42)
	if !errors.Is(err, ErrProjectMissing) {
		t.Fatalf("err = %v, want ErrProjectMissing", err)
	}
}

// A redirect to another host is how a token leaks; the client must refuse it.
func TestRedirectToAnotherHostIsRefused(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("the client followed a redirect to %s", r.Host)
	}))
	defer other.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/api/v4/version", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	client, err := NewClient(Config{BaseURL: redirector.URL, Token: "t", Timeout: 2 * time.Second,
		AllowInsecureHTTP: true}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, _, err := client.Version(context.Background()); err == nil {
		t.Fatal("the redirect was followed, which would carry the token to another host")
	}
}

// --- Connection test ---------------------------------------------------------------

func TestVerifyReportsEveryCheckWithoutCreatingAnything(t *testing.T) {
	f := newFake()
	client, _ := newServerWithFake(t, f)
	res := client.Verify(context.Background(), 42)
	if !res.OK || !res.CanCreateIssues {
		t.Fatalf("verify = %+v", res)
	}
	if res.Version != "19.5.5" || res.User != "guard-bot" || res.Project == nil || res.Project.ID != 42 {
		t.Fatalf("verify result incomplete: %+v", res)
	}
	if len(res.Checks) != 5 {
		t.Fatalf("expected 5 checks, got %d: %+v", len(res.Checks), res.Checks)
	}
	// The test must read, never write.
	if n := f.count(http.MethodPost, "/issues"); n != 0 {
		t.Fatalf("Test Connection created %d issues; it must not create any", n)
	}
	if !strings.Contains(res.Summary, "no issue was created") {
		t.Fatalf("summary must not imply a creation test: %q", res.Summary)
	}
}

func TestVerifyDistinguishesTheFailureModes(t *testing.T) {
	t.Run("invalid token", func(t *testing.T) {
		f := newFake()
		f.versionStatus = http.StatusUnauthorized
		client, _ := newServerWithFake(t, f)
		res := client.Verify(context.Background(), 42)
		if res.OK {
			t.Fatal("verify passed with a rejected token")
		}
		if !strings.Contains(res.Summary, "token was rejected") {
			t.Fatalf("summary = %q", res.Summary)
		}
	})
	t.Run("project not found", func(t *testing.T) {
		f := newFake()
		f.project = nil
		client, _ := newServerWithFake(t, f)
		res := client.Verify(context.Background(), 42)
		if res.OK || !strings.Contains(res.Summary, "not found") {
			t.Fatalf("verify = %+v", res)
		}
	})
	t.Run("issues disabled", func(t *testing.T) {
		f := newFake()
		f.project["issues_enabled"] = false
		client, _ := newServerWithFake(t, f)
		res := client.Verify(context.Background(), 42)
		if res.OK || !strings.Contains(res.Summary, "Issues are disabled") {
			t.Fatalf("verify = %+v", res)
		}
	})
	t.Run("insufficient role", func(t *testing.T) {
		f := newFake()
		f.project["permissions"] = map[string]any{"project_access": map[string]any{"access_level": 10}}
		client, _ := newServerWithFake(t, f)
		res := client.Verify(context.Background(), 42)
		if res.OK || res.CanCreateIssues {
			t.Fatalf("verify passed for a guest: %+v", res)
		}
		if !strings.Contains(res.Summary, "cannot create issues") {
			t.Fatalf("summary = %q", res.Summary)
		}
	})
}

// --- Issue rendering ---------------------------------------------------------------

func TestDescriptionCarriesTheEvidenceAndKeepsProvenance(t *testing.T) {
	f := testFinding()
	body := RenderDescription(f)
	for _, want := range []string{
		"CVE-2026-1234", "CRITICAL", "CVSS:** 9.8", "web01.prod", "Ubuntu 22.04",
		"openssl", "3.0.2", "Installed version is inside the affected range.",
		"openssl 3.0.2 installed", "3.0.13-1ubuntu1", "USN-6000-1",
		"quoted by the scanner",
		"Re-scan the host", "clanker-guard:finding:ab12cd34ef56", "SCAN-1",
		"nvd.nist.gov/vuln/detail/CVE-2026-1234",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("description is missing %q:\n%s", want, body)
		}
	}
}

func TestDescriptionDoesNotInventARemediation(t *testing.T) {
	f := testFinding()
	f.RemediationText = ""
	f.RemediationOrigin = ""
	f.FixedVersion = ""
	body := RenderDescription(f)
	if !strings.Contains(body, "No fixed version is published") {
		t.Fatalf("expected an honest \"no fix\" statement:\n%s", body)
	}
	if strings.Contains(body, "apt upgrade") || strings.Contains(body, "yum update") {
		t.Fatal("the renderer invented a package command")
	}
	if !strings.Contains(body, "Do not assume a generic package upgrade resolves this") {
		t.Fatal("the guidance must warn against assuming a generic upgrade fixes it")
	}
}

func TestDescriptionMarksGeneratedTextAsUnverified(t *testing.T) {
	f := testFinding()
	f.RemediationOrigin = "scanner"
	f.RemediationSource = ""
	body := RenderDescription(f)
	if !strings.Contains(body, "not verified steps") {
		t.Fatalf("scanner-composed remediation must be labelled:\n%s", body)
	}
}

func TestTitleFollowsTheAgreedShape(t *testing.T) {
	f := testFinding()
	want := "[CRITICAL] CVE-2026-1234 | openssl | web01"
	if got := Title(f); got != want {
		t.Fatalf("title = %q, want %q", got, want)
	}
}

func TestLabelsMergeSeverityWithConfiguredOnes(t *testing.T) {
	f := testFinding()
	got := LabelString(Labels([]string{"security", " team-infra "}, f))
	for _, want := range []string{"security", "critical", "cisa-kev", "fix-available", "team-infra"} {
		if !strings.Contains(got, want) {
			t.Fatalf("labels = %q, missing %q", got, want)
		}
	}
	// "security" is both derived and configured: it must appear once.
	if strings.Count(got, "security") != 1 {
		t.Fatalf("duplicate label in %q", got)
	}
}
