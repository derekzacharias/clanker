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

// --- Issue rendering ---

func TestDescriptionIsAWorkOrder(t *testing.T) {
	f := testFinding()
	f.Access = AccessBlock{Host: "web01", SSHUser: "deploy", SSHJump: "bastion.prod"}
	body := RenderDescription(f)

	for _, want := range []string{
		"# Security remediation — CVE-2026-1234",
		"## Affected system",
		"| Hostname | web01.prod |",
		"| Package | openssl |",
		"| Installed version | 3.0.2 |",
		"| Fixed version | 3.0.13-1ubuntu1 |",
		"## Step 1: Connect to the affected system",
		"```bash\nssh -J bastion.prod deploy@web01\n```",
		"## Step 2: Apply the fix on the host",
		"```bash\nsudo apt-get update\nsudo apt-get install --only-upgrade openssl=3.0.13-1ubuntu1\n```",
		"## Step 3: Verify the fix",
		"dpkg-query -W",
		"**Local check ≠ resolved.**",
		"## Step 4: Roll back if something breaks",
		"sudo apt-get install openssl=3.0.2",
		"## Advisory guidance",
		"## Source",
		"clanker-guard:finding:ab12cd34ef56",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("ticket is missing %q:\n%s", want, body)
		}
	}
	// Markdown hygiene: no command ever sits in a paragraph.
	if strings.Contains(body, "``sudo") || strings.Contains(body, "`sudo apt-get install --only-upgrade") {
		t.Fatalf("a command was emitted outside a fenced block:\n%s", body)
	}
}

// A missing fixed version must not turn into a guess: the ticket becomes read-only checks and
// says plainly that nothing is published.
func TestDescriptionWithoutAFixStaysReadOnly(t *testing.T) {
	f := testFinding()
	f.FixedVersion = ""
	body := RenderDescription(f)
	for _, want := range []string{"No confirmed fix is published", "Manual investigation", "## Step"} {
		_ = want
	}
	if !strings.Contains(body, "No confirmed fix is published") {
		t.Fatalf("missing the no-fix verdict:\n%s", body)
	}
	if strings.Contains(body, "install --only-upgrade") || strings.Contains(body, "upgrade openssl") {
		t.Fatalf("an upgrade command was generated without a fixed version:\n%s", body)
	}
	if !strings.Contains(body, "dpkg-query") {
		t.Fatalf("no read-only inspection step:\n%s", body)
	}
}

// Windows gets PowerShell on the host and never an SSH line.
func TestWindowsTicketUsesPowerShellAndNoSSH(t *testing.T) {
	f := testFinding()
	f.OS, f.OSVersion, f.Ecosystem = "Windows Server", "2022", "winget"
	f.Product, f.InstalledVersion, f.FixedVersion = "curl", "7.83.1", "8.4.0"
	f.Access = AccessBlock{Host: "win01", SSHUser: "deploy"}
	body := RenderDescription(f)
	if !strings.Contains(body, "```powershell") || !strings.Contains(body, "winget upgrade --id") {
		t.Fatalf("no PowerShell remediation:\n%s", body)
	}
	if strings.Contains(body, "apt-get") || strings.Contains(body, "dnf ") {
		t.Fatalf("Linux commands leaked into a Windows ticket:\n%s", body)
	}
	if strings.Contains(body, "ssh deploy@") {
		t.Fatalf("an SSH line was generated for Windows:\n%s", body)
	}
}

// A container finding is an image rebuild, not a shell inside a running container.
func TestContainerTicketRebuildsTheImage(t *testing.T) {
	f := testFinding()
	f.Asset = "image:acme/api"
	f.Hostname = "image:acme/api"
	f.Ecosystem = "container:alpine"
	f.Access = AccessBlock{Host: "image:acme/api", SSHUser: "deploy"}
	body := RenderDescription(f)
	if strings.Contains(body, "ssh deploy@") {
		t.Fatalf("an SSH line was generated for a container image:\n%s", body)
	}
	if !strings.Contains(body, "```dockerfile") || !strings.Contains(body, "docker build") {
		t.Fatalf("no rebuild instructions:\n%s", body)
	}
}

// Kernel packages are flagged: the fix is not live until the host reboots.
func TestKernelFindingIsFlaggedDisruptive(t *testing.T) {
	f := testFinding()
	f.Product, f.Ecosystem = "linux-image-generic", "Ubuntu:22.04"
	p := BuildPlan(f)
	if !p.Disruptive {
		t.Fatal("a kernel upgrade was not flagged as disruptive")
	}
	if !strings.Contains(Render(p), "**This change is disruptive.**") {
		t.Fatalf("the disruption warning is not prominent:\n%s", Render(p))
	}
}

func TestTitleFollowsTheAgreedShape(t *testing.T) {
	f := testFinding()
	want := "[CRITICAL] CVE-2026-1234 | web01.prod | openssl"
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

// The ticket must be usable by a developer: how to get on the box, what to run, how to check
// it worked, how to undo it — and it must say so when it cannot be sure.
func TestDescriptionOmitsAccessWhenNothingIsKnown(t *testing.T) {
	f := testFinding()
	f.Access = AccessBlock{Host: "web01"}
	if body := RenderDescription(f); strings.Contains(body, "## Access") {
		t.Fatalf("empty access section rendered:\n%s", body)
	}
}

// Pseudo-assets are not machines: a ticket must not tell anyone to SSH into `sbom:sbom.json`.
func TestPseudoAssetsGetNoSSHInstruction(t *testing.T) {
	for _, asset := range []string{"sbom:sbom.json", "scope:live-check", "localhost", "image:acme/api"} {
		f := testFinding()
		f.Asset = asset
		f.Hostname = asset
		f.OS, f.OSVersion = "", ""
		f.Access = AccessBlock{Host: asset, SSHUser: "deploy"}
		body := RenderDescription(f)
		if strings.Contains(body, "ssh deploy@") || strings.Contains(body, "ssh <admin-user>@") {
			t.Fatalf("%s: an SSH instruction was generated for a pseudo-asset:\n%s", asset, body)
		}
	}
}
