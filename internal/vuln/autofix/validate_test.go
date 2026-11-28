package autofix

import (
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.4.0", "2.12.0", 1},
		{"2.12.0", "3.4.0", -1},
		{"1.0.0", "1.0.0", 0},
		{"1.10.0", "1.9.9", 1}, // numeric, not lexical
		{"1.0.0", "1.0", 0},    // trailing zero run is equal
		{"2:1snap1-0ubuntu3", "2:1snap1-0ubuntu2", 1},
		{"1.0.0-1ubuntu1", "1.0.0", 1},
	}
	for _, tc := range cases {
		if got := CompareVersions(tc.a, tc.b); got != tc.want {
			t.Fatalf("CompareVersions(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestValidateUpgradeRefusesDowngrades(t *testing.T) {
	if err := ValidateUpgrade("3.4.0", "2.12.0", "3.4.0"); err != nil {
		t.Fatalf("a real upgrade must pass: %v", err)
	}
	if err := ValidateUpgrade("2.11.0", "2.12.0", "3.4.0"); err == nil {
		t.Fatal("a version below the fixed version must be refused")
	}
	if err := ValidateUpgrade("2.12.0", "2.12.0", "2.12.0"); err == nil {
		t.Fatal("a version that does not move past the installed one must be refused")
	}
	if err := ValidateUpgrade("", "2.12.0", "3.4.0"); err == nil {
		t.Fatal("an empty proposal must be refused")
	}
	if err := ValidateUpgrade("3.4.0", "2.12.0", ""); err == nil {
		t.Fatal("without a fixed version there is nothing to validate against")
	}
}

func TestValidatePathAllowList(t *testing.T) {
	allow := DefaultAllowPaths
	if err := ValidatePath("requirements.txt", allow); err != nil {
		t.Fatalf("requirements.txt should be writable: %v", err)
	}
	if err := ValidatePath("docker-compose.yml", allow); err != nil {
		t.Fatalf("docker-compose.yml is on the allow-list: %v", err)
	}
	if err := ValidatePath("app/main.py", allow); err == nil {
		t.Fatal("a source file outside the allow-list must be refused")
	}
	if err := ValidatePath("../../etc/passwd", allow); err == nil {
		t.Fatal("path traversal must be refused")
	}
	if err := ValidatePath("/etc/passwd", allow); err == nil {
		t.Fatal("absolute paths must be refused")
	}
}

func TestValidatePathForbidsPrivilegeBoundaries(t *testing.T) {
	// Even if a caller widens the allow-list, these stay off limits.
	wide := append(append([]string{}, DefaultAllowPaths...), ".gitlab-ci.yml", ".github/workflows/ci.yml", ".env", "keys/app.pem")
	for _, p := range []string{".gitlab-ci.yml", ".github/workflows/ci.yml", ".env", "keys/app.pem"} {
		if err := ValidatePath(p, wide); err == nil {
			t.Fatalf("%q must never be writable by automation", p)
		}
	}
}

func TestScanSecrets(t *testing.T) {
	bad := []string{
		"-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----",
		"token = glpat-abcdefghijklmnopqrst",
		"aws_access_key_id = AKIAIOSFODNN7EXAMPLE",
		// A vendor-neutral long credential (deliberately NOT shaped like any real
		// provider's key: shaped fixtures trip repository secret scanning).
		`api_key = "test-only-inline-credential-000000"`,
		`password = "hunter2hunter2"`,
	}
	for _, s := range bad {
		if err := ScanSecrets(s); err == nil {
			t.Fatalf("secret not detected in %q", s)
		}
	}
	good := "flask==3.0.1\nrequests==2.31.0\n"
	if err := ScanSecrets(good); err != nil {
		t.Fatalf("a plain requirements file must not trip the secret scan: %v", err)
	}
}

func TestValidatePatch(t *testing.T) {
	ok := PatchProposal{
		Rationale: "bind the service to loopback",
		Files:     []FileChange{{Path: "docker-compose.yml", Content: "services: {}\n"}},
	}
	if err := ValidatePatch(ok, DefaultAllowPaths, 1024); err != nil {
		t.Fatalf("a minimal valid proposal must pass: %v", err)
	}

	noRationale := ok
	noRationale.Rationale = "  "
	if err := ValidatePatch(noRationale, DefaultAllowPaths, 1024); err == nil {
		t.Fatal("a proposal without a rationale must be refused")
	}

	noFiles := PatchProposal{Rationale: "x"}
	if err := ValidatePatch(noFiles, DefaultAllowPaths, 1024); err == nil {
		t.Fatal("a proposal that changes nothing must be refused")
	}

	dup := PatchProposal{Rationale: "x", Files: []FileChange{
		{Path: "requirements.txt", Content: "a==1"},
		{Path: "./requirements.txt", Content: "a==2"},
	}}
	if err := ValidatePatch(dup, DefaultAllowPaths, 1024); err == nil {
		t.Fatal("the same file twice means the proposal contradicts itself")
	}

	big := PatchProposal{Rationale: "x", Files: []FileChange{
		{Path: "requirements.txt", Content: strings.Repeat("a", 2048)},
	}}
	if err := ValidatePatch(big, DefaultAllowPaths, 1024); err == nil {
		t.Fatal("an oversized generated file must be refused")
	}

	leaky := PatchProposal{Rationale: "x", Files: []FileChange{
		{Path: "requirements.txt", Content: "token = glpat-abcdefghijklmnopqrst\n"},
	}}
	if err := ValidatePatch(leaky, DefaultAllowPaths, 1024); err == nil {
		t.Fatal("a generated secret must be refused")
	}
}

func TestBumpManifestIsSurgical(t *testing.T) {
	src := "# runtime\nparamiko==2.12.0\nflask==3.0.1\nrequests>=2.0\n"
	out, ok := bumpRequirements(src, "paramiko", "3.4.0")
	if !ok {
		t.Fatal("paramiko should have been found")
	}
	if !strings.Contains(out, "paramiko==3.4.0") {
		t.Fatalf("paramiko not bumped:\n%s", out)
	}
	if !strings.Contains(out, "flask==3.0.1") || !strings.Contains(out, "requests>=2.0") {
		t.Fatalf("unrelated dependencies must not change:\n%s", out)
	}
	if !strings.Contains(out, "# runtime") {
		t.Fatal("comments must be preserved")
	}

	if _, ok := bumpRequirements(src, "absent-package", "1.0.0"); ok {
		t.Fatal("a package that is not in the file must not produce a change")
	}

	pkgJSON := `{"dependencies":{"paramiko":"^2.12.0","flask":"^3.0.1"}}`
	updated, ok := bumpPackageJSON(pkgJSON, "paramiko", "3.4.0")
	if !ok {
		t.Fatal("package.json dependency should have been found")
	}
	if !strings.Contains(updated, `"paramiko": "3.4.0"`) {
		t.Fatalf("npm dependency not pinned exactly:\n%s", updated)
	}
	if !strings.Contains(updated, `"flask": "^3.0.1"`) {
		t.Fatalf("unrelated dependency changed:\n%s", updated)
	}
}

func TestBumpPyprojectPoetryStyle(t *testing.T) {
	src := `[tool.poetry]
name = "clanker"
version = "0.1.0"

[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.115.0"
uvicorn = {version = "^0.30.0", extras = ["standard"]}
paramiko = "^4.0.0"

[tool.poetry.group.dev.dependencies]
pytest = "^8.3.0"
`
	out, ok := bumpPyproject(src, "paramiko", "4.1.0")
	if !ok {
		t.Fatal("paramiko should have been found in [tool.poetry.dependencies]")
	}
	if !strings.Contains(out, `paramiko = "4.1.0"`) {
		t.Fatalf("paramiko not pinned:\n%s", out)
	}
	if !strings.Contains(out, `fastapi = "^0.115.0"`) {
		t.Fatalf("unrelated dependency changed:\n%s", out)
	}
	// The package's own version line must not be mistaken for a dependency.
	if !strings.Contains(out, `version = "0.1.0"`) {
		t.Fatalf("project version was rewritten:\n%s", out)
	}

	inline, ok := bumpPyproject(src, "uvicorn", "0.31.0")
	if !ok || !strings.Contains(inline, `uvicorn = {version = "0.31.0", extras = ["standard"]}`) {
		t.Fatalf("inline-table version not rewritten:\n%s", inline)
	}

	dev, ok := bumpPyproject(src, "pytest", "9.0.0")
	if !ok || !strings.Contains(dev, `pytest = "9.0.0"`) {
		t.Fatalf("group dependency not rewritten:\n%s", dev)
	}

	if _, ok := bumpPyproject(src, "not-a-dependency", "1.0.0"); ok {
		t.Fatal("an absent package must not produce a change")
	}
}

func TestBumpPyprojectPEP621(t *testing.T) {
	src := `[project]
name = "app"
dependencies = [
  "pillow>=10.0",
  "fastapi",
]

[project.optional-dependencies]
dev = ["pytest"]
`
	out, ok := bumpPyproject(src, "Pillow", "13.0.0") // case-insensitive match
	if !ok {
		t.Fatal("pillow should have been found in the PEP 621 array")
	}
	if !strings.Contains(out, `"pillow==13.0.0"`) {
		t.Fatalf("requirement not pinned:\n%s", out)
	}
	if !strings.Contains(out, `"fastapi",`) {
		t.Fatalf("unrelated requirement changed:\n%s", out)
	}
}

func TestNeverLowerAnExistingConstraint(t *testing.T) {
	// The host runs paramiko 2.12.0 and the advisory fixes it at 3.4.0, but this
	// repository already requires ^4.0.0. Rewriting it to 3.4.0 would be a regression
	// caused by a remediation tool.
	pyproject := "[tool.poetry.dependencies]\nparamiko = \"^4.0.0\"\n"
	if out, ok := bumpPyproject(pyproject, "paramiko", "3.4.0"); ok {
		t.Fatalf("a newer existing constraint must not be lowered:\n%s", out)
	}

	reqs := "paramiko>=5.0\n"
	if out, ok := bumpRequirements(reqs, "paramiko", "3.4.0"); ok {
		t.Fatalf("a newer existing requirement must not be lowered:\n%s", out)
	}

	// A genuinely older constraint still gets the fix.
	if out, ok := bumpRequirements("paramiko==2.12.0\n", "paramiko", "3.4.0"); !ok {
		t.Fatalf("an older pin must be fixed:\n%s", out)
	}
	if out, ok := bumpRequirements("paramiko>=2.0\n", "paramiko", "3.4.0"); !ok || !strings.Contains(out, "paramiko==3.4.0") {
		t.Fatalf("a lower-bound constraint must be fixed:\n%s", out)
	}
}

func TestSpecVersion(t *testing.T) {
	cases := map[string]string{
		"^1.2.3":     "1.2.3",
		">=2.0":      "2.0",
		"==2.12.0":   "2.12.0",
		"~1.4":       "1.4",
		">=1.0,<2.0": "1.0",
		"\"3.4.0\"":  "3.4.0",
		"":           "",
		"no-version": "no-version",
	}
	for in, want := range cases {
		if got := specVersion(in); got != want {
			t.Fatalf("specVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
