package version

import "testing"

func TestCompareDebian(t *testing.T) {
	// Expected ordering follows dpkg --compare-versions.
	ordered := []string{
		"1.0~rc1-1",
		"1.0-1",
		"1.0-2",
		"1.0-2ubuntu1",
		"1.0-10",
		"1.1-1",
		"1:0.9-1",
		"2:0.1-1",
	}
	for i := 0; i < len(ordered)-1; i++ {
		a, b := ordered[i], ordered[i+1]
		if c, err := Compare("Debian:12", a, b); err != nil || c != -1 {
			t.Fatalf("expected %s < %s, got %d err=%v", a, b, c, err)
		}
		if c, err := Compare("Debian:12", b, a); err != nil || c != 1 {
			t.Fatalf("expected %s > %s, got %d err=%v", b, a, c, err)
		}
	}
	equal := map[string][2]string{
		"epoch zero equals no epoch": {"0:1.2.3-4", "1.2.3-4"},
		"missing revision":           {"1.2.3", "1.2.3-0"},
		"leading zeroes":             {"1.02.3", "1.2.3"},
	}
	for name, pair := range equal {
		if c, err := Compare("Ubuntu:24.04:LTS", pair[0], pair[1]); err != nil || c != 0 {
			t.Errorf("%s: expected %q == %q, got %d err=%v", name, pair[0], pair[1], c, err)
		}
	}
}

// TestDebianBackportOrdering is the case that matters for vendor backports:
// 1.2.3-1ubuntu1 (patched by Ubuntu) must sort ABOVE 1.2.3-1.
func TestDebianBackportOrdering(t *testing.T) {
	if c, err := Compare("Ubuntu:22.04:LTS", "3.0.13-0ubuntu3.5", "3.0.13-0ubuntu3.4"); err != nil || c != 1 {
		t.Fatalf("expected ubuntu3.5 > ubuntu3.4, got %d err=%v", c, err)
	}
	if c, err := Compare("Ubuntu:22.04:LTS", "3.0.13-0ubuntu3.5", "3.0.13-0ubuntu4"); err != nil || c != -1 {
		t.Fatalf("expected ubuntu3.5 < ubuntu4, got %d err=%v", c, err)
	}
}

func TestCompareRPM(t *testing.T) {
	ordered := []string{
		"1.0~beta1-1",
		"1.0-1",
		"1.0-2.el9",
		"1.0.1-1.el9",
		"2.0-1.el9",
	}
	for i := 0; i < len(ordered)-1; i++ {
		if c, err := Compare("Red Hat", ordered[i], ordered[i+1]); err != nil || c != -1 {
			t.Fatalf("expected %s < %s, got %d err=%v", ordered[i], ordered[i+1], c, err)
		}
	}
	// 1.0.10 > 1.0.9 (numeric, not lexical)
	if c, _ := Compare("Fedora", "1.0.10-1", "1.0.9-1"); c != 1 {
		t.Fatalf("1.0.10 should be newer than 1.0.9, got %d", c)
	}
	// alpha beats numeric
	if c, _ := Compare("Fedora", "1.0a-1", "1.0.1-1"); c != -1 {
		t.Fatalf("1.0a should sort before 1.0.1, got %d", c)
	}
}

func TestComparePEP440(t *testing.T) {
	ordered := []string{
		"1.0.dev1",
		"1.0a1",
		"1.0a2",
		"1.0b1",
		"1.0rc1",
		"1.0",
		"1.0.post1",
		"1.1",
		"1!1.0",
	}
	for i := 0; i < len(ordered)-1; i++ {
		if c, err := Compare("PyPI", ordered[i], ordered[i+1]); err != nil || c != -1 {
			t.Fatalf("expected %s < %s, got %d err=%v", ordered[i], ordered[i+1], c, err)
		}
	}
	equal := [][2]string{{"1.0", "1.0.0"}, {"1.0-1", "1.0.post1"}}
	for _, p := range equal {
		if c, err := Compare("PyPI", p[0], p[1]); err != nil || c != 0 {
			t.Errorf("expected %q == %q, got %d err=%v", p[0], p[1], c, err)
		}
	}
	if _, err := Compare("PyPI", "not a version", "1.0"); err == nil {
		t.Fatal("expected an error for non-PEP440 input")
	}
}

func TestCompareSemver(t *testing.T) {
	ordered := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
		"1.0.1",
		"1.10.0",
		"2.0.0",
	}
	for i := 0; i < len(ordered)-1; i++ {
		if c, err := Compare("npm", ordered[i], ordered[i+1]); err != nil || c != -1 {
			t.Fatalf("expected %s < %s, got %d err=%v", ordered[i], ordered[i+1], c, err)
		}
	}
	// build metadata is ignored
	if c, _ := Compare("Go", "1.2.3+build.5", "1.2.3"); c != 0 {
		t.Fatalf("build metadata must not affect ordering, got %d", c)
	}
}

func TestCompareMaven(t *testing.T) {
	ordered := []string{"1.0-alpha", "1.0-beta", "1.0-rc1", "1.0", "1.0.1", "1.1", "2.0"}
	for i := 0; i < len(ordered)-1; i++ {
		if c, err := Compare("Maven", ordered[i], ordered[i+1]); err != nil || c != -1 {
			t.Fatalf("expected %s < %s, got %d err=%v", ordered[i], ordered[i+1], c, err)
		}
	}
}

func TestCompareGenericAndValidation(t *testing.T) {
	if c, err := Compare("unknown", "1.2.10", "1.2.9"); err != nil || c != 1 {
		t.Fatalf("generic numeric compare failed: %d %v", c, err)
	}
	if err := ValidateVersion("npm", "1.2.3"); err != nil {
		t.Fatalf("valid version rejected: %v", err)
	}
	if err := ValidateVersion("npm", "1.2.3; rm -rf /"); err == nil {
		t.Fatal("expected version with shell metacharacters to be rejected")
	}
}
