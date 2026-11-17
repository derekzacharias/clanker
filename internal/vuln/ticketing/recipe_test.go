package ticketing

import (
	"strings"
	"testing"
)

// A recipe is only produced when it can be right: known manager, published fixed version,
// and strings that are safe to put in a shell.
func TestRecipesPerEcosystem(t *testing.T) {
	cases := []struct {
		eco, pkg, installed, fixed string
		wantManager                string
		wantFixContains            string
		supported                  bool
	}{
		{"Ubuntu:22.04", "openssl", "3.0.2", "3.0.13-1ubuntu1", "apt", "apt-get install --only-upgrade openssl=3.0.13-1ubuntu1", true},
		{"Debian:12", "libssl3", "3.0.11", "3.0.13-1~deb12u1", "apt", "libssl3=3.0.13-1~deb12u1", true},
		{"RHEL:9", "openssl", "3.0.7", "3.0.7-27", "dnf", "dnf upgrade --refresh openssl", true},
		{"Alpine:v3.21", "libxslt", "1.1.42-r2", "1.1.42-r3", "apk", "apk add --upgrade libxslt=1.1.42-r3", true},
		{"PyPI", "requests", "2.31.0", "2.32.4", "pip", "pip install --upgrade 'requests==2.32.4'", true},
		{"npm", "lodash", "4.17.20", "4.17.21", "npm", "npm install --save-exact lodash@4.17.21", true},
		{"Go", "golang.org/x/net", "0.10.0", "0.23.0", "go", "go get golang.org/x/net@v0.23.0", true},
		{"crates.io", "tokio", "1.20.0", "1.24.2", "cargo", "cargo update -p tokio --precise 1.24.2", true},
		{"RubyGems", "rack", "2.2.3", "2.2.8", "gem", "gem update rack --version 2.2.8", true},
		{"container:alpine", "openssl", "3.0.2", "3.0.13", "image", "", true},
		{"AcmeOS:1", "blob", "1.0", "1.1", "", "", false},
	}
	for _, tc := range cases {
		f := Finding{Product: tc.pkg, InstalledVersion: tc.installed, FixedVersion: tc.fixed, Ecosystem: tc.eco}
		r := RecipeFor(f)
		if r.Supported != tc.supported {
			t.Fatalf("%s: supported = %v, want %v (%s)", tc.eco, r.Supported, tc.supported, r.Caution)
		}
		if tc.supported {
			if r.Manager != tc.wantManager {
				t.Fatalf("%s: manager = %q, want %q", tc.eco, r.Manager, tc.wantManager)
			}
			joined := strings.Join(r.Fix, "\n")
			if tc.wantFixContains != "" && !strings.Contains(joined, tc.wantFixContains) {
				t.Fatalf("%s: fix commands = %q, missing %q", tc.eco, joined, tc.wantFixContains)
			}
			if len(r.Verify) == 0 {
				t.Fatalf("%s: no verification command", tc.eco)
			}
			// RPM-family hosts deliberately get no downgrade command: a downgrade can leave the
			// system in an unsupported state, so the ticket says so instead.
			if r.Manager != "dnf" && r.Manager != "zypper" && r.Manager != "image" && len(r.Rollback) == 0 {
				t.Fatalf("%s: no rollback command", tc.eco)
			}
			if r.Manager == "dnf" && len(r.Rollback) > 0 {
				t.Fatalf("%s: generated an unsafe downgrade", tc.eco)
			}
		}
	}
}

// The generator refuses rather than escapes: a package name that is not a package name is a
// sign the data is wrong, and a ticket is not the place to find out.
func TestRecipeRefusesUnsafeOrUnknownInput(t *testing.T) {
	cases := map[string]Finding{
		"no fixed version": {Product: "openssl", Ecosystem: "Ubuntu:22.04", InstalledVersion: "3.0.2"},
		"no package":       {Ecosystem: "Ubuntu:22.04", FixedVersion: "3.0.13"},
		"shell injection in package": {Product: "openssl; rm -rf /", Ecosystem: "Ubuntu:22.04",
			FixedVersion: "3.0.13"},
		"shell injection in version": {Product: "openssl", Ecosystem: "Ubuntu:22.04",
			FixedVersion: "3.0.13$(curl evil)"},
		"unknown ecosystem": {Product: "openssl", Ecosystem: "AcmeOS:1", FixedVersion: "3.0.13"},
	}
	for name, f := range cases {
		r := RecipeFor(f)
		if r.Supported {
			t.Fatalf("%s: produced a supported recipe (%v)", name, r.Fix)
		}
		if strings.TrimSpace(r.Caution) == "" {
			t.Fatalf("%s: no explanation for the missing recipe", name)
		}
		for _, line := range r.Fix {
			if strings.Contains(line, "rm -rf") || strings.Contains(line, "$(") {
				t.Fatalf("%s: unsafe content reached the command list: %q", name, line)
			}
		}
	}
}

// Access lines are derived, not invented: no user means no ssh command.
func TestAccessBlockProducesAConnectionLine(t *testing.T) {
	plain := AccessBlock{Host: "web01", SSHUser: "deploy"}
	if got := plain.SSHCommand(); got != "ssh deploy@web01" {
		t.Fatalf("plain = %q", got)
	}
	viaJump := AccessBlock{Host: "web01", SSHUser: "deploy", SSHJump: "bastion.prod"}
	if got := viaJump.SSHCommand(); got != "ssh -J bastion.prod deploy@web01" {
		t.Fatalf("jump = %q", got)
	}
	override := AccessBlock{Host: "image:learnlinux/web:dev", SSHUser: "deploy", SSHHost: "10.0.0.5"}
	if got := override.SSHCommand(); got != "ssh deploy@10.0.0.5" {
		t.Fatalf("host override = %q", got)
	}
	none := AccessBlock{Host: "web01"}
	if got := none.SSHCommand(); got != "" {
		t.Fatalf("no user should produce no command, got %q", got)
	}
	unsafe := AccessBlock{Host: "web01", SSHUser: "deploy;curl evil"}
	if got := unsafe.SSHCommand(); got != "" {
		t.Fatalf("unsafe user produced a command: %q", got)
	}
}

// A nonstandard port must appear in the command an administrator pastes; the default must not
// add noise.
func TestSSHCommandHonoursNonstandardPort(t *testing.T) {
	withPort := AccessBlock{Host: "web01", SSHUser: "deploy", SSHPort: 2222}
	if got := withPort.SSHCommand(); got != "ssh -p 2222 deploy@web01" {
		t.Fatalf("port = %q", got)
	}
	viaJump := AccessBlock{Host: "web01", SSHUser: "deploy", SSHPort: 2222, SSHJump: "bastion"}
	if got := viaJump.SSHCommand(); got != "ssh -p 2222 -J bastion deploy@web01" {
		t.Fatalf("port + jump = %q", got)
	}
	defaultPort := AccessBlock{Host: "web01", SSHUser: "deploy", SSHPort: 22}
	if got := defaultPort.SSHCommand(); got != "ssh deploy@web01" {
		t.Fatalf("default port should not be printed: %q", got)
	}
}
