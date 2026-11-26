package ticketing

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Remediation recipes.
//
// The rule that shaped this file: a generated command is only better than no command if it is
// right. So a recipe is produced only when the ecosystem maps to a known package manager and
// the advisory publishes a fixed version; otherwise the ticket says "no command" and points at
// the advisory or the team's runbook. Every recipe carries the same warning, because the tool
// cannot know whether a host pins versions, uses a private mirror, or is managed by config
// management that would overwrite a manual change.
//
// Nothing here executes anything. The commands are text for a human to review and paste.

// Recipe is the copy-paste block for one finding.
type Recipe struct {
	// Supported is false when no defensible command exists for this ecosystem.
	Supported bool
	// Manager names the package manager the commands assume ("apt", "dnf", "apk", ...).
	Manager string
	Fix     []string
	Verify  []string
	// Rollback reverts to the version that is installed today.
	Rollback []string
	// Caution explains what this recipe deliberately does not handle.
	Caution string
}

// safeToken limits package names and versions to characters that cannot break out of a shell
// word or a SQL-ish argument. Package names legitimately contain . + - _ @ / : and are
// case-insensitive; anything else (spaces, quotes, $, ;, backticks) means the data is not what
// it claims to be, and the recipe is refused instead of escaped-and-hoped.
var safeToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+@/-]*$`)

// Versions additionally allow `~` (Debian pre-release ordering) and `:` (epoch). Neither can
// break out of a shell word; spaces, quotes, `$`, backticks and separators still cannot appear.
var safeVersionToken = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+@~:/-]*$`)

func safe(s string) bool {
	return safeToken.MatchString(strings.TrimSpace(s))
}

func safeVersion(s string) bool {
	return safeVersionToken.MatchString(strings.TrimSpace(s))
}

// ecosystemFamily maps the scanner's ecosystem label onto a package manager.
//
// Matching is on the label the scanner already records (distribution name, or the language
// registry), so nothing new has to be trusted at ticket time.
func ecosystemFamily(ecosystem string) (family string, installedBy string) {
	eco := strings.ToLower(strings.TrimSpace(ecosystem))
	switch {
	case eco == "":
		return "", ""
	// Images are checked first: `container:alpine` is an Alpine package inside an image, and
	// patching a running container is not the fix — rebuilding the image is.
	case strings.Contains(eco, "container"), strings.Contains(eco, "image"), strings.Contains(eco, "docker"):
		return "image", "image"
	case strings.Contains(eco, "ubuntu"), strings.Contains(eco, "debian"), strings.Contains(eco, "raspbian"):
		return "deb", "apt"
	case strings.Contains(eco, "rhel"), strings.Contains(eco, "red hat"), strings.Contains(eco, "centos"),
		strings.Contains(eco, "rocky"), strings.Contains(eco, "alma"), strings.Contains(eco, "fedora"),
		strings.Contains(eco, "amazon"), strings.Contains(eco, "oracle linux"):
		return "rpm", "dnf"
	case strings.Contains(eco, "alpine"):
		return "apk", "apk"
	case strings.Contains(eco, "suse"), strings.Contains(eco, "opensuse"):
		return "zypper", "zypper"
	case strings.Contains(eco, "brew"), strings.Contains(eco, "homebrew"), strings.Contains(eco, "macos"):
		return "brew", "brew"
	case strings.Contains(eco, "pypi"), strings.Contains(eco, "pip"), strings.Contains(eco, "python"):
		return "pip", "pip"
	case strings.Contains(eco, "npm"), strings.Contains(eco, "node"), strings.Contains(eco, "yarn"):
		return "npm", "npm"
	case strings.Contains(eco, "rubygems"), strings.Contains(eco, "gem"):
		return "gem", "gem"
	case strings.Contains(eco, "cargo"), strings.Contains(eco, "crates"):
		return "cargo", "cargo"
	case strings.Contains(eco, "go module"), strings.Contains(eco, "gomod"), eco == "go":
		return "gomod", "go"
	case strings.Contains(eco, "maven"), strings.Contains(eco, "gradle"):
		return "maven", "maven"
	case strings.Contains(eco, "nuget"), strings.Contains(eco, "dotnet"):
		return "nuget", "nuget"
	}
	return "", ""
}

// RecipeFor is a flattened view of the plan, kept for callers that want the commands without
// the surrounding work order. The plan is the source of truth; this only reshapes it.
func RecipeFor(f Finding) Recipe {
	p := BuildPlan(f)
	r := Recipe{Manager: p.Manager, Caution: p.Reason}
	r.Supported = p.Status == StatusVerified || p.Status == StatusReview

	// The fix commands are the ones in the "apply" step: connection and inspection steps are
	// not a fix.
	for _, st := range p.Steps {
		if strings.HasPrefix(st.Title, "Apply") || strings.HasPrefix(st.Title, "Upgrade") {
			for _, c := range st.Commands {
				r.Fix = append(r.Fix, c.Lines...)
			}
		}
	}
	for _, c := range p.Verify {
		r.Verify = append(r.Verify, c.Lines...)
	}
	for _, c := range p.Rollback {
		r.Rollback = append(r.Rollback, c.Lines...)
	}
	if len(p.Warnings) > 0 {
		if r.Caution != "" {
			r.Caution += " "
		}
		r.Caution += strings.Join(p.Warnings, " ")
	}
	return r
}

// AccessBlock is how a person reaches the host, rendered into the ticket.
type AccessBlock struct {
	Host    string
	SSHUser string
	SSHHost string
	SSHJump string
	// SSHPort is the nonstandard port, 0 meaning the default.
	SSHPort   int
	Runbook   string
	Privilege string
}

// SSHCommand is the ready-to-paste connection line, or empty when no user is recorded.
//
// With a jump host it produces `ssh -J bastion user@host`, which is what an operator would
// type; without one, the plain form. Nothing is invented: no user, no command.
func (a AccessBlock) SSHCommand() string {
	if strings.TrimSpace(a.SSHUser) == "" || !safe(a.SSHUser) {
		return ""
	}
	host := strings.TrimSpace(a.SSHHost)
	if host == "" {
		host = strings.TrimSpace(a.Host)
	}
	if host == "" || !safe(host) {
		return ""
	}
	port := portSuffix(strconv.Itoa(a.SSHPort))
	if jump := strings.TrimSpace(a.SSHJump); jump != "" && safe(jump) {
		return fmt.Sprintf("ssh%s -J %s %s@%s", port, jump, a.SSHUser, host)
	}
	return fmt.Sprintf("ssh%s %s@%s", port, a.SSHUser, host)
}

// HasAccess reports whether anything useful can be said about reaching the host.
func (a AccessBlock) HasAccess() bool {
	return a.SSHCommand() != "" || strings.TrimSpace(a.Runbook) != ""
}

// sha256Prefix hashes a short value for change detection (ticket content digests).
func sha256Prefix(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	raw := make([]byte, 8)
	copy(raw, sum[:8])
	return []byte(hex.EncodeToString(raw))
}
