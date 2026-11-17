package ticketing

import (
	"fmt"
	"regexp"
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

// RecipeFor builds the fix/verify/rollback block for a finding.
//
// Inputs are the ones the ticket already has: package, installed version, fixed version and
// ecosystem. If any of them is missing or looks unsafe, the result is an unsupported recipe
// with the reason, and the ticket renders guidance instead of commands.
func RecipeFor(f Finding) Recipe {
	pkg := strings.TrimSpace(f.Product)
	fixed := strings.TrimSpace(f.FixedVersion)
	installed := strings.TrimSpace(f.InstalledVersion)

	if pkg == "" {
		return Recipe{Caution: "The scanner did not record a package name, so no command is suggested."}
	}
	family, manager := ecosystemFamily(f.Ecosystem)
	if family == "" {
		return Recipe{Caution: fmt.Sprintf("No package manager is known for ecosystem %q, so no command is suggested. Follow the advisory or the team runbook.", f.Ecosystem)}
	}
	if fixed == "" {
		return Recipe{Manager: manager, Caution: "The advisory publishes no fixed version, so no upgrade command is suggested. Check the advisory for a fix or mitigation."}
	}
	if !safe(pkg) || !safeVersion(fixed) || (installed != "" && !safeVersion(installed)) {
		return Recipe{Manager: manager, Caution: "The package or version string contains characters this generator will not put in a shell command. Use the advisory or the runbook."}
	}

	switch family {
	case "deb":
		r := Recipe{
			Supported: true, Manager: "apt",
			Fix:    []string{"sudo apt-get update", fmt.Sprintf("sudo apt-get install --only-upgrade %s=%s", pkg, fixed)},
			Verify: []string{fmt.Sprintf("dpkg-query -W -f='${Version}\\n' %s", pkg)},
			Caution: "Assumes the fixed version is published in a repository this host already uses. " +
				"If apt reports that the version is unavailable, the distribution has not shipped it yet — " +
				"check the advisory for a backport or mitigation instead of forcing it.",
		}
		if installed != "" {
			r.Rollback = []string{fmt.Sprintf("sudo apt-get install %s=%s", pkg, installed)}
		}
		return r
	case "rpm":
		r := Recipe{
			Supported: true, Manager: "dnf",
			Fix:    []string{"sudo dnf --refresh upgrade " + pkg},
			Verify: []string{fmt.Sprintf("rpm -q --qf '%%{VERSION}-%%{RELEASE}\\n' %s", pkg)},
			Caution: fmt.Sprintf("Upgrades to the newest version the enabled repositories carry (advisory fixed version: %s). "+
				"If the host pins versions, use `sudo dnf upgrade %s-%s` or your config management instead.", fixed, pkg, fixed),
		}
		if installed != "" {
			r.Rollback = []string{fmt.Sprintf("sudo dnf downgrade %s-%s", pkg, installed)}
		}
		return r
	case "apk":
		r := Recipe{
			Supported: true, Manager: "apk",
			Fix:     []string{"sudo apk update", fmt.Sprintf("sudo apk add --upgrade %s=%s", pkg, fixed)},
			Verify:  []string{fmt.Sprintf("apk info -v %s", pkg)},
			Caution: "Alpine pins exact versions in its repositories; if the version is not offered, run `sudo apk upgrade` and re-scan.",
		}
		if installed != "" {
			r.Rollback = []string{fmt.Sprintf("sudo apk add %s=%s", pkg, installed)}
		}
		return r
	case "zypper":
		return Recipe{
			Supported: true, Manager: "zypper",
			Fix:     []string{"sudo zypper refresh", "sudo zypper update " + pkg},
			Verify:  []string{fmt.Sprintf("rpm -q %s", pkg)},
			Caution: "Updates to the version the enabled repositories carry.",
		}
	case "brew":
		return Recipe{
			Supported: true, Manager: "brew",
			Fix:     []string{"brew update", "brew upgrade " + pkg},
			Verify:  []string{fmt.Sprintf("brew info %s | head -1", pkg)},
			Caution: "Homebrew does not pin versions by default; the newest formula is installed.",
		}
	case "pip":
		r := Recipe{
			Supported: true, Manager: "pip",
			Fix:     []string{fmt.Sprintf("python3 -m pip install --upgrade '%s==%s'", pkg, fixed)},
			Verify:  []string{fmt.Sprintf("python3 -m pip show %s | grep -i '^Version:'", pkg)},
			Caution: "Installs into the interpreter the command resolves to. Inside a virtualenv, drop `sudo` and use the environment's pip; the application may pin this dependency in a lockfile that must be updated instead.",
		}
		if installed != "" {
			r.Rollback = []string{fmt.Sprintf("python3 -m pip install '%s==%s'", pkg, installed)}
		}
		return r
	case "npm":
		r := Recipe{
			Supported: true, Manager: "npm",
			Fix:     []string{fmt.Sprintf("npm install --save-exact %s@%s", pkg, fixed)},
			Verify:  []string{fmt.Sprintf("npm ls %s --depth=0", pkg)},
			Caution: "Run this in the project that depends on the package, not globally, unless the host genuinely uses a global install. Commit the resulting lockfile.",
		}
		if installed != "" {
			r.Rollback = []string{fmt.Sprintf("npm install --save-exact %s@%s", pkg, installed)}
		}
		return r
	case "gem":
		r := Recipe{
			Supported: true, Manager: "gem",
			Fix:     []string{fmt.Sprintf("gem update %s --version %s", pkg, fixed)},
			Verify:  []string{fmt.Sprintf("gem list %s --exact", pkg)},
			Caution: "If the application uses Bundler, update the Gemfile and run `bundle update` instead.",
		}
		if installed != "" {
			r.Rollback = []string{fmt.Sprintf("gem install %s --version %s", pkg, installed)}
		}
		return r
	case "cargo":
		r := Recipe{
			Supported: true, Manager: "cargo",
			Fix:     []string{fmt.Sprintf("cargo update -p %s --precise %s", pkg, fixed)},
			Verify:  []string{fmt.Sprintf("cargo tree -p %s | head -5", pkg)},
			Caution: "Updates Cargo.lock; the project still has to be rebuilt and redeployed.",
		}
		if installed != "" {
			r.Rollback = []string{fmt.Sprintf("cargo update -p %s --precise %s", pkg, installed)}
		}
		return r
	case "gomod":
		r := Recipe{
			Supported: true, Manager: "go",
			Fix:     []string{fmt.Sprintf("go get %s@v%s", pkg, strings.TrimPrefix(fixed, "v"))},
			Verify:  []string{"go list -m all | grep " + pkg},
			Caution: "Updates go.mod for the module you run this in; rebuild and redeploy afterwards.",
		}
		if installed != "" {
			r.Rollback = []string{fmt.Sprintf("go get %s@v%s", pkg, strings.TrimPrefix(installed, "v"))}
		}
		return r
	case "maven":
		return Recipe{
			Supported: true, Manager: "maven",
			Fix:     []string{},
			Verify:  []string{fmt.Sprintf("mvn dependency:tree -Dincludes=%s", pkg)},
			Caution: fmt.Sprintf("Maven dependencies are declared in the project's pom.xml: set the version to %s there and rebuild. No command is suggested because it would edit a build file.", fixed),
		}
	case "nuget":
		return Recipe{
			Supported: true, Manager: "nuget",
			Fix:     []string{fmt.Sprintf("dotnet add package %s --version %s", pkg, fixed)},
			Verify:  []string{fmt.Sprintf("dotnet list package | grep -i %s", pkg)},
			Caution: "Run in the project directory; commit the updated project file.",
		}
	case "image":
		return Recipe{
			Supported: false, Manager: "image",
			Caution: fmt.Sprintf("This finding is inside a container image. Rebuild the image with %s %s and redeploy the container — patching a running container does not change the image it will restart from.", pkg, fixed),
		}
	}
	return Recipe{Caution: "No recipe is defined for this ecosystem."}
}

// AccessBlock is how a person reaches the host, rendered into the ticket.
type AccessBlock struct {
	Host      string
	SSHUser   string
	SSHHost   string
	SSHJump   string
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
	if jump := strings.TrimSpace(a.SSHJump); jump != "" && safe(jump) {
		return fmt.Sprintf("ssh -J %s %s@%s", jump, a.SSHUser, host)
	}
	return fmt.Sprintf("ssh %s@%s", a.SSHUser, host)
}

// HasAccess reports whether anything useful can be said about reaching the host.
func (a AccessBlock) HasAccess() bool {
	return a.SSHCommand() != "" || strings.TrimSpace(a.Runbook) != ""
}
