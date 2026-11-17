package ticketing

import (
	"fmt"
	"net"
	"regexp"
	"strings"
)

// Structured remediation.
//
// A ticket used to be a rendered string assembled while writing it. That made it impossible to
// test the *content* independently of the Markdown, and it hid the important distinction this
// file exists to encode: a plan is either verified enough to print commands, or it is not, and
// "not" has to be visible in the ticket rather than filled in with something plausible.
//
// BuildPlan decides; Render(plan) is display only. Nothing here executes anything.

// Status says how much the operator should trust the plan.
type Status string

const (
	// StatusVerified: a known package manager and a published fixed version — commands can be
	// generated for this platform.
	StatusVerified Status = "verified"
	// StatusReview: commands exist but something about them needs a human (a rebuild, a
	// reboot, a pin the repository may not carry).
	StatusReview Status = "requires_review"
	// StatusNoFix: the advisory publishes no fixed version.
	StatusNoFix Status = "no_fix"
	// StatusUnsupported: this asset type cannot be patched the way the finding implies.
	StatusUnsupported Status = "unsupported"
	// StatusManual: there is no defensible command; the operator gets safe inspection steps.
	StatusManual Status = "needs_investigation"
)

// Label is the human phrase used in the ticket and the UI.
func (s Status) Label() string {
	switch s {
	case StatusVerified:
		return "Verified remediation available"
	case StatusReview:
		return "Remediation available — review first"
	case StatusNoFix:
		return "No confirmed fix published"
	case StatusUnsupported:
		return "Remediation not supported for this asset type"
	default:
		return "Manual investigation required"
	}
}

// Command is one copy-paste block. Lang selects the fence: bash, powershell, dockerfile, yaml.
type Command struct {
	Lang  string   `json:"lang"`
	Lines []string `json:"lines"`
}

// Step is a numbered action in the work order.
type Step struct {
	Title      string    `json:"title"`
	Detail     string    `json:"detail,omitempty"`
	Commands   []Command `json:"commands,omitempty"`
	Disruptive bool      `json:"disruptive,omitempty"`
}

// SystemInfo is the affected system as the scanner knows it. Empty means "not recorded", and
// the ticket says so rather than filling the gap.
type SystemInfo struct {
	Hostname  string `json:"hostname"`
	AssetID   string `json:"asset_id"`
	IP        string `json:"ip,omitempty"`
	OS        string `json:"os,omitempty"`
	OSVersion string `json:"os_version,omitempty"`
	Distro    string `json:"distro,omitempty"`
	Arch      string `json:"arch,omitempty"`
	// SSHManaged is true when this asset type is reached over SSH.
	SSHManaged bool `json:"ssh_managed"`
}

// Plan is the whole work order, independent of its Markdown rendering.
type Plan struct {
	Status     Status `json:"status"`
	Confidence string `json:"confidence"` // high | medium | low | none
	// Reason explains a non-verified status in one sentence.
	Reason string `json:"reason,omitempty"`

	System    SystemInfo  `json:"system"`
	Access    AccessBlock `json:"access"`
	CVE       string      `json:"cve"`
	Severity  string      `json:"severity"`
	Package   string      `json:"package,omitempty"`
	Installed string      `json:"installed_version,omitempty"`
	Fixed     string      `json:"fixed_version,omitempty"`
	Advisory  string      `json:"advisory,omitempty"`
	// Manager is the package manager the commands assume (apt, dnf, pip, ...).
	Manager string `json:"manager,omitempty"`

	Steps         []Step      `json:"steps"`
	Verify        []Command   `json:"verify,omitempty"`
	VerifyNote    string      `json:"verify_note,omitempty"`
	Rollback      []Command   `json:"rollback,omitempty"`
	RollbackNote  string      `json:"rollback_note,omitempty"`
	Prerequisites []string    `json:"prerequisites,omitempty"`
	Warnings      []string    `json:"warnings,omitempty"`
	Disruptive    bool        `json:"disruptive"`
	References    []Reference `json:"references,omitempty"`

	// Provenance, so the ticket can be traced back and deduplicated.
	FindingKey  string     `json:"finding_key,omitempty"`
	ReportID    string     `json:"report_id,omitempty"`
	FirstSeen   string     `json:"first_seen,omitempty"`
	LastSeen    string     `json:"last_seen,omitempty"`
	Explanation string     `json:"explanation,omitempty"`
	Evidence    []Evidence `json:"evidence,omitempty"`

	// advisoryText is the vendor/distribution wording, rendered separately from generated
	// commands so a reader can always tell which is which.
	advisoryText string
}

// Unsupported platform classes get their own wording, because "we cannot help you" is a
// conclusion the ticket has to justify.
const (
	kindDeb       = "linux-deb"
	kindRPM       = "linux-rpm"
	kindAPK       = "linux-apk"
	kindZypper    = "linux-zypper"
	kindBrew      = "macos-brew"
	kindWindows   = "windows"
	kindContainer = "container"
	kindApp       = "application"
	kindAppliance = "appliance"
)

// classify decides the platform and the tool that applies the fix.
//
// The ecosystem label is checked before the OS, because a PyPI finding on an Ubuntu host is an
// application dependency (fix the application, redeploy) and not an apt upgrade — getting this
// wrong is how tickets tell people to `apt install` a package that apt has never heard of.
func classifyAsset(f Finding) (kind, manager, lang string) {
	eco := strings.ToLower(strings.TrimSpace(f.Ecosystem))
	osName := strings.ToLower(strings.TrimSpace(f.OS + " " + f.OSVersion))

	// Language ecosystems first: they follow the application, not the host.
	switch {
	case strings.Contains(eco, "pypi"), strings.Contains(eco, "pip"), strings.Contains(eco, "python"):
		return kindApp, "pip", "bash"
	case strings.Contains(eco, "npm"), strings.Contains(eco, "node"), strings.Contains(eco, "yarn"):
		return kindApp, "npm", "bash"
	case strings.Contains(eco, "rubygems"), strings.Contains(eco, "gem"):
		return kindApp, "gem", "bash"
	case strings.Contains(eco, "cargo"), strings.Contains(eco, "crates"):
		return kindApp, "cargo", "bash"
	case strings.Contains(eco, "go module"), strings.Contains(eco, "gomod"), eco == "go":
		return kindApp, "go", "bash"
	case strings.Contains(eco, "maven"), strings.Contains(eco, "gradle"):
		return kindApp, "maven", "bash"
	case strings.Contains(eco, "nuget"), strings.Contains(eco, "dotnet"):
		return kindApp, "nuget", "bash"
	}
	// Container images: the fix is a rebuild, never a shell inside a running container.
	if strings.Contains(eco, "container") || strings.Contains(eco, "image") || strings.Contains(eco, "docker") ||
		strings.HasPrefix(strings.ToLower(strings.TrimSpace(f.Asset)), "image:") {
		return kindContainer, "image", "dockerfile"
	}
	// Windows (OS-based, or a Windows package label).
	if strings.Contains(osName, "windows") || strings.Contains(eco, "windows") || strings.Contains(eco, "winget") {
		return kindWindows, "winget", "powershell"
	}
	// Linux distributions, by the label the scanner recorded.
	switch {
	case strings.Contains(eco, "ubuntu"), strings.Contains(eco, "debian"), strings.Contains(eco, "raspbian"):
		return kindDeb, "apt", "bash"
	case strings.Contains(eco, "rhel"), strings.Contains(eco, "red hat"), strings.Contains(eco, "centos"),
		strings.Contains(eco, "rocky"), strings.Contains(eco, "alma"), strings.Contains(eco, "fedora"):
		return kindRPM, "dnf", "bash"
	case strings.Contains(eco, "amazon"):
		return kindRPM, "dnf", "bash"
	case strings.Contains(eco, "alpine"):
		return kindAPK, "apk", "bash"
	case strings.Contains(eco, "suse"), strings.Contains(eco, "opensuse"):
		return kindZypper, "zypper", "bash"
	case strings.Contains(eco, "brew"), strings.Contains(eco, "homebrew"), strings.Contains(osName, "macos"):
		return kindBrew, "brew", "bash"
	}
	// Fall back to the OS name when the ecosystem says nothing useful.
	switch {
	case strings.Contains(osName, "ubuntu"), strings.Contains(osName, "debian"):
		return kindDeb, "apt", "bash"
	case strings.Contains(osName, "rhel"), strings.Contains(osName, "centos"), strings.Contains(osName, "fedora"):
		return kindRPM, "dnf", "bash"
	case strings.Contains(osName, "alpine"):
		return kindAPK, "apk", "bash"
	case strings.Contains(osName, "macos"), strings.Contains(osName, "darwin"):
		return kindBrew, "brew", "bash"
	}
	return kindAppliance, "", "bash"
}

// kernelish reports packages whose upgrade needs a reboot to take effect.
var kernelish = regexp.MustCompile(`(?i)^(linux-image|linux-server|linux-generic|linux-headers|linux-firmware|kernel|kernel-core|kernel-default|linux-kernel)`)

// serviceBearing reports packages where a service restart usually follows the upgrade.
var serviceBearing = regexp.MustCompile(`(?i)^(openssl|libssl|openssh|systemd|glibc|libc6|nginx|apache2|httpd|postgresql|mariadb|mysql|docker|containerd|sudo|polkit)`)

// BuildPlan turns a finding into a work order, or into an honest statement that it cannot.
func BuildPlan(f Finding) Plan {
	kind, manager, lang := classifyAsset(f)
	p := Plan{
		CVE:       strings.TrimSpace(f.VulnerabilityID),
		Severity:  strings.ToUpper(firstNonEmpty(f.EffectiveSeverity, f.Severity, "unknown")),
		Package:   strings.TrimSpace(f.Product),
		Installed: strings.TrimSpace(f.InstalledVersion),
		Fixed:     strings.TrimSpace(f.FixedVersion),
		Advisory:  firstNonEmpty(f.RemediationSource, f.AdvisoryLabel()),
		Manager:   manager,
		Access:    f.Access,
		System: SystemInfo{
			Hostname:  firstNonEmpty(f.Hostname, f.Asset),
			AssetID:   f.Asset,
			OS:        strings.TrimSpace(f.OS),
			OSVersion: strings.TrimSpace(f.OSVersion),
			Distro:    distroLabel(f),
			Arch:      f.Arch,
			// SSH is offered only where it is the way in: a Linux/Unix *host*. Pseudo-assets
			// (sbom:, scope:, image:, the scanning host itself) are not machines you log into,
			// and printing "ssh <user>@sbom:sbom.json" would be nonsense.
			SSHManaged: isSSHKind(kind) && !isPseudoAsset(f.Asset),
		},
		References:  f.References,
		FindingKey:  f.FindingKey,
		ReportID:    f.ReportID,
		FirstSeen:   f.FirstSeen,
		LastSeen:    f.LastSeen,
		Explanation: f.Explanation,
		Evidence:    f.Evidence,
	}
	if strings.TrimSpace(f.RemediationText) != "" {
		p.advisoryText = f.RemediationText
	}
	// An IP is shown only when one was actually recorded (the SSH host override, when it is an
	// address). Guessing from a hostname would be inventing data.
	if ip := net.ParseIP(strings.TrimSpace(f.Access.SSHHost)); ip != nil {
		p.System.IP = ip.String()
	}

	// Without a package name there is nothing to upgrade; a command with an empty slot is worse
	// than no command.
	if p.Package == "" {
		p.Status = StatusManual
		p.Confidence = "none"
		p.Reason = "The scanner did not record a package name for this finding, so no upgrade command can be built."
		p.Steps = []Step{{
			Title:    "Identify the affected component",
			Detail:   "Read-only checks to find which component the advisory applies to on this host.",
			Commands: inspectionCommands(kind, "", lang),
		}}
		return p
	}

	// Safety gate before anything is composed: a package name or version that could break out of
	// a shell word is not data this generator will touch. It becomes a manual ticket instead.
	if (p.Package != "" && !safe(p.Package)) ||
		(p.Fixed != "" && !safeVersion(p.Fixed)) ||
		(p.Installed != "" && !safeVersion(p.Installed)) {
		p.Status = StatusManual
		p.Confidence = "none"
		p.Reason = "The package or version string recorded for this finding is not a value that belongs in a shell " +
			"command, so no command was generated."
		p.Steps = []Step{{
			Title:    "Check the package by hand",
			Detail:   "Read-only. Confirm the affected package and version on the host before changing anything.",
			Commands: inspectionCommands(kind, p.Package, lang),
		}}
		p.Warnings = append(p.Warnings, "Clanker Guard refused to build a command from this finding's fields; "+
			"treat the recorded package metadata as suspect and check it on the host.")
		return p
	}

	// No fixed version: say so, and give read-only inspection instead of a fix.
	if p.Fixed == "" {
		p.Status = StatusNoFix
		p.Confidence = "none"
		p.Reason = "The advisory this finding came from publishes no fixed version, so no upgrade is suggested."
		p.Steps = []Step{{
			Title: "Confirm the finding before changing anything",
			Detail: "Read-only checks. They tell you whether the package is installed and which build this host " +
				"actually has; distribution backports can mean the CVE is already fixed under a different version.",
			Commands: inspectionCommands(kind, p.Package, lang),
		}}
		p.Warnings = append(p.Warnings, "No fixed version is published. Check the vendor advisory for a fix, "+
			"mitigation or workaround; a generic upgrade may not address this finding.")
		if kind == kindDeb || kind == kindRPM {
			p.Warnings = append(p.Warnings, "If your distribution has already shipped a fix, its package changelog names "+
				"this CVE. Install the current candidate build only once the changelog confirms it, then re-scan.")
		}
		p.VerifyNote = verificationCaveat(kind, manager)
		return p
	}

	// Container images: rebuild, never patch in place.
	if kind == kindContainer {
		p.Status = StatusReview
		p.Confidence = "medium"
		p.Reason = "The affected package is inside a container image. The fix is a rebuilt image and a redeployed container, " +
			"not a change to a running container."
		p.Steps = []Step{{
			Title: "Rebuild the image with the fixed package",
			Detail: fmt.Sprintf("Add a build step to the image that upgrades %s to at least %s, then rebuild. "+
				"Patching a running container does not change the image it will restart from.", p.Package, p.Fixed),
			Commands: []Command{{Lang: "dockerfile", Lines: []string{
				"# in the image's Dockerfile, before the application layer",
				fmt.Sprintf("RUN <your base-distro package manager> install -y %s=%s", p.Package, p.Fixed),
			}}},
		}, {
			Title:  "Rebuild, push and redeploy",
			Detail: "Substitute your registry, tag and deployment mechanism.",
			Commands: []Command{{Lang: "bash", Lines: []string{
				"docker build -t <registry>/<image>:<new-tag> .",
				"docker push <registry>/<image>:<new-tag>",
				"# then update the deployment to reference <new-tag> and let it roll out",
			}}},
		}}
		p.Verify = []Command{{Lang: "bash", Lines: []string{
			"# after the rollout, list the package inside the *deployed* container:",
			fmt.Sprintf("docker run --rm --entrypoint <pkg-query> <registry>/<image>:<new-tag> %s", p.Package),
			"# then re-scan the image from Clanker Guard",
		}}}
		p.RollbackNote = "Keep the previous image tag: redeploying it is the rollback."
		p.Prerequisites = []string{"Access to the image's build pipeline and registry",
			"A deployment you can roll back to the previous tag"}
		p.Warnings = append(p.Warnings, "The exact package manager inside the image is unknown here; adjust the RUN line to the base image's distribution.")
		return p
	}

	if kind == kindAppliance {
		p.Status = StatusUnsupported
		p.Confidence = "none"
		p.Reason = "This asset type is not a system Clanker Guard can generate patch commands for, so it is handed over " +
			"with the evidence rather than with a guess."
		p.Steps = []Step{{
			Title:    "Collect the facts the vendor will ask for",
			Detail:   "Read-only. Send these with the ticket to the asset owner or vendor.",
			Commands: inspectionCommands(kind, p.Package, lang),
		}}
		p.VerifyNote = "Verification is the vendor's confirmation plus a re-scan from Clanker Guard."
		return p
	}

	if kind == kindWindows {
		return buildWindowsPlan(p, f)
	}

	// Linux and macOS hosts, and application dependencies, all of which follow a package flow.
	cmds, verify, rollback, prereq, warn, disruptive := platformCommands(kind, manager, p)
	p.Manager = manager
	p.Steps = []Step{{
		Title:      fixStepTitle(kind),
		Detail:     fixStepDetail(kind, p),
		Commands:   cmds,
		Disruptive: disruptive,
	}}
	p.Verify = verify
	p.Rollback = rollback
	p.Prerequisites = append(p.Prerequisites, prereq...)
	p.Warnings = append(p.Warnings, warn...)
	p.Disruptive = disruptive
	p.Status = StatusVerified
	p.Confidence = "high"
	if kind == kindApp {
		// The host is not patched by these commands; the application is upgraded and redeployed.
		p.Status = StatusReview
		p.Confidence = "medium"
		p.RollbackNote = "Redeploy the previous application version if the upgrade fails; the commands above change the project, not the host."
	}
	if len(p.Rollback) == 0 {
		p.RollbackNote = rollbackAbsentNote(kind)
	}
	p.VerifyNote = verificationCaveat(kind, manager)
	return p
}

// isSSHKind reports whether a person is expected to log into this system.
func isSSHKind(kind string) bool {
	switch kind {
	case kindDeb, kindRPM, kindAPK, kindZypper, kindBrew, kindAppliance:
		return true
	}
	return false
}

// isPseudoAsset reports assets that the scanner synthesises rather than discovers.
func isPseudoAsset(asset string) bool {
	a := strings.ToLower(strings.TrimSpace(asset))
	if a == "" || a == "localhost" {
		return true
	}
	for _, prefix := range []string{"sbom:", "scope:", "image:", "container:", "file:", "tar:", "path:"} {
		if strings.HasPrefix(a, prefix) {
			return true
		}
	}
	return false
}

func distroLabel(f Finding) string {
	eco := strings.TrimSpace(f.Ecosystem)
	if i := strings.Index(eco, ":"); i > 0 && i < len(eco)-1 {
		return strings.TrimSpace(eco[i+1:])
	}
	return ""
}

// fixStepTitle names the action in the operator's language.
func fixStepTitle(kind string) string {
	switch kind {
	case kindApp:
		return "Upgrade the dependency in the project"
	case kindBrew:
		return "Upgrade the package on the host"
	default:
		return "Apply the fix on the host"
	}
}

func fixStepDetail(kind string, p Plan) string {
	switch kind {
	case kindDeb:
		return fmt.Sprintf("Installs the advisory's fixed build of %s (%s or later) from the repositories this host already uses. "+
			"Only that package is upgraded.", p.Package, p.Fixed)
	case kindRPM:
		return fmt.Sprintf("Upgrades %s from the enabled repositories (the advisory's fixed version is %s). "+
			"Only that package is upgraded; nothing else on the host changes.", p.Package, p.Fixed)
	case kindAPK:
		return fmt.Sprintf("Installs %s %s from Alpine's repositories.", p.Package, p.Fixed)
	case kindZypper:
		return fmt.Sprintf("Updates %s from the configured repositories.", p.Package)
	case kindBrew:
		return fmt.Sprintf("Upgrades %s to the current formula version.", p.Package)
	case kindApp:
		return fmt.Sprintf("Changes the dependency in the project that uses it. The new version is %s; "+
			"the application still has to be rebuilt and deployed.", p.Fixed)
	}
	return ""
}

// rollbackAbsentNote is shown when no safe automatic rollback exists.
func rollbackAbsentNote(kind string) string {
	switch kind {
	case kindDeb, kindAPK, kindApp:
		return "Previous-version commands are shown above only when the current version is known."
	case kindRPM:
		return "No automatic downgrade is suggested: on RHEL-family systems a downgrade can leave the system " +
			"unsupported. Use your snapshot or vendor procedure if the change has to be reverted."
	case kindBrew:
		return "Homebrew keeps old versions only briefly; restoring a snapshot is the reliable rollback."
	}
	return "No validated rollback procedure is known. Restore a snapshot or follow the vendor's supported procedure."
}

// verificationCaveat keeps local checks and scanner-confirmed resolution distinct.
func verificationCaveat(kind, manager string) string {
	base := "A version check is local evidence, not proof: distributions backport security fixes, so the same version " +
		"string can be patched or unpatched depending on the build. Clanker Guard only changes the finding to resolved " +
		"after a later scan no longer reports it."
	switch kind {
	case kindDeb:
		return base + " `apt-cache policy` shows which repository the candidate came from."
	case kindRPM:
		return base + " `rpm -q --changelog` shows whether the CVE appears in the package's changelog."
	case kindApp:
		return base + " Redeploy the application before re-scanning: the scanner reads the deployed artifact."
	case kindContainer:
		return base + " Re-scan the rebuilt image, not the running container."
	}
	_ = manager
	return base
}

// inspectionCommands are read-only: they help a human decide, and cannot change a system.
func inspectionCommands(kind, pkg, lang string) []Command {
	if pkg != "" && !safe(pkg) {
		// Do not interpolate a suspect value; ask the operator to substitute it.
		pkg = "<package>"
	}
	switch kind {
	case kindDeb:
		return []Command{{Lang: "bash", Lines: []string{
			fmt.Sprintf("dpkg-query -W -f='${Package} ${Version}\\n' %s", pkg),
			fmt.Sprintf("apt-cache policy %s", pkg),
			fmt.Sprintf("apt-get changelog %s 2>/dev/null | head -40   # does it name this CVE?", pkg),
			"grep -h '^deb ' /etc/apt/sources.list /etc/apt/sources.list.d/*.list 2>/dev/null | head",
		}}}
	case kindRPM:
		return []Command{{Lang: "bash", Lines: []string{
			fmt.Sprintf("rpm -q %s", pkg),
			fmt.Sprintf("rpm -q --changelog %s 2>/dev/null | head -20", pkg),
		}}}
	case kindAPK:
		return []Command{{Lang: "bash", Lines: []string{fmt.Sprintf("apk info -v %s", pkg), "cat /etc/alpine-release"}}}
	case kindWindows:
		return []Command{{Lang: "powershell", Lines: []string{
			fmt.Sprintf("Get-Package -Name '%s' | Select-Object Name,Version", pkg),
		}}}
	case kindContainer:
		return []Command{{Lang: "bash", Lines: []string{
			"# inspect the image without changing anything:",
			fmt.Sprintf("docker run --rm --entrypoint <pkg-query> <image> %s", pkg),
		}}}
	case kindBrew:
		return []Command{{Lang: "bash", Lines: []string{fmt.Sprintf("brew info %s", pkg)}}}
	}
	_ = lang
	return []Command{{Lang: "bash", Lines: []string{
		"cat /etc/os-release",
		fmt.Sprintf("command -v dpkg && dpkg -l %s; command -v rpm && rpm -q %s", pkg, pkg),
	}}}
}

// AdvisoryLabel is the advisory identifier when the finding has one, for the ticket header.
func (f Finding) AdvisoryLabel() string {
	if strings.TrimSpace(f.VulnerabilityID) == "" {
		return ""
	}
	return f.VulnerabilityID
}
