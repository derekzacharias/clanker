package ticketing

import (
	"fmt"
	"strconv"
	"strings"
)

// Platform command sets.
//
// Each function returns commands for one package manager, plus the prerequisites, warnings and
// disruption flags that belong with it. The rule everywhere: upgrade the named package only,
// never the whole system, and never a command whose syntax this platform does not accept.

func platformCommands(kind, manager string, p Plan) (cmds []Command, verify []Command, rollback []Command,
	prereq []string, warn []string, disruptive bool) {

	lang := "bash"
	pkg, fixed, installed := p.Package, p.Fixed, p.Installed

	switch manager {
	case "apt":
		cmds = []Command{{Lang: lang, Lines: []string{
			"sudo apt-get update",
			fmt.Sprintf("sudo apt-get install --only-upgrade %s=%s", pkg, fixed),
		}}}
		verify = []Command{{Lang: lang, Lines: []string{
			fmt.Sprintf("dpkg-query -W -f='${Version}\\n' %s", pkg),
			fmt.Sprintf("apt-cache policy %s", pkg),
		}}}
		if installed != "" {
			rollback = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("sudo apt-get install %s=%s", pkg, installed)}}}
		}
		prereq = []string{"Root or sudo on the host", "The advisory's fixed version available in the configured repositories"}
		warn = append(warn, "If apt reports the fixed version as unavailable, the distribution has not published it for this release; "+
			"check the advisory for a backport or mitigation instead of forcing another repository.")

	case "dnf":
		cmds = []Command{{Lang: lang, Lines: []string{
			fmt.Sprintf("sudo dnf upgrade --refresh %s", pkg),
		}}}
		verify = []Command{{Lang: lang, Lines: []string{
			fmt.Sprintf("rpm -q %s", pkg),
			fmt.Sprintf("rpm -q --changelog %s | head -20", pkg),
		}}}
		prereq = []string{"Root or sudo on the host", "The fixed build available in an enabled repository"}
		warn = append(warn, fmt.Sprintf("This upgrades %s to the newest build the enabled repositories carry (advisory fix: %s). "+
			"If the host pins versions, use `sudo dnf upgrade %s-%s` or your configuration management instead.", pkg, fixed, pkg, fixed))
		if kind == kindRPM && kernelish.MatchString(pkg) {
			disruptive = true
		}

	case "apk":
		cmds = []Command{{Lang: lang, Lines: []string{
			"sudo apk update",
			fmt.Sprintf("sudo apk add --upgrade %s=%s", pkg, fixed),
		}}}
		verify = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("apk info -v %s", pkg)}}}
		if installed != "" {
			rollback = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("sudo apk add %s=%s", pkg, installed)}}}
		}
		prereq = []string{"Root or sudo on the host"}

	case "zypper":
		cmds = []Command{{Lang: lang, Lines: []string{
			"sudo zypper refresh",
			fmt.Sprintf("sudo zypper update %s", pkg),
		}}}
		verify = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("rpm -q %s", pkg)}}}
		prereq = []string{"Root or sudo on the host"}

	case "brew":
		cmds = []Command{{Lang: lang, Lines: []string{"brew update", fmt.Sprintf("brew upgrade %s", pkg)}}}
		verify = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("brew info %s | head -3", pkg)}}}
		warn = append(warn, "Homebrew installs the newest formula; it does not pin the advisory's exact version.")

	case "pip":
		cmds = []Command{{Lang: lang, Lines: []string{
			fmt.Sprintf("python3 -m pip install --upgrade '%s==%s'", pkg, fixed),
		}}}
		verify = []Command{{Lang: lang, Lines: []string{
			fmt.Sprintf("python3 -m pip show %s | grep -i '^Version:'", pkg),
		}}}
		if installed != "" {
			rollback = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("python3 -m pip install '%s==%s'", pkg, installed)}}}
		}
		prereq = []string{"Run inside the project's virtualenv or the interpreter that runs the application",
			"Update the project's lockfile if it has one"}
		warn = append(warn, "The scanner reads the deployed artifact: rebuilding and redeploying is part of the fix, not an afterthought.")

	case "npm":
		cmds = []Command{{Lang: lang, Lines: []string{
			fmt.Sprintf("npm install --save-exact %s@%s", pkg, fixed),
		}}}
		verify = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("npm ls %s --depth=0", pkg)}}}
		if installed != "" {
			rollback = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("npm install --save-exact %s@%s", pkg, installed)}}}
		}
		prereq = []string{"Run in the project that depends on the package", "Commit the updated lockfile"}
		warn = append(warn, "A global install is only correct when the host genuinely runs the package globally.")

	case "gem":
		cmds = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("gem update %s --version %s", pkg, fixed)}}}
		verify = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("gem list %s --exact", pkg)}}}
		if installed != "" {
			rollback = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("gem install %s --version %s", pkg, installed)}}}
		}
		prereq = []string{"Prefer `bundle update` when the application uses Bundler"}

	case "cargo":
		cmds = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("cargo update -p %s --precise %s", pkg, fixed)}}}
		verify = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("cargo tree -p %s | head -5", pkg)}}}
		if installed != "" {
			rollback = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("cargo update -p %s --precise %s", pkg, installed)}}}
		}
		prereq = []string{"Rebuild and redeploy after updating Cargo.lock"}

	case "go":
		cmds = []Command{{Lang: lang, Lines: []string{
			fmt.Sprintf("go get %s@v%s", pkg, strings.TrimPrefix(fixed, "v")),
		}}}
		verify = []Command{{Lang: lang, Lines: []string{"go list -m all | grep " + pkg}}}
		if installed != "" {
			rollback = []Command{{Lang: lang, Lines: []string{
				fmt.Sprintf("go get %s@v%s", pkg, strings.TrimPrefix(installed, "v")),
			}}}
		}
		prereq = []string{"Run in the module that depends on the package", "Rebuild and redeploy after updating go.mod"}

	case "nuget":
		cmds = []Command{{Lang: lang, Lines: []string{
			fmt.Sprintf("dotnet add package %s --version %s", pkg, fixed),
		}}}
		verify = []Command{{Lang: lang, Lines: []string{fmt.Sprintf("dotnet list package | grep -i %s", pkg)}}}
		prereq = []string{"Run in the project directory", "Commit the updated project file"}

	case "maven":
		// No command: editing a pom.xml is a project change, not a shell step.
		verify = []Command{{Lang: lang, Lines: []string{
			fmt.Sprintf("mvn dependency:tree -Dincludes=%s", pkg),
		}}}
		prereq = []string{
			fmt.Sprintf("Set the %s version to %s in the project's pom.xml (or the parent BOM)", pkg, fixed),
			"Rebuild and redeploy the application",
		}
		warn = append(warn, "Maven versions are declared in the build file; there is no single command that upgrades a dependency safely.")
	}

	if kernelish.MatchString(pkg) {
		disruptive = true
		warn = append(warn, "This is a kernel package: the running kernel is not replaced until the host reboots. "+
			"Schedule a reboot and confirm the rebooted kernel version afterwards.")
	}
	if serviceBearing.MatchString(pkg) {
		warn = append(warn, fmt.Sprintf("%s backs running services. Restart the affected service (or reboot) for the "+
			"upgrade to take effect, and check service health afterwards.", pkg))
	}
	if majorVersionJump(installed, fixed) {
		warn = append(warn, fmt.Sprintf("This crosses a major version (%s → %s). Read the release notes before applying it: "+
			"application behaviour can change, not just the patch level.", installed, fixed))
	}
	return cmds, verify, rollback, prereq, warn, disruptive
}

// majorVersionJump reports whether installed and fixed differ in their first numeric component.
func majorVersionJump(installed, fixed string) bool {
	a, b := majorOf(installed), majorOf(fixed)
	if a == "" || b == "" {
		return false
	}
	return a != b
}

func majorOf(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	end := 0
	for end < len(v) && v[end] >= '0' && v[end] <= '9' {
		end++
	}
	if end == 0 {
		return ""
	}
	return v[:end]
}

// buildWindowsPlan keeps PowerShell on Windows and never emits an SSH line there.
func buildWindowsPlan(p Plan, f Finding) Plan {
	p.Status = StatusVerified
	p.Confidence = "medium"
	p.System.SSHManaged = false
	p.Manager = "winget"

	p.Steps = []Step{{
		Title: "Apply the fix on the Windows host",
		Detail: "Run these in an elevated PowerShell window on the affected host (RDP, WinRM or the console). " +
			"Clanker Guard does not assume SSH is enabled on Windows.",
		Commands: []Command{{Lang: "powershell", Lines: []string{
			fmt.Sprintf("# identify the installed build first"),
			fmt.Sprintf("Get-Package -Name '%s' | Select-Object Name,Version", p.Package),
			fmt.Sprintf("winget upgrade --id '%s' --version %s --silent", p.Package, p.Fixed),
		}}},
	}}
	p.Verify = []Command{{Lang: "powershell", Lines: []string{
		fmt.Sprintf("Get-Package -Name '%s' | Select-Object Name,Version", p.Package),
	}}}
	p.RollbackNote = "winget does not reliably downgrade a package. Restore a snapshot or use the vendor's uninstall/reinstall procedure."
	p.Prerequisites = []string{"An elevated (administrator) PowerShell session", "The host reachable over RDP or WinRM"}
	p.Warnings = append(p.Warnings,
		"Package identifiers differ from Linux names; if winget cannot find it, the fix may be a vendor installer or Windows Update.")
	if kernelish.MatchString(p.Package) {
		p.Disruptive = true
		p.Warnings = append(p.Warnings, "This requires a reboot to take effect.")
	}
	p.VerifyNote = verificationCaveat(kindWindows, "winget")
	return p
}

// portSuffix turns an SSH port into the flag a command needs, ignoring the default.
func portSuffix(port string) string {
	n, err := strconv.Atoi(strings.TrimSpace(port))
	if err != nil || n <= 0 || n == 22 {
		return ""
	}
	return " -p " + strconv.Itoa(n)
}
