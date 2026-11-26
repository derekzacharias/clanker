package inventory

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// AssetInfo is the raw OS description used to derive an asset and an OSV
// ecosystem identifier.
type AssetInfo struct {
	ID         string // os-release ID, e.g. ubuntu, debian, rocky
	VersionID  string // os-release VERSION_ID
	PrettyName string
	Codename   string
	Kernel     string
	Arch       string
	Container  bool
}

// DetectAsset reads /etc/os-release (or the platform equivalent) and builds the
// asset record. It never fails: a host with unreadable OS metadata is reported
// with empty fields plus a warning.
func DetectAsset(ctx context.Context, opts Options) (model.Asset, []string) {
	root := opts.Root
	if root == "" {
		root = "/"
	}
	info := AssetInfo{Arch: runtime.GOARCH, Container: fileExists(root, ".dockerenv") || fileExists(root, "run/.containerenv")}
	var warnings []string

	if platform() == "linux" {
		if path, ok := firstExisting(root, "etc/os-release", "usr/lib/os-release"); ok {
			parsed, err := parseOSRelease(path)
			if err != nil {
				warnings = append(warnings, "os-release unreadable: "+err.Error())
			} else {
				info.ID = parsed["ID"]
				info.VersionID = parsed["VERSION_ID"]
				info.PrettyName = parsed["PRETTY_NAME"]
				info.Codename = parsed["VERSION_CODENAME"]
				if info.Codename == "" {
					info.Codename = parsed["UBUNTU_CODENAME"]
				}
			}
		} else {
			warnings = append(warnings, "no os-release found; distribution-specific advisories cannot be selected")
		}
		// Kernel from /proc (no uname syscall import needed, keeps this portable).
		if b, err := os.ReadFile(filepath.Join(root, "proc/sys/kernel/osrelease")); err == nil {
			info.Kernel = strings.TrimSpace(string(b))
		}
	}

	if platform() == "windows" {
		name, version, build, err := detectWindowsOS(ctx)
		if err != nil {
			warnings = append(warnings, "windows version unreadable: "+err.Error())
		}
		info.PrettyName = strings.TrimSpace(name)
		info.VersionID = strings.TrimSpace(version)
		info.Kernel = strings.TrimSpace(build)
	}

	host, _ := os.Hostname()
	asset := model.Asset{
		Hostname:    host,
		OS:          info.PrettyName,
		OSVersion:   info.VersionID,
		OSCodename:  info.Codename,
		Kernel:      info.Kernel,
		Arch:        info.Arch,
		DistroID:    info.ID,
		IsContainer: info.Container,
	}
	if asset.OS == "" {
		asset.OS = runtime.GOOS
	}
	return asset, warnings
}

// ParseOSReleaseFields reads os-release key/value pairs from a stream.
func ParseOSReleaseFields(r io.Reader) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"'`)
	}
	return out, sc.Err()
}

// EcosystemFromFields derives the OSV ecosystem from parsed os-release fields.
func EcosystemFromFields(fields map[string]string) string {
	return OSEcosystem(AssetInfo{ID: fields["ID"], VersionID: fields["VERSION_ID"]})
}

// ParseOSReleaseFieldsPath is kept for callers with a file path.
func parseOSRelease(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		v = strings.Trim(v, `"'`)
		out[strings.TrimSpace(k)] = v
	}
	return out, sc.Err()
}

// OSEcosystem maps a distribution to the ecosystem string used by OSV.
//
// OSV uses distribution-specific ecosystems so that the advisory's version
// strings are the distribution's own versions. Getting this wrong is the most
// common source of false positives in Linux scanning, so unknown distributions
// return "" and the assessor records that distro advisories were not consulted.
func OSEcosystem(info AssetInfo) string {
	id := strings.ToLower(strings.TrimSpace(info.ID))
	ver := strings.TrimSpace(info.VersionID)
	switch id {
	case "ubuntu":
		if ver == "" {
			return ""
		}
		// OSV names Ubuntu releases with the LTS suffix where applicable.
		if isUbuntuLTS(ver) {
			return "Ubuntu:" + ver + ":LTS"
		}
		return "Ubuntu:" + ver
	case "debian":
		if ver == "" {
			return ""
		}
		return "Debian:" + ver
	case "alpine":
		if ver == "" {
			return ""
		}
		// OSV uses the major.minor form with a "v" prefix, e.g. Alpine:v3.19.
		parts := strings.Split(ver, ".")
		if len(parts) >= 2 {
			ver = parts[0] + "." + parts[1]
		}
		return "Alpine:v" + ver
	case "rocky", "rockylinux":
		if ver == "" {
			return ""
		}
		return "Rocky Linux:" + ver
	case "almalinux":
		if ver == "" {
			return ""
		}
		return "AlmaLinux:" + ver
	case "rhel", "redhat":
		if ver == "" {
			return "Red Hat"
		}
		return "Red Hat:" + ver
	case "centos":
		if ver == "" {
			return ""
		}
		return "CentOS:" + ver
	case "fedora":
		if ver == "" {
			return "Fedora"
		}
		return "Fedora:" + ver
	case "opensuse-leap", "opensuse", "suse", "sles":
		if ver == "" {
			return ""
		}
		return "openSUSE:" + ver
	default:
		return ""
	}
}

func isUbuntuLTS(version string) bool {
	switch version {
	case "14.04", "16.04", "18.04", "20.04", "22.04", "24.04", "26.04":
		return true
	}
	return false
}

// VendorFor returns the human-readable vendor used in reports and backport
// reasoning.
func VendorFor(info AssetInfo) string {
	switch strings.ToLower(info.ID) {
	case "ubuntu":
		return "Ubuntu"
	case "debian":
		return "Debian"
	case "rocky", "rockylinux":
		return "Rocky Linux"
	case "almalinux":
		return "AlmaLinux"
	case "rhel", "redhat":
		return "Red Hat"
	case "fedora":
		return "Fedora"
	case "opensuse", "opensuse-leap", "suse", "sles":
		return "SUSE"
	case "alpine":
		return "Alpine"
	default:
		return info.ID
	}
}

// OSPackageCollector reads the distro package database directly:
// dpkg status on Debian derivatives, rpm -qa on RPM distributions, and the APK
// installed database on Alpine. Reading distro metadata (rather than scanning
// the filesystem) is what gives us trustworthy versions and patch provenance.
type OSPackageCollector struct{}

func (c *OSPackageCollector) Name() string { return "os_packages" }

func (c *OSPackageCollector) Collect(ctx context.Context, opts Options) ([]model.Package, error) {
	root := opts.Root
	if root == "" {
		root = "/"
	}
	asset, _ := DetectAsset(ctx, opts)
	info := AssetInfo{ID: asset.DistroID, VersionID: asset.OSVersion, Codename: asset.OSCodename}
	eco := OSEcosystem(info)
	vendor := VendorFor(info)

	if path, ok := firstExisting(root, "var/lib/dpkg/status", "usr/var/lib/dpkg/status"); ok {
		pkgs, err := ParseDpkgStatus(path, eco, vendor)
		if err != nil {
			return nil, err
		}
		return pkgs, nil
	}
	if rpmAvail(ctx) {
		return CollectRPM(ctx, eco, vendor)
	}
	if path, ok := firstExisting(root, "lib/apk/db/installed"); ok {
		return ParseAPKInstalled(path, eco, vendor)
	}
	return nil, fmt.Errorf("%w: no supported package database (dpkg, rpm, apk) found", ErrUnavailable)
}

// windowsOSScript reads the one registry key Windows keeps its own identity in. Read-only.
const windowsOSScript = `$ErrorActionPreference='SilentlyContinue';
$k=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion';
[pscustomobject]@{product=$k.ProductName; display=$k.DisplayVersion; build=$k.CurrentBuild;
  major=$k.CurrentMajorVersionNumber; minor=$k.CurrentMinorVersionNumber; ubr=$k.UBR} |
  ConvertTo-Json -Compress`

// windowsOSRunner runs PowerShell; a variable so tests can inject a fake.
var windowsOSRunner = func(ctx context.Context, script string) ([]byte, error) {
	return run(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
}

// detectWindowsOS returns the product name, release and full build.
//
// An asset that says only "windows" cannot be matched against anything: Windows advisories are
// keyed by build, and the dashboard's OS column is how a human tells two machines apart. The
// build is reported as major.minor.build.UBR, which is what a patch level actually is.
func detectWindowsOS(ctx context.Context) (name, version, build string, err error) {
	out, err := windowsOSRunner(ctx, windowsOSScript)
	if err != nil {
		return "", "", "", err
	}
	return parseWindowsOSInfo(out)
}

func parseWindowsOSInfo(raw []byte) (name, version, build string, err error) {
	var info struct {
		Product string `json:"product"`
		Display string `json:"display"`
		Build   string `json:"build"`
		Major   any    `json:"major"`
		Minor   any    `json:"minor"`
		UBR     any    `json:"ubr"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(raw))), &info); err != nil {
		return "", "", "", err
	}
	name = strings.TrimSpace(info.Product)
	version = strings.TrimSpace(info.Display)
	build = strings.TrimSpace(info.Build)
	// Windows reports the build as a bare number ("26100") plus a separate update revision.
	// Compose the version the rest of the world uses: major.minor.build.UBR, using the numbers
	// the registry itself provides rather than assuming 10.0.
	if build != "" {
		major, minor := numberString(info.Major), numberString(info.Minor)
		if major != "" && minor != "" {
			build = major + "." + minor + "." + build
		}
		switch ubr := numberString(info.UBR); {
		case ubr != "":
			build = build + "." + ubr
		}
	}
	name, _ = WindowsMarketingName(name, build)
	return name, version, build, nil
}

// WindowsMarketingName corrects the registry's product name using the build number.
//
// Windows 11 machines commonly report ProductName = "Windows 10 Pro": Microsoft never updated that
// key for many SKUs, and every tool that trusts it mislabels the OS. The build is authoritative —
// 22000 and above is Windows 11 (21H2=22000, 22H2=22621, 23H2=22631, 24H2=26100) — except for
// Server, whose builds overlap Windows 11 (Server 2025 is also 26100) but which is named correctly.
//
// Getting this wrong is not cosmetic: the advisory matcher selects Microsoft's product by family
// and release, so a Windows 11 host labelled "Windows 10 Version 23H2" matches nothing and silently
// reports zero missing updates.
func WindowsMarketingName(product, build string) (string, bool) {
	name := strings.TrimSpace(product)
	if name == "" {
		return name, false
	}
	upper := strings.ToUpper(name)
	if strings.Contains(upper, "SERVER") {
		return name, false
	}
	// The build string is composed as major.minor.build[.UBR]; take the third component.
	parts := strings.Split(strings.TrimSpace(build), ".")
	if len(parts) < 3 {
		return name, false
	}
	buildNumber, err := strconv.Atoi(parts[2])
	if err != nil || buildNumber < 22000 {
		return name, false
	}
	if strings.HasPrefix(upper, "WINDOWS 10") {
		return "Windows 11" + name[len("Windows 10"):], true
	}
	return name, false
}

// numberString renders a JSON number or string without a type assertion mess.
func numberString(v any) string {
	switch n := v.(type) {
	case float64:
		return fmt.Sprintf("%d", int(n))
	case string:
		return strings.TrimSpace(n)
	}
	return ""
}
