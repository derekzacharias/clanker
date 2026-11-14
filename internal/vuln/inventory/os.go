package inventory

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
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
