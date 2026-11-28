// Package inventory collects installed software from an endpoint.
//
// Design rules enforced here:
//   - Every collector is optional and reports why it could not run; the
//     inventory never silently pretends to be complete.
//   - Collection is read-only and unprivileged by default. Collectors only read
//     package-manager metadata or invoke read-only package-manager queries.
//   - No filesystem walks outside well-known package-manager locations, so
//     application secrets and user documents are never touched.
package inventory

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/pkgurl"
)

// Options controls what the runner collects and where it reads from. Root and
// Exec exist so tests can run against fixtures instead of the host.
type Options struct {
	Root               string
	IncludePython      bool
	IncludeNode        bool
	IncludeGo          bool
	IncludeRust        bool
	IncludeRuby        bool
	IncludeWindowsApps bool
	// IncludeContainers collects container images when a read-only Docker
	// socket/CLI is available and authorised.
	IncludeContainers bool
}

// DefaultOptions collects the package-manager inventories that are cheap and
// read-only. Language ecosystems are opt-out because they can be large.
func DefaultOptions() Options {
	return Options{
		Root:          "/",
		IncludePython: true,
		IncludeNode:   true,
		IncludeGo:     false,
		IncludeRust:   false,
		IncludeRuby:   true,
	}
}

// Collector is one inventory source.
type Collector interface {
	// Name is a stable identifier used in reports and skipped-check records.
	Name() string
	// Collect returns packages. Returning (nil, ErrUnavailable) records a
	// skipped check rather than an error, because a missing package manager is
	// a coverage gap, not a scan failure.
	Collect(ctx context.Context, opts Options) ([]model.Package, error)
}

// ErrUnavailable marks a collector that cannot run on this host.
var ErrUnavailable = errors.New("collector unavailable")

// StateCollector is a collector that also reports platform servicing state (Windows today):
// identity, installed updates, applicable missing updates, pending reboot. It is separate from
// Collector because state is not a package list, and folding it into []Package would lose the
// difference between "no update is missing" and "the update service was not asked".
type StateCollector interface {
	CollectState(ctx context.Context, opts Options) (model.WindowsState, error)
}

// Runner executes collectors and assembles an inventory.
type Runner struct {
	Collectors []Collector
}

// Run collects everything and returns the inventory plus non-fatal problems.
func (r *Runner) Run(ctx context.Context, opts Options) (model.Inventory, error) {
	asset, assetWarnings := DetectAsset(ctx, opts)
	inv := model.Inventory{Asset: asset, CollectedAt: time.Now().UTC(), Warnings: assetWarnings}

	var (
		pkgs    []model.Package
		windows *model.WindowsState
	)
	for _, c := range r.Collectors {
		if c == nil {
			continue
		}
		got, err := c.Collect(ctx, opts)
		switch {
		case errors.Is(err, ErrUnavailable):
			inv.Skipped = append(inv.Skipped, model.SkippedCheck{
				Check:  c.Name(),
				Reason: err.Error(),
			})
		case err != nil:
			inv.Warnings = append(inv.Warnings, fmt.Sprintf("%s: %v", c.Name(), err))
		}
		for i := range got {
			normalizePackage(&got[i])
		}
		pkgs = append(pkgs, got...)
		if sc, ok := c.(StateCollector); ok {
			state, err := sc.CollectState(ctx, opts)
			if err != nil {
				inv.Warnings = append(inv.Warnings, c.Name()+" state: "+err.Error())
				continue
			}
			windows = &state
		}
	}
	inv.Windows = windows
	pkgs, dropped := dropDistroProvidedPython(pkgs)
	if dropped > 0 {
		// Say it out loud: this is a deliberate coverage decision, not a silent gap.
		inv.Skipped = append(inv.Skipped, model.SkippedCheck{
			Check: "python_packages_in_distro_paths",
			Reason: fmt.Sprintf("%d Python distributions under the distribution-managed path are reported "+
				"through the OS package manager instead; counting them twice produced findings against "+
				"a package that pip does not own", dropped),
		})
	}
	inv.Packages = Dedupe(pkgs)
	return inv, nil
}

// dropDistroProvidedPython removes Python distributions that belong to the operating system.
//
// On Debian/Ubuntu, Python's own site.getsitepackages() includes /usr/lib/python3/dist-packages,
// which is where dpkg installs every python3-* package. Reading it as PyPI data reports one
// installed package twice — once truthfully from dpkg, once as a language dependency — and the
// second copy produces a `pip install` recommendation for something pip cannot upgrade without
// breaking the system package.
//
// The rule is narrow on purpose: only paths under a distribution-managed prefix, and only when
// an OS package manager actually covered the host (so a mixed or unusual image keeps coverage).
func dropDistroProvidedPython(pkgs []model.Package) ([]model.Package, int) {
	distroManaged := false
	for _, p := range pkgs {
		switch p.Source {
		case model.OriginDpkg, model.OriginAPK, model.OriginRPM:
			distroManaged = true
		}
	}
	if !distroManaged {
		return pkgs, 0
	}
	out := make([]model.Package, 0, len(pkgs))
	dropped := 0
	for _, p := range pkgs {
		if p.Ecosystem == model.EcosystemPyPI && isDistroPythonPath(p.Origin) {
			dropped++
			continue
		}
		out = append(out, p)
	}
	return out, dropped
}

// isDistroPythonPath reports whether a Python metadata path belongs to the OS.
//
// /usr/lib/python3/dist-packages is Debian/Ubuntu's convention for distribution packages.
// /usr/lib/python3.11/site-packages and /usr/local/... are not: those are local installs,
// including the interpreter's own pip target, and belong to the PyPI world.
func isDistroPythonPath(origin string) bool {
	if origin == "" {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(origin))
	for _, prefix := range []string{"/usr/lib/python3/dist-packages/", "/usr/lib/python3.11/dist-packages/"} {
		if strings.HasPrefix(clean, prefix) {
			return true
		}
	}
	// Any /usr/lib/python3.X/dist-packages (X varies by release).
	if strings.HasPrefix(clean, "/usr/lib/python3.") && strings.Contains(clean, "/dist-packages/") {
		return true
	}
	return false
}

// normalizePackage fills in derived fields consistently across collectors.
func normalizePackage(p *model.Package) {
	if p.Ecosystem == "" {
		p.Ecosystem = model.EcosystemUnknown
	}
	if p.PatchStatus == "" {
		p.PatchStatus = model.PatchUnknown
	}
	if p.PURL == "" {
		p.PURL = pkgurl.BuildPURL(p.Ecosystem, p.Name, p.Version)
	}
}

// Dedupe removes exact duplicates (same ecosystem, name, version, source)
// while preserving the first occurrence's provenance. It deliberately does
// NOT merge different versions of the same package: two installed versions
// are two distinct facts.
//
// For application records (Windows desktop software), duplicates observed by
// different collection sources (registry hive vs MSI vs winget vs file
// version) are merged into one record whose EvidenceSources keeps every
// origin, so deduplication never destroys provenance.
func Dedupe(in []model.Package) []model.Package {
	seen := make(map[string]int, len(in))
	out := make([]model.Package, 0, len(in))
	for _, p := range in {
		key := strings.Join([]string{
			strings.ToLower(p.Ecosystem),
			pkgurl.NormalizeName(p.Ecosystem, p.Name),
			p.Version,
			string(p.Source),
			p.Arch,
		}, "\x00")
		if idx, ok := seen[key]; ok {
			mergePackageEvidence(&out[idx], p)
			continue
		}
		seen[key] = len(out)
		out = append(out, p)
	}
	// A second pass merges application records that differ only in source:
	// the same (name, version) seen through the registry, MSI metadata and
	// winget is one application.
	if merged := mergeAppDuplicates(out); merged != nil {
		out = merged
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Ecosystem != out[j].Ecosystem {
			return out[i].Ecosystem < out[j].Ecosystem
		}
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Version < out[j].Version
	})
	return out
}

// mergeAppDuplicates collapses application records with the same
// (ecosystem, name, version) but different sources, keeping the richest
// record and unioning evidence. Non-application packages are untouched.
func mergeAppDuplicates(in []model.Package) []model.Package {
	appKey := func(p model.Package) (string, bool) {
		if strings.ToLower(p.Ecosystem) != strings.ToLower(model.EcosystemWindows) {
			return "", false
		}
		return strings.Join([]string{
			strings.ToLower(p.Ecosystem),
			pkgurl.NormalizeName(p.Ecosystem, p.Name),
			p.Version,
		}, "\x00"), true
	}
	changed := false
	seen := map[string]int{}
	var out []model.Package
	for _, p := range in {
		key, isApp := appKey(p)
		if !isApp {
			out = append(out, p)
			continue
		}
		if idx, ok := seen[key]; ok {
			changed = true
			mergePackageEvidence(&out[idx], p)
			continue
		}
		seen[key] = len(out)
		out = append(out, p)
	}
	if !changed {
		return nil
	}
	return out
}

// mergePackageEvidence folds b's provenance into a, keeping the first
// record's identity.
func mergePackageEvidence(a *model.Package, b model.Package) {
	seen := map[string]bool{}
	for _, s := range a.EvidenceSources {
		seen[s] = true
	}
	for _, s := range b.EvidenceSources {
		if s != "" && !seen[s] {
			seen[s] = true
			a.EvidenceSources = append(a.EvidenceSources, s)
		}
	}
	// Fill gaps in the surviving record from the duplicate.
	if a.Publisher == "" {
		a.Publisher = b.Publisher
	}
	if a.Vendor == "" {
		a.Vendor = b.Vendor
	}
	if a.InstallDate == "" {
		a.InstallDate = b.InstallDate
	}
	if a.Location == "" {
		a.Location = b.Location
	}
	if a.Scope == "" {
		a.Scope = b.Scope
	}
	if a.Arch == "" {
		a.Arch = b.Arch
	}
	if a.ProductID == "" {
		a.ProductID = b.ProductID
	}
	if a.PkgManagerID == "" {
		a.PkgManagerID = b.PkgManagerID
	}
}

// run executes a read-only helper command. All call sites pass fixed arguments;
// no scanned data is ever interpolated into a command line.
func run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	out, err := cmd.Output()
	if err != nil {
		var execErr *exec.Error
		if errors.As(err, &execErr) {
			return nil, fmt.Errorf("%w: %s not found", ErrUnavailable, name)
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			msg := strings.TrimSpace(string(exitErr.Stderr))
			if msg == "" {
				msg = exitErr.Error()
			}
			// Some package managers return non-zero when an optional repo is
			// missing yet still print usable output on stdout.
			if len(out) > 0 {
				return out, nil
			}
			return nil, fmt.Errorf("%s: %s", name, msg)
		}
		return nil, err
	}
	return out, nil
}

func fileExists(root, rel string) bool {
	st, err := os.Stat(filepath.Join(root, rel))
	return err == nil && !st.IsDir()
}

func firstExisting(root string, rels ...string) (string, bool) {
	for _, rel := range rels {
		if fileExists(root, rel) {
			return filepath.Join(root, rel), true
		}
	}
	return "", false
}

func platform() string { return runtime.GOOS }

// DefaultCollectors returns the collector set appropriate to this platform.
func DefaultCollectors() []Collector {
	switch platform() {
	case "linux":
		return []Collector{
			&OSPackageCollector{},
			&PipCollector{},
			&NpmCollector{},
			&RubyGemCollector{},
		}
	case "darwin":
		return []Collector{
			&BrewCollector{},
			&PipCollector{},
			&NpmCollector{},
			&RubyGemCollector{},
		}
	case "windows":
		return []Collector{
			&WindowsRegistryCollector{},
			// Servicing state, Windows Update applicability and MSIX/Store packages. This is
			// what turns "12 desktop installers" into a Windows assessment.
			&WindowsStateCollector{},
			&PipCollector{},
			&NpmCollector{},
		}
	default:
		return []Collector{&PipCollector{}, &NpmCollector{}}
	}
}
