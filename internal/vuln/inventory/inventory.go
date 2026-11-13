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

// Runner executes collectors and assembles an inventory.
type Runner struct {
	Collectors []Collector
}

// Run collects everything and returns the inventory plus non-fatal problems.
func (r *Runner) Run(ctx context.Context, opts Options) (model.Inventory, error) {
	asset, assetWarnings := DetectAsset(ctx, opts)
	inv := model.Inventory{Asset: asset, CollectedAt: time.Now().UTC(), Warnings: assetWarnings}

	var pkgs []model.Package
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
	}
	inv.Packages = Dedupe(pkgs)
	return inv, nil
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

// Dedupe removes exact duplicates (same ecosystem, name, version, source) while
// preserving the first occurrence's provenance. It deliberately does NOT merge
// different versions of the same package: two installed versions are two
// distinct facts.
func Dedupe(in []model.Package) []model.Package {
	seen := make(map[string]struct{}, len(in))
	out := make([]model.Package, 0, len(in))
	for _, p := range in {
		key := strings.Join([]string{
			strings.ToLower(p.Ecosystem),
			pkgurl.NormalizeName(p.Ecosystem, p.Name),
			p.Version,
			string(p.Source),
			p.Arch,
		}, "\x00")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
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
			&PipCollector{},
			&NpmCollector{},
		}
	default:
		return []Collector{&PipCollector{}, &NpmCollector{}}
	}
}
