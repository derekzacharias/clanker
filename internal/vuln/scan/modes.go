package scan

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/assess"
	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/netscan"
	"github.com/bgdnvk/clanker/internal/vuln/sbom"
)

// ------------------------------------------------------------------ network ---

// runNetwork performs an authorised network assessment.
//
// Findings come from two sources, kept distinguishable in the report:
//   - configuration/exposure observations from the services themselves;
//   - CVE matches from NVD for fingerprinted products with a known version.
//
// Nothing here exploits anything: discovery is a TCP connect, fingerprinting is
// one benign request per service, and TLS is observed by handshake.
func runNetwork(ctx context.Context, opts Options) (Result, error) {
	started := opts.Now()
	if opts.Scope == nil {
		return Result{}, fmt.Errorf("network assessment requires an authorised scope")
	}

	store, err := intel.OpenStore(opts.CachePath)
	if err != nil {
		return Result{}, fmt.Errorf("open intelligence cache: %w", err)
	}
	defer store.Close()

	opts.report(Stage{Name: "discovery", Percent: 8, Detail: fmt.Sprintf("authorised scope %q", opts.Scope.Name)})
	result, err := netscan.Run(ctx, netscan.Options{
		Scope:          opts.Scope,
		Ports:          opts.TargetPorts,
		Concurrency:    opts.NetConcurrency,
		ConnectTimeout: opts.NetConnectTimeout,
		Now:            opts.Now,
	})
	if err != nil {
		return Result{}, fmt.Errorf("network discovery failed: %w", err)
	}
	opts.report(Stage{Name: "discovery", Percent: 25,
		Detail: fmt.Sprintf("%d host(s), %d service(s)", len(result.Targets), len(result.Services))})

	if len(result.Services) == 0 {
		return Result{}, fmt.Errorf(
			"no services responded in scope %q; refusing to report a clean network assessment (check the authorised ports and reachability)",
			opts.Scope.Name)
	}

	// --- CVE correlation ------------------------------------------------------
	nvd := netscan.NewNVDClient(opts.NVDAPIKey)
	lookup := opts.NVDFunc
	if lookup == nil {
		lookup = nvd.MatchCPE
	}
	now := opts.Now()
	var advisories []intel.Advisory
	var nvdFindings []model.Finding
	seenPkg := map[string]bool{}
	var nvdErrors []string
	for _, svc := range result.Services {
		pkg, ok := netscan.PackageFor(svc)
		if !ok {
			continue // no version observed: no correlation, no guessing
		}
		key := pkg.Name + "@" + pkg.Version
		if seenPkg[key] {
			continue
		}
		seenPkg[key] = true
		if opts.Offline || netscan.CacheFresh(store, pkg, 24*time.Hour, now) {
			// Rebuild findings from the cached advisories instead of skipping:
			// a cache hit must not turn into "no findings".
			nvdFindings = append(nvdFindings, netscan.FindingsFromCache(store, svc, now)...)
			continue
		}
		matches, err := lookup(ctx, svc.CPE)
		if err != nil {
			// An upstream failure must never be reported as "no vulnerabilities".
			nvdErrors = append(nvdErrors, fmt.Sprintf("NVD lookup for %s failed: %v", svc.CPE, err))
			continue
		}
		for _, m := range matches {
			advisories = append(advisories, netscan.AdvisoryFor(pkg, m, now))
			nvdFindings = append(nvdFindings, netscan.FindingForAdvisory(svc, m, now))
		}
	}
	opts.report(Stage{Name: "intelligence", Percent: 55,
		Detail: fmt.Sprintf("%d NVD advisories for %d fingerprinted service(s)", len(advisories), len(seenPkg))})
	if len(advisories) > 0 {
		if err := store.SaveAdvisories(ctx, advisories); err != nil {
			nvdErrors = append(nvdErrors, "could not cache NVD advisories: "+err.Error())
		}
	}

	// --- inventory: one pseudo-package per fingerprinted service ---------------
	hosts := map[string][]netscan.Service{}
	var hostOrder []string
	for _, svc := range result.Services {
		if _, ok := hosts[svc.Host]; !ok {
			hostOrder = append(hostOrder, svc.Host)
		}
		hosts[svc.Host] = append(hosts[svc.Host], svc)
	}
	sort.Strings(hostOrder)

	inv := model.Inventory{
		Asset: model.Asset{
			Hostname:  scopeAssetName(opts.Scope),
			OS:        "network scope",
			OSVersion: fmt.Sprintf("%d host(s)", len(hostOrder)),
			Arch:      "tcp",
		},
		CollectedAt: now,
	}
	var packages []model.Package
	for _, host := range hostOrder {
		for _, svc := range hosts[host] {
			if pkg, ok := netscan.PackageFor(svc); ok {
				pkg.Arch = fmt.Sprintf("%s:%d", svc.Host, svc.Port)
				packages = append(packages, pkg)
			}
		}
	}
	inv.Packages = packages
	if len(inv.Packages) == 0 {
		inv.Warnings = append(inv.Warnings,
			"no service exposed a usable product/version, so no CVE correlation was possible")
	}
	if len(nvdErrors) > 0 {
		inv.Warnings = append(inv.Warnings, nvdErrors...)
	}

	// --- configuration findings, attributed to the scanned host ---------------
	extra := append([]model.Finding(nil), nvdFindings...)
	for _, f := range result.Findings {
		extra = append(extra, f.ToModelFinding(f.Host))
	}

	limits := []string{
		"network assessment is non-destructive: discovery, banner/HTTP/TLS observation and one protocol probe per service",
		"CVE correlation uses fingerprint evidence only; a service that hides its version cannot be correlated",
		"NVD CPE matching identifies advisories for the observed version and does not prove exploitability",
	}
	if opts.Offline {
		limits = append(limits, "offline mode: no NVD queries were made; cached matches only")
	}

	return finishWith(ctx, store, opts, started, pipelineInput{
		Mode:          "network",
		Inventory:     inv,
		ExtraFindings: extra,
		Scope:         opts.Scope,
		ExtraSources: []string{
			fmt.Sprintf("network discovery (%d services on %d hosts)", len(result.Services), len(hostOrder)),
			"NVD CPE matching",
		},
		ExtraLimitations: limits,
		ExtraErrors:      nvdErrors,
		Incomplete:       len(nvdErrors) > 0,
		CoverageHint: &model.Coverage{
			PackagesInspected: len(result.Services),
			Sources:           nil,
			Limitations:       limits,
		},
	})
}

// scopeAssetName is the asset identifier for a network assessment. It names the
// scope (not a single host) because one report can cover several targets.
func scopeAssetName(sc *model.Scope) string {
	name := strings.TrimSpace(sc.Name)
	if name == "" {
		name = "network"
	}
	return "scope:" + name
}

// --------------------------------------------------------------------- SBOM ---

// runSBOM correlates a software bill of materials, dependency manifest or
// container image against the advisory data.
func runSBOM(ctx context.Context, opts Options) (Result, error) {
	started := opts.Now()
	store, err := intel.OpenStore(opts.CachePath)
	if err != nil {
		return Result{}, fmt.Errorf("open intelligence cache: %w", err)
	}
	defer store.Close()

	inv := model.Inventory{CollectedAt: opts.Now()}
	var subject string
	var warnings []string
	var limitations []string

	if strings.TrimSpace(opts.Image) != "" {
		opts.report(Stage{Name: "inventory", Percent: 10, Detail: "reading container image layers"})
		size, err := sbom.ImageInspectSize(ctx, opts.DockerPath, opts.Image)
		if err != nil {
			return Result{}, err
		}
		limit := opts.MaxImageBytes
		if limit <= 0 {
			limit = 4 << 30 // 4 GiB
		}
		if size > limit {
			return Result{}, fmt.Errorf("image %s is %d bytes, above the %d byte limit; export an SBOM instead",
				opts.Image, size, limit)
		}
		res, err := sbom.ScanImage(ctx, opts.Image, sbom.ImageOptions{DockerPath: opts.DockerPath})
		if err != nil {
			return Result{}, err
		}
		inv.Packages = res.Packages
		warnings = append(warnings, res.Warnings...)
		subject = opts.Image
		inv.Asset = model.Asset{
			Hostname:  "image:" + subject,
			OS:        firstNonEmptyString(res.OS, "container image"),
			OSVersion: "",
			Arch:      "container",
			DistroID:  distroID(res.OS),
		}
		limitations = append(limitations,
			"container inventory comes from distribution package databases inside the image layers; RPM-based images are not supported yet")
	} else {
		opts.report(Stage{Name: "inventory", Percent: 10, Detail: "parsing bill of materials"})
		doc, err := sbom.ParseFile(opts.SBOMPath)
		if err != nil {
			return Result{}, err
		}
		inv.Packages = doc.Packages
		warnings = append(warnings, doc.Warnings...)
		subject = firstNonEmptyString(doc.Subject, doc.Path)
		inv.Asset = model.Asset{
			Hostname: "sbom:" + baseName(doc.Path),
			OS:       fmt.Sprintf("SBOM (%s)", doc.Format),
		}
		limitations = append(limitations,
			"SBOM assessment reflects the document's declared components; drift between the document and the deployed software is not detectable here")
	}

	if len(inv.Packages) == 0 {
		return Result{}, fmt.Errorf("no versioned components found in %s; refusing to report a clean assessment", subject)
	}
	inv.Warnings = append(inv.Warnings, warnings...)
	opts.report(Stage{Name: "inventory", Percent: 30, Detail: fmt.Sprintf("%d component(s)", len(inv.Packages))})

	return finishWith(ctx, store, opts, started, pipelineInput{
		Mode:         "sbom",
		Inventory:    inv,
		ExtraSources: []string{"software bill of materials"},
		ExtraLimitations: append(limitations,
			"component versions are taken from the document; ecosystems without public advisory coverage are listed as not covered"),
	})
}

func distroID(ecosystem string) string {
	switch {
	case strings.HasPrefix(ecosystem, "Ubuntu"):
		return "ubuntu"
	case strings.HasPrefix(ecosystem, "Debian"):
		return "debian"
	case strings.HasPrefix(ecosystem, "Alpine"):
		return "alpine"
	}
	return ""
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, "/\\"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

var _ = assess.SupportsOSV
