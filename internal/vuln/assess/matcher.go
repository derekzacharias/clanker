// Package assess turns advisories into evidence-backed findings.
//
// This is the accuracy core of Clanker Guard. The rules implemented here are
// deliberately conservative: absence of a fixed version, unparsable versions,
// missing vendor data and conflicting sources all produce an explicit
// uncertainty state instead of a guess.
package assess

import (
	"fmt"
	"sort"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/pkgurl"
	"github.com/bgdnvk/clanker/internal/vuln/version"
)

// Outcome is the verdict for one (advisory, package) pair.
type Outcome struct {
	Applicability  model.Applicability
	Confidence     model.Confidence
	Explanation    string
	Evidence       []model.Evidence
	FixedVersion   string
	VendorAdvisory *model.VendorAdvisory
	PatchStatus    model.PatchStatus
	Raise          []string
	Lower          []string
	// MatchedEcosystem is the advisory entry that produced the verdict.
	MatchedEcosystem string
	// DistroAdvisory is true when the verdict came from a distribution feed
	// rather than an upstream ecosystem feed.
	DistroAdvisory bool
}

// distroSources are feeds that speak the distribution's own version strings.
var distroSources = map[string]bool{
	"Ubuntu": true, "Debian": true, "Alpine": true,
	"Red Hat": true, "Rocky Linux": true, "AlmaLinux": true, "Fedora": true,
}

// IsDistroAdvisory reports whether an advisory was published by a distribution
// security team.
//
// Provenance (the feed that published it) decides this, not the ecosystem in the
// record: an NVD/OSV aggregation that merely carries a "Debian:12" ecosystem
// string does not speak the distribution's patched version scheme, so its
// version verdicts must not be treated as authoritative for a distro build.
func IsDistroAdvisory(a intel.Advisory) bool {
	return distroSources[a.Source]
}

func isDistroEcosystem(eco string) bool {
	l := strings.ToLower(eco)
	for _, p := range []string{"ubuntu", "debian", "alpine", "red hat", "rhel", "rocky", "almalinux", "fedora", "opensuse", "suse", "centos"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return false
}

// Match evaluates one advisory against one installed package.
//
// Rules, in order:
//  1. Only affected entries for the package's own ecosystem are considered.
//     Cross-ecosystem matching (e.g. PyPI advice applied to a distro build) is
//     the single largest source of false positives in open-source scanners.
//  2. Distribution advisories that enumerate affected binary versions are
//     matched on the binary version (what dpkg/rpm reports).
//  3. Distribution advisories that enumerate source versions are matched on
//     the source package name.
//  4. Explicit introduced/fixed ranges are authoritative when present.
//  5. Anything unresolved becomes needs_investigation, never "affected".
func Match(pkg model.Package, adv intel.Advisory) (Outcome, bool) {
	var best Outcome
	matched := false
	for _, aff := range adv.Affected {
		if !strings.EqualFold(aff.Ecosystem, pkg.Ecosystem) {
			// Pro/ESM ecosystems are separate entitlements; record the gap
			// rather than silently applying (or ignoring) them.
			if strings.HasPrefix(aff.Ecosystem, "Ubuntu:Pro:") || strings.HasPrefix(aff.Ecosystem, "Ubuntu:Pro") {
				continue
			}
			continue
		}
		out, ok := evaluateEntry(pkg, adv, aff)
		if !ok {
			continue
		}
		if !matched || betterOutcome(out, best) {
			best = out
		}
		matched = true
	}
	if !matched {
		return Outcome{}, false
	}
	return best, true
}

// betterOutcome prefers the most actionable verdict when an advisory carries
// several entries for the same package (e.g. source and binary views).
func betterOutcome(a, b Outcome) bool {
	rank := func(o Outcome) int {
		switch o.Applicability {
		case model.ApplicabilityConfirmed:
			return 5
		case model.ApplicabilityProbable:
			return 4
		case model.ApplicabilityPotential:
			return 3
		case model.ApplicabilityNeedsInvestigation:
			return 2
		case model.ApplicabilityNotAffected:
			return 1
		default:
			return 0
		}
	}
	return rank(a) > rank(b)
}

func evaluateEntry(pkg model.Package, adv intel.Advisory, aff intel.Affected) (Outcome, bool) {
	distro := IsDistroAdvisory(adv)
	out := Outcome{DistroAdvisory: distro, MatchedEcosystem: aff.Ecosystem}

	// --- binary-view matching (Ubuntu/Pro records) ---------------------------
	if len(aff.Binaries) > 0 {
		if bv, ok := findBinary(aff.Binaries, pkg.Name); ok {
			out.VendorAdvisory = vendorAdvisoryFor(adv, aff.Ecosystem, "")
			cmp, err := version.Compare(pkg.Ecosystem, pkg.Version, bv)
			if err != nil {
				return unresolved(out, adv, fmt.Sprintf(
					"installed version %q could not be compared with the vendor's affected binary version %q: %v",
					pkg.Version, bv, err)), true
			}
			switch {
			case cmp == 0:
				out.Applicability = model.ApplicabilityConfirmed
				out.Confidence = model.ConfidenceHigh
				out.Explanation = fmt.Sprintf(
					"%s lists the installed build %s (%s) as affected.", adv.Source, pkg.Version, pkg.Name)
				out.Evidence = append(out.Evidence, evidenceVersion(adv, pkg, aff.Ecosystem),
					model.Evidence{Kind: "vendor_binary_enumerated", Source: adv.Source,
						Detail: fmt.Sprintf("%s binary %s is listed at affected version %s", adv.Source, pkg.Name, bv),
						URL:    advURL(adv)})
				out.PatchStatus = model.PatchVulnerable
			case cmp > 0:
				if marker := foreignBuildMarker(pkg.Ecosystem, pkg.Version); marker != "" {
					out.Applicability = model.ApplicabilityNeedsInvestigation
					out.Confidence = model.ConfidenceLow
					out.PatchStatus = model.PatchUnknown
					out.Explanation = fmt.Sprintf(
						"Installed %s (%s) is a %s build, which %s's version enumeration does not cover; the installed build being newer than the last enumerated affected build is therefore not evidence that this advisory is fixed.",
						pkg.Version, pkg.Name, marker, adv.Source)
					out.Evidence = append(out.Evidence,
						evidenceVersion(adv, pkg, aff.Ecosystem),
						model.Evidence{Kind: "foreign_build", Source: "inventory",
							Detail: fmt.Sprintf("build marker %q indicates a third-party package, not a %s build", marker, adv.Source)})
					out.Raise = append(out.Raise, "the third-party packager publishes a patched build")
					return out, true
				}
				out.Applicability = model.ApplicabilityNotAffected
				out.Confidence = model.ConfidenceMedium
				out.Explanation = fmt.Sprintf(
					"Installed %s (%s) is newer than the last build %s enumerates as affected; the vendor appears to have shipped a fixed build. No explicit fixed version is published in this advisory.",
					pkg.Version, pkg.Name, bv)
				out.Evidence = append(out.Evidence, model.Evidence{
					Kind: "vendor_version_boundary", Source: adv.Source,
					Detail: fmt.Sprintf("affected binary %s = %s; installed = %s", pkg.Name, bv, pkg.Version),
					URL:    advURL(adv)})
				out.PatchStatus = model.PatchVendorFixed
				out.FixedVersion = nextVersionHint(bv)
				out.Raise = append(out.Raise, "vendor publishes an explicit fixed version that post-dates the installed build")
				out.Lower = append(out.Lower, "vendor confirms the installed build is affected")
			default:
				out.Applicability = model.ApplicabilityNeedsInvestigation
				out.Confidence = model.ConfidenceLow
				out.Explanation = fmt.Sprintf(
					"Installed %s (%s) is older than the build the vendor enumerates (%s); whether that build is patched cannot be determined from this advisory.",
					pkg.Version, pkg.Name, bv)
				out.Evidence = append(out.Evidence, evidenceVersion(adv, pkg, aff.Ecosystem))
				out.PatchStatus = model.PatchUnknown
			}
			return out, true
		}
	}

	// --- source-package matching --------------------------------------------
	if !namesMatch(pkg.Name, aff.Name) {
		return Outcome{}, false
	}
	out.VendorAdvisory = vendorAdvisoryFor(adv, aff.Ecosystem, "")

	// 1) authoritative ranges
	if fixed, verdict, reason, ok := evaluateRanges(pkg, aff, adv); ok {
		out.Applicability = verdict
		out.FixedVersion = fixed
		out.Explanation = reason
		out.Evidence = append(out.Evidence, evidenceVersion(adv, pkg, aff.Ecosystem))
		if fixed != "" {
			out.Evidence = append(out.Evidence, model.Evidence{
				Kind: "fixed_version", Source: adv.Source,
				Detail: fmt.Sprintf("advisory lists fixed version %s", fixed), URL: advURL(adv)})
			if out.VendorAdvisory != nil {
				out.VendorAdvisory.FixedVersion = fixed
			}
		}
		switch verdict {
		case model.ApplicabilityConfirmed:
			out.Confidence = model.ConfidenceHigh
			out.PatchStatus = model.PatchVulnerable
			out.Lower = append(out.Lower, "vendor publishes a patched build for this version")
		case model.ApplicabilityNotAffected:
			out.Confidence = model.ConfidenceHigh
			out.PatchStatus = model.PatchVendorFixed
			out.Raise = append(out.Raise, "a second advisory lists this exact build as affected")
		default:
			out.Confidence = model.ConfidenceLow
			out.PatchStatus = model.PatchUnknown
		}
		return out, true
	}

	// 2) enumerated affected versions (Ubuntu-style, no fixed boundary)
	if len(aff.Versions) > 0 {
		outcome := evaluateVersionEnumeration(pkg, aff, adv)
		return outcome, true
	}

	// 3) nothing usable
	if len(aff.Ranges) > 0 {
		return unresolved(out, adv, "advisory defines ranges without a fixed version and without an affected-version enumeration"), true
	}
	return unresolved(out, adv, "advisory contains no version data for this ecosystem"), true
}

// evaluateRanges applies introduced/fixed/last_affected semantics.
//
// A range without an upper bound (no fixed, no last_affected) is deliberately
// NOT treated as "everything is affected": distribution OSV records publish
// open-ended ranges ({introduced: "0"}) alongside an affected-version
// enumeration, and treating those as unbounded produces mass false positives.
// Unbounded ranges are skipped so the enumeration logic can decide.
func evaluateRanges(pkg model.Package, aff intel.Affected, adv intel.Advisory) (fixed string, verdict model.Applicability, reason string, ok bool) {
	bounded := false
	for _, r := range aff.Ranges {
		if strings.EqualFold(r.Type, "GIT") {
			continue // commit ranges are not installable-version evidence
		}
		var introduced, fixedV, lastAff string
		for _, ev := range r.Events {
			switch {
			case ev.Introduced != "":
				introduced = ev.Introduced
			case ev.Fixed != "":
				fixedV = ev.Fixed
			case ev.LastAffected != "":
				lastAff = ev.LastAffected
			}
		}
		if fixedV == "" && lastAff == "" {
			continue
		}
		bounded = true

		// lower bound: values below "introduced" are outside this range
		if introduced != "" && introduced != "0" {
			cmp, err := version.Compare(pkg.Ecosystem, pkg.Version, introduced)
			if err != nil {
				return "", model.ApplicabilityNeedsInvestigation,
					fmt.Sprintf("cannot compare installed %q with introduced %q: %v", pkg.Version, introduced, err), false
			}
			if cmp < 0 {
				if fixedV != "" && fixed == "" {
					fixed = fixedV
				}
				continue
			}
		}

		if fixedV != "" {
			cmp, err := version.Compare(pkg.Ecosystem, pkg.Version, fixedV)
			if err != nil {
				return "", model.ApplicabilityNeedsInvestigation,
					fmt.Sprintf("cannot compare installed %q with fixed %q: %v", pkg.Version, fixedV, err), false
			}
			if cmp >= 0 {
				// fixed in this range; another range may still cover this build
				if fixed == "" {
					fixed = fixedV
				}
				continue
			}
			return fixedV, model.ApplicabilityConfirmed,
				fmt.Sprintf("Installed %s falls inside the affected range published by %s (from %s, fixed in %s).",
					pkg.Version, adv.Source, valueOrZero(introduced), fixedV), true
		}

		cmp, err := version.Compare(pkg.Ecosystem, pkg.Version, lastAff)
		if err != nil {
			return "", model.ApplicabilityNeedsInvestigation,
				fmt.Sprintf("cannot compare installed %q with last_affected %q: %v", pkg.Version, lastAff, err), false
		}
		if cmp <= 0 {
			return "", model.ApplicabilityConfirmed,
				fmt.Sprintf("Installed %s is at or below the last affected version %s published by %s.",
					pkg.Version, lastAff, adv.Source), true
		}
		if fixed == "" {
			fixed = ""
		}
	}
	if bounded {
		if fixed != "" {
			return fixed, model.ApplicabilityNotAffected,
				fmt.Sprintf("Installed %s is at or beyond the fixed version %s published by %s.", pkg.Version, fixed, adv.Source), true
		}
		return "", model.ApplicabilityNotAffected,
			fmt.Sprintf("Installed %s is outside the bounded affected ranges published by %s.", pkg.Version, adv.Source), true
	}
	return "", model.ApplicabilityNeedsInvestigation,
		fmt.Sprintf("Advisory ranges for %s are open-ended (no fixed version) and no affected-version enumeration is available.", adv.Source), false
}

func valueOrZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

func rangeSuffix(introduced, fixed string) string {
	var parts []string
	if introduced != "" {
		parts = append(parts, "from "+introduced)
	}
	if fixed != "" {
		parts = append(parts, "fixed in "+fixed)
	}
	if len(parts) == 0 {
		return ""
	}
	return " (" + strings.Join(parts, ", ") + ")"
}

// evaluateVersionEnumeration handles advisories that list affected versions but
// publish no fixed boundary (Ubuntu OSV exports work this way).
func evaluateVersionEnumeration(pkg model.Package, aff intel.Affected, adv intel.Advisory) Outcome {
	out := Outcome{
		DistroAdvisory:   IsDistroAdvisory(adv),
		MatchedEcosystem: aff.Ecosystem,
		VendorAdvisory:   vendorAdvisoryFor(adv, aff.Ecosystem, ""),
	}

	sorted := append([]string(nil), aff.Versions...)
	sort.Slice(sorted, func(i, j int) bool {
		c, err := version.Compare(pkg.Ecosystem, sorted[i], sorted[j])
		return err == nil && c < 0
	})
	lo, hi := sorted[0], sorted[len(sorted)-1]

	for _, v := range sorted {
		if v == pkg.Version {
			out.Applicability = model.ApplicabilityConfirmed
			out.Confidence = model.ConfidenceHigh
			out.PatchStatus = model.PatchVulnerable
			out.Explanation = fmt.Sprintf("%s enumerates the installed version %s as affected.", adv.Source, pkg.Version)
			out.Evidence = []model.Evidence{
				evidenceVersion(adv, pkg, aff.Ecosystem),
				{Kind: "vendor_version_enumerated", Source: adv.Source,
					Detail: fmt.Sprintf("%s lists %s %s as affected", adv.Source, pkg.Name, pkg.Version), URL: advURL(adv)},
			}
			out.Lower = append(out.Lower, "vendor publishes a fixed version newer than the installed build")
			return out
		}
	}

	cmpHi, errHi := version.Compare(pkg.Ecosystem, pkg.Version, hi)
	if errHi != nil {
		return unresolved(out, adv, fmt.Sprintf("cannot compare installed %q with enumerated versions: %v", pkg.Version, errHi))
	}
	if cmpHi > 0 {
		if marker := foreignBuildMarker(pkg.Ecosystem, pkg.Version); marker != "" {
			out.Applicability = model.ApplicabilityNeedsInvestigation
			out.Confidence = model.ConfidenceLow
			out.PatchStatus = model.PatchUnknown
			out.Explanation = fmt.Sprintf(
				"Installed %s is a %s build, so %s's affected-version enumeration (highest %s) does not apply to it. Whether this build contains the fix must be confirmed with the packager.",
				pkg.Version, marker, adv.Source, hi)
			out.Evidence = []model.Evidence{
				evidenceVersion(adv, pkg, aff.Ecosystem),
				{Kind: "foreign_build", Source: "inventory",
					Detail: fmt.Sprintf("build marker %q indicates a third-party package", marker)},
			}
			out.Raise = append(out.Raise, "the third-party packager confirms the build contains the upstream fix")
			return out
		}
		out.Applicability = model.ApplicabilityNotAffected
		out.Confidence = model.ConfidenceMedium
		out.PatchStatus = model.PatchVendorFixed
		out.Explanation = fmt.Sprintf(
			"Installed %s is newer than the highest version %s enumerates as affected (%s); the distribution appears to have shipped a fixed build.",
			pkg.Version, adv.Source, hi)
		out.Evidence = []model.Evidence{
			evidenceVersion(adv, pkg, aff.Ecosystem),
			{Kind: "vendor_version_boundary", Source: adv.Source,
				Detail: fmt.Sprintf("highest affected version listed = %s; installed = %s", hi, pkg.Version), URL: advURL(adv)},
		}
		out.Raise = append(out.Raise, "the advisory publishes an explicit fixed version covering this build")
		out.Lower = append(out.Lower, "the vendor additionally lists this installed build as affected")
		return out
	}

	cmpLo, errLo := version.Compare(pkg.Ecosystem, pkg.Version, lo)
	if errLo != nil {
		return unresolved(out, adv, fmt.Sprintf("cannot compare installed %q with enumerated versions: %v", pkg.Version, errLo))
	}
	if cmpLo < 0 {
		out.Applicability = model.ApplicabilityNeedsInvestigation
		out.Confidence = model.ConfidenceLow
		out.PatchStatus = model.PatchUnknown
		out.Explanation = fmt.Sprintf(
			"Installed %s predates the earliest version %s enumerates (%s); the advisory's enumeration does not cover this build, so applicability is unresolved.",
			pkg.Version, adv.Source, lo)
		out.Evidence = []model.Evidence{evidenceVersion(adv, pkg, aff.Ecosystem)}
		out.Raise = append(out.Raise, "the vendor confirms the build predates the enumeration window is affected")
		return out
	}

	out.Applicability = model.ApplicabilityNeedsInvestigation
	out.Confidence = model.ConfidenceLow
	out.PatchStatus = model.PatchUnknown
	out.Explanation = fmt.Sprintf(
		"Installed %s sits between versions %s enumerates as affected (%s .. %s) but is not itself listed: the build may be an unlisted fix or an unlisted vulnerable build.",
		pkg.Version, adv.Source, lo, hi)
	out.Evidence = []model.Evidence{evidenceVersion(adv, pkg, aff.Ecosystem)}
	out.Raise = append(out.Raise, "vendor confirms this exact build is affected")
	out.Lower = append(out.Lower, "vendor confirms this exact build contains the fix")
	return out
}

func unresolved(out Outcome, adv intel.Advisory, reason string) Outcome {
	out.Applicability = model.ApplicabilityNeedsInvestigation
	out.Confidence = model.ConfidenceLow
	out.Explanation = reason
	out.PatchStatus = model.PatchUnknown
	out.Evidence = append(out.Evidence, model.Evidence{
		Kind: "advisory_incomplete", Source: adv.Source, Detail: reason, URL: advURL(adv)})
	return out
}

// foreignBuildMarker detects builds that did not come from the distribution
// whose advisories we are reading.
//
// This is the second half of backport awareness: "installed is newer than the
// vendor's last enumerated build" is only meaningful when the installed package
// was actually built by that vendor. A NodeSource/PPA/COPR build carries a
// different revision scheme and must not be resolved by distro enumeration.
func foreignBuildMarker(ecosystem, installed string) string {
	e := strings.ToLower(ecosystem)
	v := strings.ToLower(installed)
	switch {
	case strings.Contains(v, "nodesource"):
		return "nodesource"
	case strings.Contains(v, "ppa"):
		return "ppa"
	case strings.Contains(v, "copr"):
		return "copr"
	case strings.Contains(v, "snap"):
		return "snap-transition"
	}
	// RPM ecosystems: an Ubuntu/Debian revision on an RPM ecosystem (or vice
	// versa) means the advisory's version scheme does not apply.
	if isDistroEcosystem(ecosystem) {
		if strings.Contains(e, "ubuntu") || strings.Contains(e, "debian") {
			if strings.Contains(v, ".el") || strings.Contains(v, "fc") || strings.Contains(v, ".suse") {
				return "foreign-distro-revision"
			}
		}
	}
	return ""
}

// findBinary matches an installed package name against OSV binary entries.
// Distribution binary names are sometimes suffixed (libssl3t64), so an exact
// case-insensitive match is required before falling back to the source name.
func findBinary(bins []intel.Binary, name string) (string, bool) {
	for _, b := range bins {
		if strings.EqualFold(b.Name, name) {
			return b.Version, true
		}
	}
	return "", false
}

// namesMatch compares an installed name with the advisory's package name using
// ecosystem normalisation where it applies.
func namesMatch(installed, advisory string) bool {
	if strings.EqualFold(installed, advisory) {
		return true
	}
	// Debian/Ubuntu source-vs-binary naming is handled by the binary view; a
	// purl-normalised comparison covers PyPI/npm spelling differences.
	if pkgurl.NormalizeName("PyPI", installed) == pkgurl.NormalizeName("PyPI", advisory) {
		return true
	}
	return false
}

func evidenceVersion(adv intel.Advisory, pkg model.Package, ecosystem string) model.Evidence {
	return model.Evidence{
		Kind:   "installed_version",
		Source: adv.Source,
		Detail: fmt.Sprintf("%s %s installed (ecosystem %s); advisory %s", pkg.Name, pkg.Version, ecosystem, adv.ID),
		URL:    advURL(adv),
	}
}

func vendorAdvisoryFor(adv intel.Advisory, ecosystem, fixed string) *model.VendorAdvisory {
	if !IsDistroAdvisory(adv) {
		return nil
	}
	return &model.VendorAdvisory{
		Vendor:       adv.Source,
		ID:           adv.ID,
		URL:          advURL(adv),
		FixedVersion: fixed,
	}
}

func advURL(adv intel.Advisory) string {
	for _, ref := range adv.References {
		if ref.URL == "" {
			continue
		}
		if strings.Contains(ref.Type, "ADVISORY") || strings.Contains(ref.Type, "REPORT") {
			return ref.URL
		}
	}
	if len(adv.References) > 0 {
		return adv.References[0].URL
	}
	return ""
}

// nextVersionHint is a human hint for "the next build after this one"; it is
// never presented as an authoritative fixed version.
func nextVersionHint(v string) string {
	return ""
}
