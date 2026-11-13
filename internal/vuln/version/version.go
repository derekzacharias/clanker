// Package version implements ecosystem-aware version comparison.
//
// Vuln correlation lives or dies on this file: Debian and RPM versions are not
// semver, PyPI versions are not semver, and comparing them as strings produces
// both false positives and false negatives. Each comparator below follows the
// authoritative algorithm for its ecosystem.
package version

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
)

// Compare orders a and b for the given OSV ecosystem name.
// It returns -1, 0 or 1 (like strings.Compare).
func Compare(ecosystem, a, b string) (int, error) {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	switch comparatorFor(ecosystem) {
	case kindDebian:
		return compareDebian(a, b)
	case kindRPM:
		return compareRPM(a, b)
	case kindPEP440:
		return comparePEP440(a, b)
	case kindSemver:
		return compareSemver(a, b)
	case kindMaven:
		return compareMaven(a, b)
	default:
		return compareGeneric(a, b)
	}
}

// Less reports whether a < b for the ecosystem.
func Less(ecosystem, a, b string) bool {
	c, err := Compare(ecosystem, a, b)
	return err == nil && c < 0
}

type kind int

const (
	kindGeneric kind = iota
	kindDebian
	kindRPM
	kindPEP440
	kindSemver
	kindMaven
)

func comparatorFor(ecosystem string) kind {
	e := strings.ToLower(ecosystem)
	switch {
	case strings.HasPrefix(e, "debian"), strings.HasPrefix(e, "ubuntu"):
		return kindDebian
	case strings.HasPrefix(e, "red hat"), strings.HasPrefix(e, "rhel"),
		strings.HasPrefix(e, "rocky"), strings.HasPrefix(e, "almalinux"),
		strings.HasPrefix(e, "fedora"), strings.HasPrefix(e, "opensuse"),
		strings.HasPrefix(e, "suse"), strings.HasPrefix(e, "centos"),
		strings.HasPrefix(e, "oracle"), strings.HasPrefix(e, "amazon"),
		strings.HasPrefix(e, "mageia"), strings.HasPrefix(e, "photon"):
		return kindRPM
	case e == "pypi":
		return kindPEP440
	case e == "npm", e == "go", e == "crates.io", e == "hex", e == "pub",
		e == "github actions", e == "swifturl", e == "bitnami", e == "hackage":
		return kindSemver
	case e == "maven":
		return kindMaven
	default:
		return kindGeneric
	}
}

// ---------------------------------------------------------------- Debian ----

// compareDebian implements dpkg's version comparison:
//
//	[epoch:]upstream_version[-debian_revision]
func compareDebian(a, b string) (int, error) {
	ae, au, ar := splitDebian(a)
	be, bu, br := splitDebian(b)
	if ae != be {
		return sign(ae - be), nil
	}
	if c := verrevcmp(au, bu); c != 0 {
		return c, nil
	}
	return verrevcmp(ar, br), nil
}

func splitDebian(v string) (epoch int, upstream, revision string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if n, err := strconv.Atoi(v[:i]); err == nil {
			epoch = n
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		upstream, revision = v[:i], v[i+1:]
	} else {
		upstream = v
	}
	return epoch, upstream, revision
}

// verrevcmp is the dpkg string comparison from deb-version(7).
func verrevcmp(a, b string) int {
	i, j := 0, 0
	for i < len(a) || j < len(b) {
		// non-digit prefix
		for (i < len(a) && !isDigit(a[i])) || (j < len(b) && !isDigit(b[j])) {
			ac, bc := 0, 0
			if i < len(a) {
				ac = order(a[i])
			}
			if j < len(b) {
				bc = order(b[j])
			}
			if ac != bc {
				return sign(ac - bc)
			}
			i++
			j++
		}
		// skip leading zeroes
		for i < len(a) && a[i] == '0' {
			i++
		}
		for j < len(b) && b[j] == '0' {
			j++
		}
		// numeric run
		si, sj := i, j
		for i < len(a) && isDigit(a[i]) {
			i++
		}
		for j < len(b) && isDigit(b[j]) {
			j++
		}
		if c := compareNumber(a[si:i], b[sj:j]); c != 0 {
			return c
		}
	}
	return 0
}

func order(c byte) int {
	switch {
	case c == '~':
		return -1
	case isDigit(c):
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	default:
		return int(c) + 256
	}
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// compareNumber compares two digit strings without leading zeros.
func compareNumber(a, b string) int {
	if len(a) != len(b) {
		return sign(len(a) - len(b))
	}
	return sign(strings.Compare(a, b))
}

// ------------------------------------------------------------------- RPM ----

// compareRPM implements rpmvercmp(8) semantics including '~' and '^'.
//
// An RPM version is [epoch:]version[-release]; the release is NOT part of the
// version ordering, so "1.0-9" < "1.0.1-1" even though a plain string compare
// of the segments would say otherwise.
func compareRPM(a, b string) (int, error) {
	aEpoch, aVer, aRel := splitRPM(a)
	bEpoch, bVer, bRel := splitRPM(b)
	if aEpoch != bEpoch {
		return sign(aEpoch - bEpoch), nil
	}
	if c := rpmVerCmp(aVer, bVer); c != 0 {
		return c, nil
	}
	return rpmVerCmp(aRel, bRel), nil
}

func splitRPM(v string) (epoch int, version, release string) {
	if i := strings.IndexByte(v, ':'); i >= 0 {
		if n, err := strconv.Atoi(v[:i]); err == nil {
			epoch = n
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		version, release = v[:i], v[i+1:]
	} else {
		version = v
	}
	return epoch, version, release
}

func rpmVerCmp(a, b string) int {
	if a == b {
		return 0
	}
	ia, ib := 0, 0
	for ia < len(a) || ib < len(b) {
		for ia < len(a) && !isAlnum(a[ia]) && a[ia] != '~' && a[ia] != '^' {
			ia++
		}
		for ib < len(b) && !isAlnum(b[ib]) && b[ib] != '~' && b[ib] != '^' {
			ib++
		}

		atilde := ia < len(a) && a[ia] == '~'
		btilde := ib < len(b) && b[ib] == '~'
		if atilde || btilde {
			if atilde && btilde {
				ia++
				ib++
				continue
			}
			if atilde {
				return -1
			}
			return 1
		}

		acaret := ia < len(a) && a[ia] == '^'
		bcaret := ib < len(b) && b[ib] == '^'
		if acaret || bcaret {
			if acaret && bcaret {
				ia++
				ib++
				continue
			}
			// "^" sorts newer than nothing but older than anything else
			if ia >= len(a) {
				return -1
			}
			if ib >= len(b) {
				return 1
			}
			if acaret {
				return 1
			}
			return -1
		}

		if ia >= len(a) || ib >= len(b) {
			break
		}

		aisnum := isDigit(a[ia])
		bisnum := isDigit(b[ib])
		if aisnum != bisnum {
			if aisnum {
				return 1
			}
			return -1
		}

		sa, sb := ia, ib
		if aisnum {
			for ia < len(a) && isDigit(a[ia]) {
				ia++
			}
			for ib < len(b) && isDigit(b[ib]) {
				ib++
			}
		} else {
			for ia < len(a) && isAlpha(a[ia]) {
				ia++
			}
			for ib < len(b) && isAlpha(b[ib]) {
				ib++
			}
		}
		segA, segB := a[sa:ia], b[sb:ib]
		if segA == segB {
			continue
		}
		if aisnum {
			trimA := strings.TrimLeft(segA, "0")
			trimB := strings.TrimLeft(segB, "0")
			if len(trimA) != len(trimB) {
				return sign(len(trimA) - len(trimB))
			}
			if c := strings.Compare(trimA, trimB); c != 0 {
				return sign(c)
			}
			continue
		}
		return sign(strings.Compare(segA, segB))
	}
	switch {
	case ia < len(a):
		return 1
	case ib < len(b):
		return -1
	}
	return 0
}

func isAlnum(c byte) bool { return isDigit(c) || isAlpha(c) }

func isAlpha(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// ---------------------------------------------------------------- PEP440 ----

// pep440Re is the canonical PEP 440 version pattern (case-insensitive).
var pep440Re = regexp.MustCompile(`(?i)^v?` +
	`(?:(?P<epoch>\d+)!)?` +
	`(?P<release>\d+(?:\.\d+)*)` +
	`(?:[-_.]?(?P<pre_l>alpha|beta|preview|pre|rc|a|b|c)[-_.]?(?P<pre_n>\d+)?)?` +
	`(?:-(?P<post_n1>\d+)|[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n>\d+)?)?` +
	`(?:[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?` +
	`(?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?$`)

type pep440 struct {
	epoch   int
	release []int
	pre     float64 // -Inf: dev-only, +Inf: final release, else rank*1000+n
	post    float64 // -1: none
	dev     float64 // +Inf: none
	valid   bool
}

func parsePEP440(v string) pep440 {
	p := pep440{post: -1, dev: math.Inf(1), pre: math.Inf(1)}
	m := pep440Re.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return p
	}
	p.valid = true
	named := func(name string) string {
		i := pep440Re.SubexpIndex(name)
		if i < 0 || i >= len(m) {
			return ""
		}
		return strings.ToLower(m[i])
	}
	if s := named("epoch"); s != "" {
		p.epoch, _ = strconv.Atoi(s)
	}
	for _, part := range strings.Split(named("release"), ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return pep440{post: -1, dev: math.Inf(1), pre: math.Inf(1)}
		}
		p.release = append(p.release, n)
	}
	preLabel := named("pre_l")
	preNum := named("pre_n")
	postLabel := named("post_l")
	postNum := named("post_n")
	if implicit := named("post_n1"); implicit != "" {
		postLabel = "post"
		postNum = implicit
	}
	devLabel := named("dev_l")
	devNum := named("dev_n")

	hasPre := preLabel != ""
	hasPost := postLabel != ""
	hasDev := devLabel != ""

	switch {
	case hasPre:
		rank := map[string]int{"a": 0, "alpha": 0, "b": 1, "beta": 1, "rc": 2, "c": 2, "pre": 2, "preview": 2}[preLabel]
		n := 0
		if preNum != "" {
			n, _ = strconv.Atoi(preNum)
		}
		p.pre = float64(rank*1000 + n)
	case hasDev && !hasPost && !hasPre:
		p.pre = math.Inf(-1) // 1.0.dev0 sorts before 1.0a1 and 1.0
	default:
		p.pre = math.Inf(1) // final release
	}
	if hasPost {
		n := 0
		if postNum != "" {
			n, _ = strconv.Atoi(postNum)
		}
		p.post = float64(n)
	}
	if hasDev {
		n := 0
		if devNum != "" {
			n, _ = strconv.Atoi(devNum)
		}
		p.dev = float64(n)
	}
	return p
}

func comparePEP440(a, b string) (int, error) {
	pa, pb := parsePEP440(a), parsePEP440(b)
	if !pa.valid || !pb.valid {
		return 0, fmt.Errorf("not a PEP 440 version: %q vs %q", a, b)
	}
	if pa.epoch != pb.epoch {
		return sign(pa.epoch - pb.epoch), nil
	}
	n := len(pa.release)
	if len(pb.release) > n {
		n = len(pb.release)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa.release) {
			x = pa.release[i]
		}
		if i < len(pb.release) {
			y = pb.release[i]
		}
		if x != y {
			return sign(x - y), nil
		}
	}
	if c := compareFloat(pa.pre, pb.pre); c != 0 {
		return c, nil
	}
	if c := compareFloat(pa.post, pb.post); c != 0 {
		return c, nil
	}
	return compareFloat(pa.dev, pb.dev), nil
}

func compareFloat(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}

// ---------------------------------------------------------------- semver ----

func compareSemver(a, b string) (int, error) {
	va, oka := parseSemver(a)
	vb, okb := parseSemver(b)
	if !oka || !okb {
		// Ecosystems occasionally publish non-semver strings (calendars,
		// epochs); fall back rather than fabricate an ordering error.
		return compareGeneric(a, b)
	}
	for i := 0; i < 3; i++ {
		if va.core[i] != vb.core[i] {
			return sign(va.core[i] - vb.core[i]), nil
		}
	}
	return comparePrerelease(va.pre, vb.pre), nil
}

type semver struct {
	core [3]int
	pre  []string
}

func parseSemver(v string) (semver, bool) {
	var s semver
	v = strings.TrimSpace(v)
	v = strings.TrimPrefix(v, "v")
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	if i := strings.IndexByte(v, '-'); i >= 0 {
		s.pre = strings.Split(v[i+1:], ".")
		v = v[:i]
	}
	parts := strings.Split(v, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return s, false
	}
	for i := 0; i < 3; i++ {
		if i >= len(parts) {
			s.core[i] = 0
			continue
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return s, false
		}
		s.core[i] = n
	}
	return s, true
}

func comparePrerelease(a, b []string) int {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	// A version without prerelease outranks one with it.
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] == b[i] {
			continue
		}
		na, erra := strconv.Atoi(a[i])
		nb, errb := strconv.Atoi(b[i])
		switch {
		case erra == nil && errb == nil:
			if na != nb {
				return sign(na - nb)
			}
		case erra == nil:
			return -1 // numeric < alphanumeric
		case errb == nil:
			return 1
		default:
			return sign(strings.Compare(a[i], b[i]))
		}
	}
	return sign(len(a) - len(b))
}

// ----------------------------------------------------------------- Maven ----

// compareMaven follows Maven's ComparableVersion closely enough for advisory
// ranges: numeric segments compare numerically, qualifiers in the documented
// order, and an absent qualifier outranks a qualifier.
func compareMaven(a, b string) (int, error) {
	ta := mavenTokens(a)
	tb := mavenTokens(b)
	n := len(ta)
	if len(tb) > n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		var x, y string
		if i < len(ta) {
			x = ta[i]
		}
		if i < len(tb) {
			y = tb[i]
		}
		if x == y {
			continue
		}
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				return sign(xn - yn), nil
			}
		case xerr == nil:
			return 1, nil // numeric beats qualifier
		case yerr == nil:
			return -1, nil
		default:
			if c := sign(mavenQualifierRank(x) - mavenQualifierRank(y)); c != 0 {
				return c, nil
			}
			if c := strings.Compare(x, y); c != 0 {
				return sign(c), nil
			}
		}
	}
	return 0, nil
}

var mavenQualifierOrder = map[string]int{
	"alpha": -5, "beta": -4, "milestone": -3, "rc": -2, "cr": -2,
	"snapshot": -1, "": 0, "ga": 0, "final": 0, "release": 0, "sp": 1,
}

func mavenQualifierRank(q string) int {
	if r, ok := mavenQualifierOrder[strings.ToLower(q)]; ok {
		return r
	}
	return 2
}

func mavenTokens(v string) []string {
	var out []string
	cur := strings.Builder{}
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	prevDigit := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '.' || c == '-' || c == '_':
			flush()
		case isDigit(c):
			if !prevDigit {
				flush()
			}
			cur.WriteByte(c)
			prevDigit = true
		default:
			if prevDigit {
				flush()
			}
			cur.WriteByte(c)
			prevDigit = false
		}
	}
	flush()
	return out
}

// --------------------------------------------------------------- generic ----

// compareGeneric splits versions into numeric and alphabetic runs and compares
// them pairwise. It is a last resort for ecosystems without a documented
// ordering; callers treat matches based on it as lower confidence.
func compareGeneric(a, b string) (int, error) {
	ta := tokenize(a)
	tb := tokenize(b)
	n := len(ta)
	if len(tb) > n {
		n = len(tb)
	}
	for i := 0; i < n; i++ {
		if i >= len(ta) {
			return -1, nil
		}
		if i >= len(tb) {
			return 1, nil
		}
		x, y := ta[i], tb[i]
		xn, xerr := strconv.Atoi(x)
		yn, yerr := strconv.Atoi(y)
		switch {
		case xerr == nil && yerr == nil:
			if xn != yn {
				return sign(xn - yn), nil
			}
		case xerr == nil:
			return 1, nil
		case yerr == nil:
			return -1, nil
		default:
			if c := strings.Compare(x, y); c != 0 {
				return sign(c), nil
			}
		}
	}
	return 0, nil
}

func tokenize(v string) []string {
	var out []string
	cur := strings.Builder{}
	prevDigit := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if isAlnum(c) {
			d := isDigit(c)
			if cur.Len() > 0 && d != prevDigit {
				flush()
			}
			cur.WriteByte(c)
			prevDigit = d
			continue
		}
		flush()
	}
	flush()
	return out
}

// ValidateVersion reports whether v is plausibly parseable for the ecosystem.
// It is used to avoid correlating on garbage inventory values.
func ValidateVersion(ecosystem, v string) error {
	v = strings.TrimSpace(v)
	if v == "" {
		return fmt.Errorf("empty version")
	}
	if len(v) > 128 {
		return fmt.Errorf("version too long")
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if isAlnum(c) || strings.IndexByte(".-_+~:^", c) >= 0 {
			continue
		}
		return fmt.Errorf("unexpected character %q in version %q", c, v)
	}
	return nil
}
