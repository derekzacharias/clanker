package autofix

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

// This file is the safety boundary. Everything the model proposes passes through it
// before a single byte reaches a repository, and every check here is deterministic.
//
// The three rules it enforces, in order of importance:
//
//  1. A generated version may never be older than the advisory's fixed version. The
//     model writes prose; the advisory writes versions.
//  2. A generated change may only touch files that cannot escalate privileges. CI
//     configuration, credentials and deployment keys are permanently off limits.
//  3. A generated file may not contain a secret. If it does, the proposal is rejected
//     and nothing is written.

// forbiddenExact are paths that must never be written by automation, whatever the
// allow-list says. A bot that can edit CI config with a project token can read every
// variable in the project; a bot that can write a deploy key can outlive its revocation.
var forbiddenExact = map[string]string{
	".gitlab-ci.yml":              "CI configuration decides what runs with the project's tokens",
	".gitlab-ci.yaml":             "CI configuration decides what runs with the project's tokens",
	"docker-compose.override.yml": "overrides are how a fix becomes a privilege escalation",
	".env":                        "environment files hold secrets",
	".env.local":                  "environment files hold secrets",
}

// forbiddenPatterns are path shapes that are never acceptable.
var forbiddenPatterns = []struct {
	re     *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`(^|/)\.gitlab/`), "GitLab configuration directory"},
	{regexp.MustCompile(`(^|/)\.github/`), "GitHub workflow directory"},
	{regexp.MustCompile(`(^|/)\.circleci/`), "CI configuration directory"},
	{regexp.MustCompile(`(^|/)\.ssh/`), "SSH material"},
	{regexp.MustCompile(`(^|/)\.docker/config\.json$`), "registry credentials"},
	{regexp.MustCompile(`(^|/)kubeconfig$`), "cluster credentials"},
	{regexp.MustCompile(`(?i)(^|/)id_(rsa|dsa|ecdsa|ed25519)`), "private key"},
	{regexp.MustCompile(`(?i)\.(pem|key|p12|pfx|jks|keystore)$`), "key material"},
	{regexp.MustCompile(`(?i)(^|/)(secrets?|credentials?)\.`), "secret material"},
}

// secretPatterns are content shapes that must never appear in a generated file.
var secretPatterns = []struct {
	re     *regexp.Regexp
	reason string
}{
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`), "private key block"},
	{regexp.MustCompile(`\bglpat-[A-Za-z0-9_\-]{16,}\b`), "GitLab personal access token"},
	{regexp.MustCompile(`\bghp_[A-Za-z0-9]{20,}\b`), "GitHub token"},
	{regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`), "AWS access key id"},
	{regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`), "Slack token"},
	{regexp.MustCompile(`(?i)\b(api[_-]?key|secret[_-]?key|password|passwd|token)\s*[:=]\s*["']([A-Za-z0-9_\-/+]{20,})["']`), "inline credential"},
	{regexp.MustCompile(`(?i)\b(password|passwd|secret)\s*[:=]\s*["']?[^\s"'#]{8,}["']?`), "hardcoded password"},
}

// ValidatePath checks one path against the allow-list and the forbidden set.
func ValidatePath(p string, allow []string) error {
	p = strings.TrimSpace(strings.ReplaceAll(p, "\\", "/"))
	if p == "" {
		return fmt.Errorf("empty path")
	}
	if strings.HasPrefix(p, "/") || strings.Contains(p, "..") {
		return fmt.Errorf("%q: path must be relative and must not traverse upwards", p)
	}
	cleaned := path.Clean(p)
	if reason, bad := forbiddenExact[cleaned]; bad {
		return fmt.Errorf("%q is not writable by automation: %s", cleaned, reason)
	}
	for _, f := range forbiddenPatterns {
		if f.re.MatchString(cleaned) {
			return fmt.Errorf("%q is not writable by automation: %s", cleaned, f.reason)
		}
	}
	for _, a := range allow {
		a = path.Clean(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if cleaned == a || strings.HasPrefix(cleaned, a+"/") {
			return nil
		}
	}
	return fmt.Errorf("%q is outside the writable allow-list", cleaned)
}

// ValidatePaths applies ValidatePath to every path and rejects duplicates, because two
// changes to one file mean the proposal disagrees with itself.
func ValidatePaths(paths []string, allow []string) error {
	seen := make(map[string]bool, len(paths))
	for _, p := range paths {
		if err := ValidatePath(p, allow); err != nil {
			return err
		}
		key := path.Clean(p)
		if seen[key] {
			return fmt.Errorf("%q appears more than once in the proposal", key)
		}
		seen[key] = true
	}
	return nil
}

// ScanSecrets rejects content that looks like it is carrying a credential.
func ScanSecrets(content string) error {
	for _, s := range secretPatterns {
		if s.re.MatchString(content) {
			return fmt.Errorf("generated content contains what looks like a %s", s.reason)
		}
	}
	return nil
}

// ValidatePatch runs every guard over a model proposal.
func ValidatePatch(p PatchProposal, allow []string, maxBytes int) error {
	if len(p.Files) == 0 {
		return fmt.Errorf("the proposal changes no files")
	}
	if strings.TrimSpace(p.Rationale) == "" {
		return fmt.Errorf("the proposal has no rationale")
	}
	paths := make([]string, 0, len(p.Files))
	for _, f := range p.Files {
		paths = append(paths, f.Path)
	}
	if err := ValidatePaths(paths, allow); err != nil {
		return err
	}
	for _, f := range p.Files {
		if maxBytes > 0 && len(f.Content) > maxBytes {
			return fmt.Errorf("%q is %d bytes, over the %d-byte limit for a generated file",
				f.Path, len(f.Content), maxBytes)
		}
		if err := ScanSecrets(f.Content); err != nil {
			return fmt.Errorf("%q: %w", f.Path, err)
		}
	}
	return nil
}

// CompareVersions orders two version strings the way a package manager roughly would:
// an optional epoch, then alternating numeric and alphabetic runs. It is deliberately
// tolerant — these strings come from Ubuntu, PyPI and npm, and no single parser handles
// all three — but it is strict enough to catch a downgrade, which is the only decision
// that depends on it.
func CompareVersions(a, b string) int {
	at, bt := tokenizeVersion(a), tokenizeVersion(b)
	for i := 0; i < len(at) || i < len(bt); i++ {
		var x, y string
		if i < len(at) {
			x = at[i]
		}
		if i < len(bt) {
			y = bt[i]
		}
		if x == y {
			continue
		}
		xn, xIsNum := numeric(x)
		yn, yIsNum := numeric(y)
		switch {
		case xIsNum && yIsNum:
			if xn != yn {
				if xn < yn {
					return -1
				}
				return 1
			}
		case xIsNum != yIsNum:
			// A numeric run outranks an alphabetic one ("1.0.1" > "1.0.rc1").
			if xIsNum {
				return 1
			}
			return -1
		default:
			if x < y {
				return -1
			}
			if x > y {
				return 1
			}
		}
	}
	return 0
}

// ValidateUpgrade refuses a proposed version that would not actually move past the
// advisory's fix, which is the one thing a model must never be trusted to choose.
func ValidateUpgrade(proposed, installed, fixed string) error {
	proposed, fixed = strings.TrimSpace(proposed), strings.TrimSpace(fixed)
	if proposed == "" {
		return fmt.Errorf("no version proposed")
	}
	if fixed == "" {
		return fmt.Errorf("no fixed version is known for this finding")
	}
	if CompareVersions(proposed, fixed) < 0 {
		return fmt.Errorf("proposed version %q is older than the fixed version %q", proposed, fixed)
	}
	if installed != "" && CompareVersions(proposed, installed) <= 0 {
		return fmt.Errorf("proposed version %q does not move past the installed version %q", proposed, installed)
	}
	return nil
}

func tokenizeVersion(v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	var out []string
	var cur strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	prevDigit := false
	for i, r := range v {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			flush()
			prevDigit = false
			continue
		}
		isDigit := unicode.IsDigit(r)
		if i > 0 && cur.Len() > 0 && isDigit != prevDigit {
			flush()
		}
		cur.WriteRune(r)
		prevDigit = isDigit
	}
	flush()
	// Trailing zero runs do not distinguish versions: 1.0.0 and 1.0 are the same
	// version, and a guard that says otherwise rejects a correct fix. A trailing
	// non-zero run (1.0.0-1ubuntu1) is preserved, because that one is a real revision.
	for len(out) > 1 {
		last := out[len(out)-1]
		if n, ok := numeric(last); ok && n == 0 {
			out = out[:len(out)-1]
			continue
		}
		break
	}
	return out
}

func numeric(s string) (uint64, bool) {
	if s == "" {
		return 0, false
	}
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return 0, false
		}
	}
	n, err := strconv.ParseUint(strings.TrimLeft(s, "0"), 10, 64)
	if err != nil {
		if strings.Trim(s, "0") == "" {
			return 0, true
		}
		return 0, false
	}
	return n, true
}
