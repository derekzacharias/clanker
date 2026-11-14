package intel

import (
	"regexp"
	"strings"
)

// ecosystemPatterns are the OSV ecosystem identifiers this scanner emits.
//
// OSV answers HTTP 200 with an empty body for an unknown ecosystem, which is
// indistinguishable from "no vulnerabilities". Validating locally is therefore
// the only way to tell a coverage gap from a clean result.
var ecosystemPatterns = []*regexp.Regexp{
	regexp.MustCompile(`^Ubuntu:\d\d\.\d\d(:LTS)?$`),
	regexp.MustCompile(`^Ubuntu:Pro:[A-Za-z0-9.:-]+$`),
	regexp.MustCompile(`^Debian:\d+$`),
	regexp.MustCompile(`^Alpine:v\d+\.\d+$`),
	regexp.MustCompile(`^Red Hat(:\d+)?$`),
	regexp.MustCompile(`^Rocky Linux:\d+$`),
	regexp.MustCompile(`^AlmaLinux:\d+(\.\d+)?$`),
	regexp.MustCompile(`^Fedora:\d+$`),
	regexp.MustCompile(`^CentOS:\d+$`),
	regexp.MustCompile(`^openSUSE:\d+(\.\d+)?$`),
	regexp.MustCompile(`^(PyPI|npm|Go|crates\.io|Maven|NuGet|RubyGems|Packagist|Hex|Pub|Linux|Windows)$`),
}

// ValidEcosystem reports whether an ecosystem string is one OSV recognises.
func ValidEcosystem(ecosystem string) bool {
	eco := strings.TrimSpace(ecosystem)
	if eco == "" {
		return false
	}
	for _, re := range ecosystemPatterns {
		if re.MatchString(eco) {
			return true
		}
	}
	return false
}
