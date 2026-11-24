package msrc

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Lookup answers the correlation questions from the stored advisories.

// CVEForKB is one CVE fixed by a KB, with the vendor's assessment of it.
type CVEForKB struct {
	CVE        string
	Title      string
	Severity   string
	CVSS       float64
	KB         string
	Product    string
	Document   string
	Supersedes []string
	URL        string
}

// KBsForProduct returns the CVEs a KB fixes, restricted to products whose name matches the
// host. An empty product pattern means "any product" and is used only by the caller that
// already knows it matched by KB (Windows Update told it so).
func KBsForProduct(ctx context.Context, db *sql.DB, kb string, match func(product string) bool) ([]CVEForKB, error) {
	rows, err := db.QueryContext(ctx, `SELECT f.cve, COALESCE(c.title,''), COALESCE(c.severity,''),
			COALESCE(c.cvss,0), f.kb, COALESCE(p.name,''), COALESCE(f.document,''),
			COALESCE(f.supersedes,''), COALESCE(f.url,'')
		FROM msrc_fixes f
		LEFT JOIN msrc_cves c ON c.cve = f.cve
		LEFT JOIN msrc_products p ON p.product_id = f.product_id
		WHERE f.kb = ?`, kb)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CVEForKB
	for rows.Next() {
		var c CVEForKB
		var supersedes string
		if err := rows.Scan(&c.CVE, &c.Title, &c.Severity, &c.CVSS, &c.KB, &c.Product,
			&c.Document, &supersedes, &c.URL); err != nil {
			return nil, err
		}
		if match != nil && !match(c.Product) {
			continue
		}
		if supersedes != "" {
			c.Supersedes = strings.Split(supersedes, ",")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// FixesForProduct lists every stored fix whose product matches, newest document first.
// Used to answer "which KB does this host need for this CVE" when the endpoint did not run
// the Windows Update Agent.
func FixesForProduct(ctx context.Context, db *sql.DB, match func(product string) bool) ([]CVEForKB, error) {
	rows, err := db.QueryContext(ctx, `SELECT f.cve, COALESCE(c.title,''), COALESCE(c.severity,''),
			COALESCE(c.cvss,0), f.kb, COALESCE(p.name,''), COALESCE(f.document,''),
			COALESCE(f.supersedes,''), COALESCE(f.url,'')
		FROM msrc_fixes f
		LEFT JOIN msrc_cves c ON c.cve = f.cve
		LEFT JOIN msrc_products p ON p.product_id = f.product_id
		ORDER BY f.document DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CVEForKB
	for rows.Next() {
		var c CVEForKB
		var supersedes string
		if err := rows.Scan(&c.CVE, &c.Title, &c.Severity, &c.CVSS, &c.KB, &c.Product,
			&c.Document, &supersedes, &c.URL); err != nil {
			return nil, err
		}
		if match != nil && !match(c.Product) {
			continue
		}
		if supersedes != "" {
			c.Supersedes = strings.Split(supersedes, ",")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AdvisoryCount reports how many CVEs are stored, so a caller can distinguish "no MSRC data"
// from "no affected products".
func AdvisoryCount(ctx context.Context, db *sql.DB) (int, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM msrc_cves`).Scan(&n)
	if err != nil {
		// A cache that predates this feature has no table; that is "no data", not an error.
		return 0, nil
	}
	return n, nil
}

// WindowsProductMatch builds the product matcher for a host.
//
// MSRC names products as "Windows 11 Version 24H2 for x64-based Systems". A host reports
// product "Windows 11 Pro", release "24H2" and an architecture. A match requires the family
// and the release to agree; architecture is compared when the advisory states one, but a
// mismatch there narrows rather than rejects, because MSRC alternates between "x64-based" and
// "64-bit" spellings and rejects would silently drop real fixes.
func WindowsProductMatch(product, release, arch string) (func(string) bool, []string) {
	product = strings.ToLower(strings.TrimSpace(product))
	release = strings.ToLower(strings.TrimSpace(release))
	arch = strings.ToLower(strings.TrimSpace(arch))

	family := ""
	switch {
	case strings.Contains(product, "windows 11"):
		family = "windows 11"
	case strings.Contains(product, "windows 10"):
		family = "windows 10"
	case strings.Contains(product, "server 2025"):
		family = "windows server 2025"
	case strings.Contains(product, "server 2022"):
		family = "windows server 2022"
	case strings.Contains(product, "server 2019"):
		family = "windows server 2019"
	case strings.Contains(product, "server 2016"):
		family = "windows server 2016"
	case strings.Contains(product, "server 2012"):
		family = "windows server 2012"
	}
	var notes []string
	if family == "" {
		return func(string) bool { return false }, []string{
			"the operating system name is not one Microsoft publishes advisories for; update findings were not matched",
		}
	}
	if release == "" {
		notes = append(notes, "the Windows release (e.g. 24H2) is unknown, so advisory matching was limited to the product family")
	}
	match := func(name string) bool {
		n := strings.ToLower(name)
		if !strings.Contains(n, family) {
			return false
		}
		if release != "" && !strings.Contains(n, release) {
			return false
		}
		if arch != "" {
			switch {
			case strings.Contains(arch, "arm"):
				if !strings.Contains(n, "arm") {
					return false
				}
			case strings.Contains(arch, "amd64"), strings.Contains(arch, "x86_64"):
				if strings.Contains(n, "arm") || strings.Contains(n, "32-bit") {
					return false
				}
			case strings.Contains(arch, "386"), strings.Contains(arch, "x86"):
				if !strings.Contains(n, "32-bit") && !strings.Contains(n, "x86") {
					return false
				}
			}
		}
		return true
	}
	return match, notes
}

// SortedKBs is a stable ordering helper for deterministic output and tests.
func SortedKBs(in []string) []string {
	out := append([]string{}, in...)
	sort.Strings(out)
	return out
}

// NormalizeKB accepts "5044284", "kb5044284" and "KB 5044284" and returns "KB5044284".
func NormalizeKB(s string) string {
	up := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(s), " ", ""))
	if strings.HasPrefix(up, "KB") {
		up = up[2:]
	}
	for _, r := range up {
		if r < '0' || r > '9' {
			return ""
		}
	}
	if len(up) < 6 {
		return ""
	}
	return "KB" + up
}

// DescribeSyncText is a one-line health sentence for the dashboard.
func DescribeSyncText(st SyncState, now func() time.Time) (string, bool) {
	if now == nil {
		now = func() time.Time { return st.SyncedAt }
	}
	if st.SyncedAt.IsZero() {
		return "Microsoft advisory data has never been imported; Windows update findings cannot be produced", false
	}
	age := now().Sub(st.SyncedAt)
	stale := age > 35*24*time.Hour
	text := fmt.Sprintf("Microsoft advisories: %d documents, %d CVEs, last synced %s",
		st.Documents, st.CVE, st.SyncedAt.UTC().Format("2006-01-02"))
	if stale {
		text += " (stale — more than 35 days old)"
	}
	return text, !stale
}
