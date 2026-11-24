// Package msrc ingests Microsoft Security Response Center advisories (CVRF) and answers the
// one question Windows correlation needs: which CVEs does a given KB fix, for a given product?
//
// The data is CVRF XML per monthly update. Only the parts that change a decision are kept:
// the product tree (to know which Windows release an entry is about) and, for each CVE, the
// vendor fixes with their KB numbers. Severity and CVSS come along because a finding without
// them cannot be prioritised.
package msrc

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// Document is one monthly advisory bundle after parsing.
type Document struct {
	ID       string
	Title    string
	Products map[string]Product
	CVEs     []CVE
}

// Product is one entry in the product tree.
type Product struct {
	ID     string
	Name   string
	Family []string // branch names above it, e.g. ["Microsoft","Windows"]
}

// CVE is one vulnerability with the fixes Microsoft published for it.
type CVE struct {
	ID       string
	Title    string
	Severity string
	CVSS     float64
	Fixes    []Fix
}

// Fix is a vendor remediation for one product.
type Fix struct {
	ProductID   string
	ProductName string
	KB          string
	Supersedes  []string
	URL         string
}

// cvrfDoc mirrors only the elements that are used. Extra elements are ignored by encoding/xml.
type cvrfDoc struct {
	XMLName          xml.Name `xml:"cvrfdoc"`
	DocumentTitle    string   `xml:"DocumentTitle"`
	DocumentTracking struct {
		Identification struct {
			ID string `xml:"ID"`
		} `xml:"Identification"`
	} `xml:"DocumentTracking"`
	ProductTree struct {
		Branch []cvrfBranch `xml:"Branch"`
	} `xml:"ProductTree"`
	Vulnerability []cvrfVuln `xml:"Vulnerability"`
}

type cvrfBranch struct {
	Type     string            `xml:"Type,attr"`
	Name     string            `xml:"Name,attr"`
	Branch   []cvrfBranch      `xml:"Branch"`
	FullName []cvrfFullProduct `xml:"FullProductName"`
}

type cvrfFullProduct struct {
	ProductID string `xml:"ProductID,attr"`
	Value     string `xml:",chardata"`
}

type cvrfVuln struct {
	CVE   string `xml:"CVE"`
	Title string `xml:"Title"`
	Notes []struct {
		Type  string `xml:"Type,attr"`
		Title string `xml:"Title,attr"`
		Value string `xml:",chardata"`
	} `xml:"Notes>Note"`
	CVSSScoreSets []struct {
		BaseScore float64 `xml:"BaseScore"`
	} `xml:"CVSSScoreSets>ScoreSet"`
	Threats []struct {
		Type        string `xml:"Type,attr"`
		Description string `xml:"Description"`
	} `xml:"Threats>Threat"`
	Remediations []struct {
		Type         string   `xml:"Type,attr"`
		Description  string   `xml:"Description"`
		URL          string   `xml:"URL"`
		Supercedence string   `xml:"Supercedence"`
		ProductIDs   []string `xml:"ProductID"`
	} `xml:"Remediations>Remediation"`
}

// ParseDocument parses one CVRF document (MSRC's XML export).
func ParseDocument(raw []byte) (Document, error) {
	var doc cvrfDoc
	if err := xml.Unmarshal(raw, &doc); err != nil {
		return Document{}, fmt.Errorf("parse CVRF: %w", err)
	}
	if len(doc.Vulnerability) == 0 {
		return Document{}, fmt.Errorf("CVRF document has no vulnerabilities; not a security update bundle")
	}
	out := Document{
		ID:       strings.TrimSpace(doc.DocumentTracking.Identification.ID),
		Title:    strings.TrimSpace(doc.DocumentTitle),
		Products: map[string]Product{},
	}
	for _, b := range doc.ProductTree.Branch {
		walkBranch(b, []string{b.Name}, out.Products)
	}
	for _, v := range doc.Vulnerability {
		cve := CVE{
			ID:    strings.TrimSpace(v.CVE),
			Title: strings.TrimSpace(v.Title),
			CVSS:  firstScore(v),
		}
		cve.Severity = severityFromThreats(v)
		for _, r := range v.Remediations {
			kb := extractKB(r.Description)
			if kb == "" {
				continue
			}
			// "Type" values: 0=Unknown,1=Workaround,2=Vendor Fix,3=None Available,...
			if r.Type != "" && r.Type != "2" && r.Type != "Vendor Fix" {
				continue
			}
			var supersedes []string
			for _, s := range strings.FieldsFunc(r.Supercedence, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
				if k := extractKB(s); k != "" {
					supersedes = append(supersedes, k)
				}
			}
			for _, pid := range r.ProductIDs {
				p := out.Products[pid]
				cve.Fixes = append(cve.Fixes, Fix{
					ProductID: pid, ProductName: p.Name, KB: kb,
					Supersedes: supersedes, URL: strings.TrimSpace(r.URL),
				})
			}
		}
		if cve.ID != "" {
			out.CVEs = append(out.CVEs, cve)
		}
	}
	return out, nil
}

func walkBranch(b cvrfBranch, path []string, out map[string]Product) {
	for _, f := range b.FullName {
		name := strings.TrimSpace(f.Value)
		out[f.ProductID] = Product{ID: f.ProductID, Name: name, Family: path}
	}
	for _, c := range b.Branch {
		walkBranch(c, append(path, c.Name), out)
	}
}

func firstScore(v cvrfVuln) float64 {
	for _, s := range v.CVSSScoreSets {
		if s.BaseScore > 0 {
			return s.BaseScore
		}
	}
	return 0
}

// severityFromThreats picks the vendor severity label ("Critical", "Important", …).
func severityFromThreats(v cvrfVuln) string {
	for _, t := range v.Threats {
		d := strings.TrimSpace(t.Description)
		if d == "" {
			continue
		}
		switch strings.ToLower(d) {
		case "critical", "important", "moderate", "low", "security impact":
			if strings.EqualFold(d, "Security Impact") {
				continue
			}
			return d
		}
	}
	return ""
}

// extractKB pulls the first KB number out of a remediation description.
//
// MSRC writes these as "5044284", "KB5044284", or occasionally with surrounding prose.
func extractKB(s string) string {
	s = strings.ToUpper(strings.TrimSpace(s))
	for i := 0; i+1 < len(s); i++ {
		if s[i] != 'K' || s[i+1] != 'B' {
			continue
		}
		j := i + 2
		start := j
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		if j-start >= 6 {
			return "KB" + s[start:j]
		}
	}
	// A bare number of KB length is also accepted (MSRC's usual form).
	digits := strings.TrimSpace(s)
	if len(digits) >= 6 && len(digits) <= 9 {
		allDigits := true
		for _, r := range digits {
			if r < '0' || r > '9' {
				allDigits = false
				break
			}
		}
		if allDigits {
			return "KB" + digits
		}
	}
	return ""
}
