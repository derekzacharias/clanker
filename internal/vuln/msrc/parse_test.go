package msrc

import "testing"

// A trimmed but structurally faithful MSRC CVRF document: the branch tree, a Windows 11
// product, a CVE with a vendor fix KB, severity, and CVSS.
const fixture = `<?xml version="1.0" encoding="utf-8"?>
<cvrfdoc xmlns="http://www.icasi.org/CVRF/schema/cvrf/1.1">
  <DocumentTitle>December 2026 Security Updates</DocumentTitle>
  <DocumentTracking><Identification><ID>2026-Dec</ID></Identification></DocumentTracking>
  <ProductTree>
    <Branch Type="Vendor" Name="Microsoft">
      <Branch Type="Product Family" Name="Windows">
        <FullProductName ProductID="12085">Windows 11 Version 24H2 for x64-based Systems</FullProductName>
        <FullProductName ProductID="12086">Windows 11 Version 24H2 for ARM64-based Systems</FullProductName>
        <FullProductName ProductID="11923">Windows Server 2022</FullProductName>
      </Branch>
    </Branch>
  </ProductTree>
  <Vulnerability>
    <CVE>CVE-2026-40001</CVE>
    <Title>Windows Remote Code Execution Vulnerability</Title>
    <Notes><Note Type="Description" Title="Description">A flaw in a Windows component.</Note></Notes>
    <CVSSScoreSets><ScoreSet><BaseScore>8.8</BaseScore></ScoreSet></CVSSScoreSets>
    <Threats><Threat Type="Severity"><Description>Important</Description></Threat></Threats>
    <Remediations>
      <Remediation Type="2">
        <Description>5044284</Description>
        <URL>https://catalog.update.microsoft.com/v7/site/Search.aspx?q=5044284</URL>
        <Supercedence>5041234</Supercedence>
        <ProductID>12085</ProductID>
      </Remediation>
    </Remediations>
  </Vulnerability>
  <Vulnerability>
    <CVE>CVE-2026-40002</CVE>
    <Title>Windows Elevation of Privilege Vulnerability</Title>
    <CVSSScoreSets><ScoreSet><BaseScore>7.8</BaseScore></ScoreSet></CVSSScoreSets>
    <Threats><Threat Type="Severity"><Description>Critical</Description></Threat></Threats>
    <Remediations>
      <Remediation Type="2">
        <Description>KB5044285</Description>
        <ProductID>12085</ProductID>
      </Remediation>
    </Remediations>
  </Vulnerability>
</cvrfdoc>`

func TestParseDocumentExtractsProductsCVEsAndFixes(t *testing.T) {
	doc, err := ParseDocument([]byte(fixture))
	if err != nil {
		t.Fatalf("ParseDocument: %v", err)
	}
	if doc.ID != "2026-Dec" || doc.Title != "December 2026 Security Updates" {
		t.Fatalf("document identity = %q %q", doc.ID, doc.Title)
	}
	if len(doc.Products) != 3 {
		t.Fatalf("products = %d, want 3", len(doc.Products))
	}
	if p := doc.Products["12085"]; p.Name != "Windows 11 Version 24H2 for x64-based Systems" ||
		len(p.Family) < 2 || p.Family[len(p.Family)-1] != "Windows" {
		t.Fatalf("product 12085 = %+v", p)
	}
	if len(doc.CVEs) != 2 {
		t.Fatalf("cves = %d", len(doc.CVEs))
	}
	first := doc.CVEs[0]
	if first.ID != "CVE-2026-40001" || first.Severity != "Important" || first.CVSS != 8.8 {
		t.Fatalf("cve = %+v", first)
	}
	// A bare KB number and a KB-prefixed one both normalise.
	if first.Fixes[0].KB != "KB5044284" || first.Fixes[0].ProductName != "Windows 11 Version 24H2 for x64-based Systems" {
		t.Fatalf("fix = %+v", first.Fixes[0])
	}
	if len(first.Fixes[0].Supersedes) != 1 || first.Fixes[0].Supersedes[0] != "KB5041234" {
		t.Fatalf("supersedence = %v", first.Fixes[0].Supersedes)
	}
	if doc.CVEs[1].Fixes[0].KB != "KB5044285" {
		t.Fatalf("KB-prefixed remediation = %+v", doc.CVEs[1].Fixes[0])
	}
}

// A document that is not a security bundle (release notes) must be refused rather than stored
// as an empty advisory set that silently means "nothing to fix".
func TestParseDocumentRejectsNonSecurityBundles(t *testing.T) {
	if _, err := ParseDocument([]byte(`<cvrfdoc><DocumentTitle>Mariner Release Notes</DocumentTitle></cvrfdoc>`)); err == nil {
		t.Fatal("release notes were accepted as a security document")
	}
	if _, err := ParseDocument([]byte(`not xml`)); err == nil {
		t.Fatal("garbage was accepted")
	}
}

func TestExtractKBForms(t *testing.T) {
	cases := map[string]string{
		"5044284":                 "KB5044284",
		"KB5044284":               "KB5044284",
		" kb5044284 ":             "KB5044284",
		"Superseded by 5041234":   "",
		"Security Update 5044284": "",
		"":                        "",
	}
	for in, want := range cases {
		if got := extractKB(in); got != want {
			t.Fatalf("extractKB(%q) = %q, want %q", in, got, want)
		}
	}
}
