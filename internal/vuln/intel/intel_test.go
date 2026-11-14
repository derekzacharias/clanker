package intel

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestParseOSVRecordAndCVEIDs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "osv_ubuntu.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	adv, err := parseOSVRecord(doc, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if adv.ID != "UBUNTU-CVE-2026-107496" || adv.Source != "Ubuntu" {
		t.Fatalf("unexpected identity: %+v", adv)
	}
	if len(adv.Affected) == 0 {
		t.Fatal("affected entries were dropped")
	}
	var found bool
	for _, a := range adv.Affected {
		if a.Ecosystem == "Ubuntu:24.04:LTS" {
			found = true
			if len(a.Versions) == 0 {
				t.Fatal("version enumeration lost")
			}
			if len(a.Binaries) == 0 {
				t.Fatal("binary view lost (needed for dpkg package matching)")
			}
		}
	}
	if !found {
		t.Fatal("Ubuntu 24.04 affected entry not parsed")
	}

	cves := adv.CVEIDs()
	if len(cves) != 1 || cves[0] != "CVE-2026-107496" {
		t.Fatalf("CVE extraction from a distro ID failed: %v", cves)
	}
}

func TestAdvisoryCVEIDsPrefersAliases(t *testing.T) {
	a := Advisory{ID: "GHSA-xxxx-yyyy-zzzz", Aliases: []string{"CVE-2022-37454", "PYSEC-2026-504"}}
	got := a.CVEIDs()
	if len(got) != 1 || got[0] != "CVE-2022-37454" {
		t.Fatalf("unexpected CVE ids: %v", got)
	}
}

func TestCVSSBaseScores(t *testing.T) {
	cases := map[string]float64{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H": 8.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
		"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H": 6.5,
		"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N": 1.8,
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N": 0.0,
	}
	for vector, want := range cases {
		v, ok := ParseCVSSVector(vector)
		if !ok {
			t.Fatalf("vector not parsed: %s", vector)
		}
		got, ok := v.BaseScore()
		if !ok {
			t.Fatalf("score not computed: %s", vector)
		}
		if diff := got - want; diff > 0.05 || diff < -0.05 {
			t.Errorf("%s => %.1f, want %.1f", vector, got, want)
		}
	}
	// CVSS v4 must not be silently approximated
	v4, _ := ParseCVSSVector("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N")
	if _, ok := v4.BaseScore(); ok {
		t.Error("CVSS v4 must not be scored with the v3.1 algorithm")
	}
}

func TestInterpretSeverities(t *testing.T) {
	sev, cvss, _, src := InterpretSeverities([]SeverityEntry{
		{Type: "Ubuntu", Score: "medium"},
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	})
	if sev != "medium" {
		t.Fatalf("vendor word severity should win, got %q", sev)
	}
	if cvss == nil || cvss.Score != 9.8 {
		t.Fatalf("numeric CVSS should still be captured: %+v", cvss)
	}
	if src != "Ubuntu" {
		t.Fatalf("severity source not reported: %q", src)
	}

	sev, cvss, _, _ = InterpretSeverities([]SeverityEntry{
		{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
	})
	if sev != "critical" || cvss == nil || cvss.Score != 9.8 {
		t.Fatalf("CVSS-derived severity wrong: %q %+v", sev, cvss)
	}
}

func TestStoreAdvisoryRoundTrip(t *testing.T) {
	store, err := OpenStore(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()

	if err := store.SaveAdvisories(ctx, []Advisory{debianFixture()}); err != nil {
		t.Fatal(err)
	}
	got, err := store.AdvisoriesFor(ctx, "Debian:12", "openssl")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "DEBIAN-CVE-2023-5678" {
		t.Fatalf("cache lookup failed: %+v", got)
	}
	// case-insensitive lookup by package name
	if again, _ := store.AdvisoriesFor(ctx, "Debian:12", "OpenSSL"); len(again) != 1 {
		t.Fatalf("package index is not case-insensitive: %d", len(again))
	}
	// unknown package returns nothing (not an error)
	if none, err := store.AdvisoriesFor(ctx, "Debian:12", "not-installed"); err != nil || len(none) != 0 {
		t.Fatalf("unexpected result for unknown package: %v %v", none, err)
	}
	if n, _ := store.AdvisoryCount(ctx); n != 1 {
		t.Fatalf("advisory count = %d", n)
	}
}

func TestKEVAndEPSSFetchAndStore(t *testing.T) {
	kev := `{"title":"test","vulnerabilities":[
		{"cveID":"CVE-2024-0001","vendorProject":"Acme","product":"Widget","vulnerabilityName":"Widget RCE","dateAdded":"2024-01-02","knownRansomwareCampaignUse":"Known"},
		{"cveID":"CVE-2024-0002","vendorProject":"Acme","product":"Gadget","vulnerabilityName":"Gadget XSS","dateAdded":"2024-02-03"}]}`
	epss := "#model_version:v2024.01.01,score_date:2024-01-05T00:00:00Z\ncve,epss,percentile\nCVE-2024-0001,0.91,0.99\nCVE-2024-0002,0.02,0.4\n"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/kev.json":
			w.Write([]byte(kev))
		case "/epss.csv.gz":
			w.Header().Set("Content-Type", "application/gzip")
			w.Write(gzipBytes(t, epss))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	f := &Fetcher{HTTP: srv.Client(), KEVURL: srv.URL + "/kev.json", EPSSURL: srv.URL + "/epss.csv.gz"}
	kevEntries, err := f.FetchKEV(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(kevEntries) != 2 || kevEntries[0].Ransomware != "Known" {
		t.Fatalf("KEV parse wrong: %+v", kevEntries)
	}
	epssEntries, err := f.FetchEPSS(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(epssEntries) != 2 || epssEntries[0].Model != "v2024.01.01" || epssEntries[0].Score != 0.91 {
		t.Fatalf("EPSS parse wrong: %+v", epssEntries)
	}

	store, err := OpenStore(filepath.Join(t.TempDir(), "cache.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.SaveKEV(context.Background(), kevEntries); err != nil {
		t.Fatal(err)
	}
	if err := store.SaveEPSS(context.Background(), epssEntries, 10); err != nil {
		t.Fatal(err)
	}
	gotKEV, ok, err := store.KEVFor(context.Background(), "CVE-2024-0001")
	if err != nil || !ok || gotKEV.Product != "Widget" {
		t.Fatalf("KEV lookup failed: %+v %v", gotKEV, err)
	}
	gotEPSS, ok, err := store.EPSSFor(context.Background(), "CVE-2024-0001")
	if err != nil || !ok || gotEPSS.Percentile != 0.99 {
		t.Fatalf("EPSS lookup failed: %+v %v", gotEPSS, err)
	}
	if _, ok, _ := store.KEVFor(context.Background(), "CVE-1999-9999"); ok {
		t.Fatal("unknown CVE must not report KEV membership (BOMBS-style false negative risk)")
	}
}

func TestFetchersFailLoudly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}))
	defer srv.Close()
	f := &Fetcher{HTTP: srv.Client(), KEVURL: srv.URL + "/kev", EPSSURL: srv.URL + "/epss"}
	if _, err := f.FetchKEV(context.Background()); err == nil {
		t.Error("KEV fetch must return an error on HTTP failure")
	}
	if _, err := f.FetchEPSS(context.Background()); err == nil {
		t.Error("EPSS fetch must return an error on HTTP failure")
	}
}

func TestOSVClientParsesBatchAndDetails(t *testing.T) {
	batch := `{"results":[{"vulns":[{"id":"UBUNTU-CVE-2026-107496","modified":"2024-01-01T00:00:00Z"}]},{"vulns":[]}]}`
	detail, err := os.ReadFile(filepath.Join("testdata", "osv_ubuntu.json"))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			w.Write([]byte(batch))
		case r.URL.Path == "/v1/vulns/UBUNTU-CVE-2026-107496":
			w.Write(detail)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := &OSVClient{BaseURL: srv.URL, HTTP: srv.Client(), MaxBatch: 10}
	refs, err := c.QueryBatch(context.Background(), []Query{
		{Ecosystem: "Ubuntu:24.04:LTS", Name: "openssl", Version: "3.0.13-0ubuntu3.5"},
		{Ecosystem: "PyPI", Name: "requests", Version: "2.31.0"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(refs) != 2 || len(refs[0]) != 1 || len(refs[1]) != 0 {
		t.Fatalf("batch results mis-assigned: %+v", refs)
	}
	adv, err := c.FetchVuln(context.Background(), "UBUNTU-CVE-2026-107496")
	if err != nil {
		t.Fatal(err)
	}
	if adv.ID != "UBUNTU-CVE-2026-107496" {
		t.Fatalf("detail fetch wrong: %+v", adv)
	}

	// an upstream error must surface, never be treated as "no vulnerabilities"
	srvErr := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srvErr.Close()
	cErr := &OSVClient{BaseURL: srvErr.URL, HTTP: srvErr.Client()}
	if _, err := cErr.QueryBatch(context.Background(), []Query{{Ecosystem: "PyPI", Name: "x", Version: "1.0"}}); err == nil {
		t.Fatal("querybatch failure must be reported")
	}
}

func debianFixture() Advisory {
	return Advisory{
		ID:     "DEBIAN-CVE-2023-5678",
		Source: "Debian",
		Affected: []Affected{{
			Ecosystem: "Debian:12",
			Name:      "openssl",
			Ranges:    []Range{{Type: "ECOSYSTEM", Events: []Event{{Introduced: "0"}, {Fixed: "3.0.13-1~deb12u1"}}}},
		}},
		FetchedAt: time.Now().UTC(),
	}
}

func gzipBytes(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestValidEcosystem(t *testing.T) {
	valid := []string{
		"Ubuntu:24.04:LTS", "Ubuntu:26.10", "Debian:12", "Alpine:v3.19",
		"Red Hat:9", "Rocky Linux:9", "AlmaLinux:9.3", "Fedora:40",
		"PyPI", "npm", "Go", "crates.io", "Maven", "RubyGems", "Packagist",
	}
	for _, eco := range valid {
		if !ValidEcosystem(eco) {
			t.Errorf("%q should be accepted", eco)
		}
	}
	// These are the strings that OSV silently answered "no results" for.
	invalid := []string{"", "unknown", "Alpine:3.21.3", "Alpine:3.19", "Ubuntu", "Debian", "network-service"}
	for _, eco := range invalid {
		if ValidEcosystem(eco) {
			t.Errorf("%q must be rejected: OSV cannot answer for it", eco)
		}
	}
}
