package netscan

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/intel"
	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/scope"
)

// testScope authorises loopback only, which is what the tests scan.
func testScope(t *testing.T) *model.Scope {
	t.Helper()
	data := []byte(`
name: unit-test
authorized_by: test
authorized_at: 2026-01-01T00:00:00Z
targets: [127.0.0.1]
max_hosts: 4
`)
	sc, err := scope.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	return &sc
}

func TestResolveEnforcesScopeOnResolvedAddresses(t *testing.T) {
	sc := testScope(t)
	targets, err := Resolve(context.Background(), Options{Scope: sc})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0] != "127.0.0.1" {
		t.Fatalf("unexpected targets: %v", targets)
	}
	if scope.Allows(*sc, "10.9.9.9") {
		t.Fatal("an address outside the authorised scope must never be allowed")
	}

	// Address-based scope: a hostname whose resolved address is outside is
	// refused, even though the hostname itself was not listed.
	addrScope := *sc
	addrScope.Targets = []string{"10.0.0.0/30", "web.example"}
	_, err = Resolve(context.Background(), Options{
		Scope: &addrScope,
		Lookup: func(context.Context, string) ([]string, error) {
			return []string{"10.9.9.9"}, nil
		},
	})
	if err == nil || !strings.Contains(err.Error(), "outside the authorised scope") {
		t.Fatalf("a hostname resolving outside the address scope must be rejected, got %v", err)
	}

	// Name-based scope: authorisation is by name; the address is resolved once,
	// recorded, and used immediately (no second lookup to rebind).
	nameScope := *sc
	nameScope.Targets = []string{"inside.example"}
	targets, err = Resolve(context.Background(), Options{
		Scope: &nameScope,
		Lookup: func(context.Context, string) ([]string, error) {
			return []string{"127.0.0.1"}, nil
		},
	})
	if err != nil || len(targets) != 1 || targets[0] != "127.0.0.1" {
		t.Fatalf("a hostname listed in the scope should resolve: %v %v", targets, err)
	}

	// CIDR expansion stays inside the range.
	cidr := *sc
	cidr.Targets = []string{"10.0.0.0/30"}
	targets, err = Resolve(context.Background(), Options{Scope: &cidr, Lookup: func(context.Context, string) ([]string, error) { return nil, nil }})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 4 {
		t.Fatalf("expected 4 addresses from /30, got %v", targets)
	}
}

func TestResolveRefusesWithoutScope(t *testing.T) {
	if _, err := Resolve(context.Background(), Options{}); err == nil {
		t.Fatal("network assessment without an authorised scope must fail")
	}
}

// startHTTPServer listens on loopback and returns its port.
func startHTTPServer(t *testing.T, handler http.Handler) int {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

func TestRunDiscoversAndFingerprintsHTTP(t *testing.T) {
	port := startHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "" {
			t.Error("assessment should identify itself in the User-Agent")
		}
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "PHP/8.2.7")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("<html><head><title>Welcome to nginx!</title></head></html>"))
	}))

	sc := testScope(t)
	sc.Ports = []int{port}
	res, err := Run(context.Background(), Options{Scope: sc, ConnectTimeout: time.Second, BannerTimeout: 500 * time.Millisecond, HTTPTimeout: 2 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Services) != 1 {
		t.Fatalf("expected one discovered service, got %d (%+v)", len(res.Services), res.Services)
	}
	svc := res.Services[0]
	if svc.Port != port || svc.HTTP == nil {
		t.Fatalf("service not fingerprinted: %+v", svc)
	}
	if svc.Product != "nginx" || svc.Version != "1.24.0" {
		t.Fatalf("expected nginx 1.24.0, got %q %q (server %q)", svc.Product, svc.Version, svc.HTTP.Server)
	}
	if svc.HTTP.Title != "Welcome to nginx!" {
		t.Fatalf("title not captured: %q", svc.HTTP.Title)
	}
	if svc.CPE == "" {
		t.Fatal("a fingerprinted product should yield a CPE for NVD correlation")
	}
	if len(res.Findings) == 0 {
		t.Fatal("version disclosure should produce a configuration finding")
	}
	for _, f := range res.Findings {
		if f.Severity == "" || f.Remediation == "" || len(f.Evidence) == 0 {
			t.Fatalf("finding must be actionable and evidenced: %+v", f)
		}
	}
}

func TestRunDiscoversClosedPortsAreNotReported(t *testing.T) {
	// Find a port that is closed by listening then closing.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()

	sc := testScope(t)
	sc.Ports = []int{port}
	res, err := Run(context.Background(), Options{Scope: sc, ConnectTimeout: 300 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Services) != 0 {
		t.Fatalf("closed port must not be reported: %+v", res.Services)
	}
}

func TestTLSInspectionFindsExpiredAndDeprecated(t *testing.T) {
	// Self-signed, expired certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired.test"},
		NotBefore:    time.Now().Add(-48 * time.Hour),
		NotAfter:     time.Now().Add(-24 * time.Hour),
		DNSNames:     []string{"expired.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS10})
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				// Complete the handshake so the client can read the certificate.
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.Handshake()
				}
				time.Sleep(200 * time.Millisecond)
				_ = c.Close()
			}(conn)
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	sc := testScope(t)
	sc.Ports = []int{port}
	res, err := Run(context.Background(), Options{Scope: sc, ConnectTimeout: time.Second, BannerTimeout: 300 * time.Millisecond, HTTPTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Services) != 1 || res.Services[0].TLS == nil {
		t.Fatalf("TLS should be observed: %+v", res.Services)
	}
	if !res.Services[0].TLS.SelfSigned {
		t.Fatalf("expected self-signed detection: %+v", res.Services[0].TLS)
	}
	var expired, selfSigned bool
	for _, f := range res.Findings {
		if strings.Contains(f.Title, "expired") {
			expired = true
		}
		if strings.Contains(f.Title, "self-signed") {
			selfSigned = true
		}
	}
	if !expired || !selfSigned {
		t.Fatalf("expected expiry and self-signed findings, got %+v", res.Findings)
	}
}

func TestBannersAreSanitised(t *testing.T) {
	got := sanitizeBanner("SSH-2.0-OpenSSH_9.6p1\u0000\u0007evil\r\n")
	if strings.ContainsAny(got, "\x00\x07\r\n") {
		t.Fatalf("control characters must be stripped: %q", got)
	}
	long := sanitizeBanner(strings.Repeat("A", 500))
	if len(long) > 200 {
		t.Fatalf("banner must be bounded: %d", len(long))
	}
}

func TestSSHBannerParsing(t *testing.T) {
	svc := Service{Banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20"}
	identifySSH(&svc)
	classify(&svc)
	if svc.Product != "openssh" || svc.Version != "9.6p1" || svc.Vendor != "openbsd" {
		t.Fatalf("unexpected SSH fingerprint: %+v", svc)
	}
	if svc.CPE != "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*" {
		t.Fatalf("unexpected CPE: %q", svc.CPE)
	}
}

func TestPackageAndAdvisoryShape(t *testing.T) {
	svc := Service{Host: "web-01", Port: 443, Product: "nginx", Version: "1.24.0", Vendor: "nginx"}
	pkg, ok := PackageFor(svc)
	if !ok || pkg.Ecosystem != EcosystemService || pkg.Name != "nginx:nginx" {
		t.Fatalf("unexpected package: %+v ok=%v", pkg, ok)
	}
	adv := AdvisoryFor(pkg, CVEMatch{ID: "CVE-2024-0001", Description: "test", URL: "https://nvd.nist.gov/vuln/detail/CVE-2024-0001"}, time.Now())
	if adv.Source != "NVD" || len(adv.Affected) != 1 || adv.Affected[0].Versions[0] != "1.24.0" {
		t.Fatalf("unexpected advisory: %+v", adv)
	}
	// The package ecosystem is deliberately distinct from the NVD advisory
	// ecosystem so the engine cannot re-derive network findings.
	if pkg.Ecosystem == EcosystemNVD {
		t.Fatal("service packages must not share the NVD advisory ecosystem")
	}
	// A service without a version cannot be correlated: it must be skipped.
	if _, ok := PackageFor(Service{Product: "nginx"}); ok {
		t.Fatal("a product without a version must not be correlated")
	}
}

func TestNVDClientRateLimitAndParse(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if !strings.Contains(r.URL.RawQuery, "virtualMatchString") {
			t.Errorf("expected a CPE query, got %s", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(`{"vulnerabilities":[{"cve":{"id":"CVE-2023-48795",
			"published":"2023-12-18T16:15:10.897",
			"descriptions":[{"lang":"en","value":"Terrapin prefix truncation"}],
			"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":5.9,"vectorString":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N"}}]},
			"references":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2023-48795"}]}}]}`))
	}))
	defer srv.Close()

	c := &NVDClient{BaseURL: srv.URL, HTTP: srv.Client(), MinInterval: 0, now: func() time.Time { return time.Now() }}
	got, err := c.MatchCPE(context.Background(), "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "CVE-2023-48795" || got[0].CVSS == nil {
		t.Fatalf("unexpected NVD parse: %+v", got)
	}
	if calls != 1 {
		t.Fatalf("expected one request, got %d", calls)
	}

	// HTTP failures must surface, never be treated as "no vulnerabilities".
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream down", http.StatusServiceUnavailable)
	}))
	defer errSrv.Close()
	bad := &NVDClient{BaseURL: errSrv.URL, HTTP: errSrv.Client(), now: func() time.Time { return time.Now() }}
	if _, err := bad.MatchCPE(context.Background(), "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"); err == nil {
		t.Fatal("NVD failure must be reported")
	}
}

// TestDistroBuildIsNotConfirmedFromUpstreamVersion is the regression test for the
// defect found by scanning this host: NVD matched upstream OpenSSH 9.6p1 and the
// scanner reported 28 "confirmed" CVEs for a patched Ubuntu build.
func TestDistroBuildIsNotConfirmedFromUpstreamVersion(t *testing.T) {
	svc := Service{
		Host: "host1", Port: 22, Product: "openssh", Version: "9.6p1",
		Vendor: "openbsd", CPE: "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*",
		Banner: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20",
	}
	identifySSH(&svc)
	classify(&svc)
	if !svc.DistroBuild || svc.Distro != "Ubuntu" {
		t.Fatalf("distro packaging not detected: %+v", svc)
	}
	if svc.DistroVersion == "" {
		t.Fatalf("distro version not captured: %+v", svc)
	}

	match := CVEMatch{ID: "CVE-2024-6387", Description: "regreSSHion",
		CVSS: &intel.CVSS{Score: 8.1, Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}}
	f := FindingForAdvisory(svc, match, time.Now())
	if f.Affected != model.ApplicabilityNeedsInvestigation {
		t.Fatalf("a distro build must not be confirmed from upstream version data, got %s", f.Affected)
	}
	if f.Confidence != model.ConfidenceLow {
		t.Fatalf("confidence should be low for a backport-dependent match: %s", f.Confidence)
	}
	var hasDistroEvidence bool
	for _, e := range f.Evidence {
		if e.Kind == "distro_build" {
			hasDistroEvidence = true
		}
	}
	if !hasDistroEvidence {
		t.Fatalf("evidence must show the distribution build: %+v", f.Evidence)
	}
	if len(f.LowerConfidence) == 0 || len(f.RaiseConfidence) == 0 {
		t.Fatalf("the finding must say what would change the verdict: %+v", f)
	}

	// An upstream build (no distro marker) is still version-level probable.
	upstream := Service{Host: "host2", Port: 22, Product: "openssh", Version: "9.6p1",
		Banner: "SSH-2.0-OpenSSH_9.6p1", CPE: "cpe:2.3:a:openbsd:openssh:9.6p1:*:*:*:*:*:*:*"}
	identifySSH(&upstream)
	classify(&upstream)
	if upstream.DistroBuild {
		t.Fatalf("plain upstream banner misdetected as a distro build: %+v", upstream)
	}
	f2 := FindingForAdvisory(upstream, match, time.Now())
	if f2.Affected != model.ApplicabilityProbable {
		t.Fatalf("upstream build should be probable, got %s", f2.Affected)
	}
}
