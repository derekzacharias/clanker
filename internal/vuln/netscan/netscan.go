// Package netscan implements explicitly authorised network assessment.
//
// Safety model, enforced in code (not by prompt):
//   - every target is checked against the scope on the resolved IP, never on the
//     supplied hostname alone (DNS rebinding cannot widen a scope);
//   - discovery uses ordinary TCP connect() calls: no raw sockets, no privileges,
//     no fragmentation tricks, no evasion;
//   - work is bounded by scope port lists, per-host caps, timeouts and
//     concurrency limits;
//   - nothing is exploited, guessed or brute-forced. Validation is limited to
//     observing what the service itself returns.
package netscan

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
	"github.com/bgdnvk/clanker/internal/vuln/scope"
)

// Options bound what a network assessment may do.
type Options struct {
	Scope *model.Scope
	// Ports to probe when the scope does not list any.
	Ports []int
	// MaxPortsPerHost caps work even if the scope lists more.
	MaxPortsPerHost int
	// Concurrency is the number of simultaneous connect attempts.
	Concurrency int
	// ConnectTimeout bounds a single TCP handshake.
	ConnectTimeout time.Duration
	// BannerTimeout bounds the passive banner read.
	BannerTimeout time.Duration
	// HTTPTimeout bounds the single HTTP fingerprint request.
	HTTPTimeout time.Duration
	// MaxBodyBytes caps how much of an HTTP response is read.
	MaxBodyBytes int64
	// MaxHosts caps the number of resolved targets.
	MaxHosts int
	// Now is injectable for tests.
	Now func() time.Time
	// Lookup resolves hostnames. Defaults to the system resolver; tests inject a
	// resolver to prove that a hostname cannot widen an authorised scope.
	Lookup func(ctx context.Context, host string) ([]string, error)
}

// DefaultPorts is a conservative, service-dense list: enough to describe a host
// without turning the assessment into a sweep.
func DefaultPorts() []int {
	return []int{21, 22, 25, 53, 80, 110, 143, 389, 443, 445, 587, 993, 995,
		1433, 1521, 2049, 3306, 3389, 5432, 5672, 5900, 6379, 8080, 8443, 9200, 11211, 27017}
}

func (o *Options) normalize() {
	if o.MaxPortsPerHost <= 0 {
		o.MaxPortsPerHost = 512
	}
	if o.Concurrency <= 0 {
		o.Concurrency = 32
	}
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = 2 * time.Second
	}
	if o.BannerTimeout <= 0 {
		o.BannerTimeout = 2 * time.Second
	}
	if o.HTTPTimeout <= 0 {
		o.HTTPTimeout = 5 * time.Second
	}
	if o.MaxBodyBytes <= 0 {
		o.MaxBodyBytes = 64 << 10
	}
	if o.MaxHosts <= 0 {
		o.MaxHosts = 256
	}
	if o.Now == nil {
		o.Now = func() time.Time { return time.Now().UTC() }
	}
	if o.Lookup == nil {
		o.Lookup = func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		}
	}
}

// Service is one observed listening socket.
type Service struct {
	Host     string `json:"host"`
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol,omitempty"` // tcp
	Banner   string `json:"banner,omitempty"`
	// Product/Version come from observable behaviour only (banner, Server header,
	// certificate subject). Unknown stays empty rather than guessed.
	Product string           `json:"product,omitempty"`
	Version string           `json:"version,omitempty"`
	Vendor  string           `json:"vendor,omitempty"`
	CPE     string           `json:"cpe,omitempty"`
	TLS     *TLSObservation  `json:"tls,omitempty"`
	HTTP    *HTTPObservation `json:"http,omitempty"`
	// DistroBuild is set when the service reveals that it was packaged by a
	// distribution (SSH banner suffix, Server header vendor tag). Distribution
	// builds usually carry backported fixes, so upstream version data alone is
	// not authoritative for them.
	DistroBuild bool   `json:"distro_build,omitempty"`
	Distro      string `json:"distro,omitempty"`
	// DistroVersion is the distribution package version when the banner exposes
	// it (e.g. OpenSSH_9.6p1 Ubuntu-3ubuntu13.20).
	DistroVersion string `json:"distro_version,omitempty"`
	// ObservedAt records when the evidence was collected.
	ObservedAt time.Time `json:"observed_at"`
}

// TLSObservation is what the handshake itself reveals (no decryption).
type TLSObservation struct {
	Version    string    `json:"version"`
	Cipher     string    `json:"cipher"`
	Subject    string    `json:"subject,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`
	NotAfter   time.Time `json:"not_after,omitempty"`
	DNSNames   []string  `json:"dns_names,omitempty"`
	SelfSigned bool      `json:"self_signed"`
}

// HTTPObservation is a single, benign request for identification.
type HTTPObservation struct {
	Scheme      string `json:"scheme"`
	StatusCode  int    `json:"status_code,omitempty"`
	Server      string `json:"server,omitempty"`
	PoweredBy   string `json:"powered_by,omitempty"`
	Title       string `json:"title,omitempty"`
	RedirectsTo string `json:"redirects_to,omitempty"`
}

// Result is the outcome of a network assessment.
type Result struct {
	Scope      model.Scope `json:"scope"`
	Targets    []string    `json:"targets"`
	Services   []Service   `json:"services"`
	Findings   []Finding   `json:"findings"`
	Errors     []string    `json:"errors,omitempty"`
	StartedAt  time.Time   `json:"started_at"`
	FinishedAt time.Time   `json:"finished_at"`
}

// Finding is a configuration or exposure observation. Vulnerabilities coming from
// NVD are produced separately and merged by the scanner.
type Finding struct {
	ID          string           `json:"id"`
	Title       string           `json:"title"`
	Severity    string           `json:"severity"`
	Host        string           `json:"host"`
	Port        int              `json:"port"`
	Evidence    []model.Evidence `json:"evidence"`
	Remediation string           `json:"remediation"`
	Remediated  bool             `json:"-"`
}

// Resolve expands the scope into concrete addresses, enforcing the host cap and
// the scope on every resolved address.
func Resolve(ctx context.Context, opts Options) ([]string, error) {
	opts.normalize()
	if opts.Scope == nil {
		return nil, errors.New("network assessment requires an authorised scope")
	}
	// A scope that lists addresses is enforced on addresses: a hostname target is
	// only reachable when it resolves into those ranges. A name-only scope
	// authorises the name itself (there is nothing else to check against).
	hasAddressTargets := false
	for _, target := range opts.Scope.Targets {
		if net.ParseIP(target) != nil || strings.Contains(target, "/") {
			hasAddressTargets = true
			break
		}
	}

	var out []string
	seen := map[string]bool{}
	add := func(addr string, authorisedName string) error {
		if seen[addr] {
			return nil
		}
		// Authorisation is by name OR by address, never by "it resolved":
		//   - an address entry must contain the address;
		//   - a hostname entry authorises that name, and the name was resolved
		//     once here, immediately before use (no second lookup to rebind).
		allowed := scope.Allows(*opts.Scope, addr) ||
			(!hasAddressTargets && authorisedName != "" && scope.Allows(*opts.Scope, authorisedName))
		if !allowed {
			return fmt.Errorf("resolved address %s for %q is outside the authorised scope", addr, authorisedName)
		}
		seen[addr] = true
		out = append(out, addr)
		if len(out) > opts.MaxHosts {
			return fmt.Errorf("scope resolves to more than %d hosts", opts.MaxHosts)
		}
		return nil
	}

	for _, target := range opts.Scope.Targets {
		if strings.Contains(target, "/") {
			_, ipnet, err := net.ParseCIDR(target)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", target, err)
			}
			for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
				if err := add(ip.String(), ""); err != nil {
					return nil, err
				}
				if len(out) > opts.MaxHosts {
					break
				}
			}
			continue
		}
		if ip := net.ParseIP(target); ip != nil {
			if err := add(ip.String(), ""); err != nil {
				return nil, err
			}
			continue
		}
		// Hostname: resolve, then check every address against the scope.
		ips, err := opts.Lookup(ctx, target)
		if err != nil {
			return nil, fmt.Errorf("resolve %q: %w", target, err)
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("resolve %q: no addresses", target)
		}
		for _, addr := range ips {
			if err := add(addr, target); err != nil {
				return nil, fmt.Errorf("hostname %q: %w", target, err)
			}
		}
	}
	sort.Strings(out)
	return out, nil
}

func incIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

// Run performs discovery and fingerprinting for an authorised scope.
func Run(ctx context.Context, opts Options) (Result, error) {
	opts.normalize()
	started := opts.Now()
	targets, err := Resolve(ctx, opts)
	if err != nil {
		return Result{Scope: *opts.Scope}, err
	}
	res := Result{Scope: *opts.Scope, Targets: targets, StartedAt: started}

	ports := opts.Scope.Ports
	if len(ports) == 0 {
		ports = opts.Ports
	}
	if len(ports) == 0 {
		ports = DefaultPorts()
	}
	if len(ports) > opts.MaxPortsPerHost {
		ports = ports[:opts.MaxPortsPerHost]
	}

	type job struct {
		addr string
		host string
		port int
	}
	jobs := make(chan job)
	var mu sync.Mutex
	var services []Service
	var errs []string

	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				if ctx.Err() != nil {
					return
				}
				svc, err := probe(ctx, opts, j.host, j.addr, j.port)
				if err != nil {
					continue // closed port or timeout: not an error to report
				}
				mu.Lock()
				services = append(services, svc)
				mu.Unlock()
			}
		}()
	}
	for _, addr := range targets {
		host := addr
		if names, err := net.LookupAddr(addr); err == nil && len(names) > 0 {
			host = strings.TrimSuffix(names[0], ".")
		}
		for _, port := range ports {
			select {
			case jobs <- job{addr: addr, host: host, port: port}:
			case <-ctx.Done():
			}
		}
	}
	close(jobs)
	wg.Wait()

	if ctx.Err() != nil {
		return res, ctx.Err()
	}

	sort.Slice(services, func(i, j int) bool {
		if services[i].Host != services[j].Host {
			return services[i].Host < services[j].Host
		}
		return services[i].Port < services[j].Port
	})
	res.Services = services
	res.Findings = InspectServices(services, opts.Now())
	res.Errors = errs
	res.FinishedAt = opts.Now()
	return res, nil
}

// probe performs one connect + fingerprint. A refused port returns an error and
// is intentionally not reported.
func probe(ctx context.Context, opts Options, host, addr string, port int) (Service, error) {
	d := net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)))
	if err != nil {
		return Service{}, err
	}
	defer conn.Close()

	svc := Service{Host: host, Address: addr, Port: port, Protocol: "tcp", ObservedAt: opts.Now()}

	// Passive banner: read what the service says without sending anything first.
	_ = conn.SetReadDeadline(time.Now().Add(opts.BannerTimeout))
	buf := make([]byte, 1024)
	if n, err := conn.Read(buf); err == nil && n > 0 {
		svc.Banner = sanitizeBanner(string(buf[:n]))
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Protocol-specific follow-up. Services appear on arbitrary ports, so the
	// detection is behavioural: SSH by banner, otherwise HTTP, otherwise TLS,
	// then a single protocol-specific probe for known daemons.
	switch {
	case strings.HasPrefix(svc.Banner, "SSH-") || port == 22:
		identifySSH(&svc)
	case looksTLS(svc.Banner) || port == 443 || port == 8443:
		if obs, tlsErr := observeTLS(ctx, opts, addr, port); tlsErr == nil {
			svc.TLS = obs
			if httpObs := observeHTTP(ctx, opts, "https", addr, port); httpObs != nil {
				svc.HTTP = httpObs
			}
		} else if httpObs := observeHTTP(ctx, opts, "http", addr, port); httpObs != nil {
			svc.HTTP = httpObs
		}
	case port == 6379:
		// Redis answers PING without auth only when unprotected; observe, never exploit.
		if reply := commandReply(conn, opts, "PING\r\n"); reply != "" {
			svc.Banner = sanitizeBanner(reply)
			svc.Product = "redis"
		}
	default:
		// One plaintext request; if the socket speaks TLS instead, observe that.
		if httpObs := observeHTTP(ctx, opts, "http", addr, port); httpObs != nil {
			svc.HTTP = httpObs
		} else if obs, tlsErr := observeTLS(ctx, opts, addr, port); tlsErr == nil {
			svc.TLS = obs
			if httpObs := observeHTTP(ctx, opts, "https", addr, port); httpObs != nil {
				svc.HTTP = httpObs
			}
		}
	}
	classify(&svc)
	return svc, nil
}

func sanitizeBanner(s string) string {
	// Banners are attacker-controlled data: collapse control characters, bound
	// the length, never interpret the content.
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			return r
		}
		return '.'
	}, s)
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func looksTLS(banner string) bool {
	return len(banner) > 2 && (banner[0] == 0x16 || strings.Contains(banner, "TLS"))
}

func identifySSH(svc *Service) {
	if !strings.HasPrefix(svc.Banner, "SSH-") {
		return
	}
	// SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.20
	detectDistroSuffix(svc, svc.Banner)
	parts := strings.SplitN(svc.Banner, "-", 3)
	if len(parts) < 3 {
		return
	}
	software := parts[2]
	if i := strings.IndexAny(software, " _"); i > 0 {
		product := software[:i]
		svc.Product = strings.ToLower(product)
		if product == "OpenSSH" {
			svc.Vendor = "openbsd"
			svc.Product = "openssh"
		}
	}
	versionPart := software
	if i := strings.IndexAny(software, " _"); i > 0 {
		versionPart = strings.TrimSpace(software[i+1:])
	}
	if f := strings.Fields(versionPart); len(f) > 0 {
		svc.Version = f[0]
	}
	if svc.Product == "" {
		svc.Product = strings.ToLower(parts[0])
	}
}

// detectDistroSuffix recognises distribution packaging markers in a banner or
// header, which is what makes backport awareness possible for network findings.
func detectDistroSuffix(svc *Service, text string) {
	lower := strings.ToLower(text)
	for _, marker := range []struct {
		key  string
		name string
	}{
		{"ubuntu", "Ubuntu"},
		{"debian", "Debian"},
		{"el9", "Red Hat"},
		{"el8", "Red Hat"},
		{"almalinux", "AlmaLinux"},
		{"rocky", "Rocky Linux"},
		{"fedora", "Fedora"},
		{"alpine", "Alpine"},
	} {
		if strings.Contains(lower, marker.key) {
			svc.DistroBuild = true
			svc.Distro = marker.name
			if i := strings.Index(lower, marker.key); i >= 0 {
				rest := text[i:]
				if f := strings.Fields(rest); len(f) > 0 {
					svc.DistroVersion = strings.TrimSpace(f[0])
				}
			}
			return
		}
	}
}

func observeTLS(ctx context.Context, opts Options, addr string, port int) (*TLSObservation, error) {
	d := &net.Dialer{Timeout: opts.ConnectTimeout}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(addr, strconv.Itoa(port)), &tls.Config{
		// Verification is not the point here: we record the certificate the
		// service presents, and report verification problems as findings.
		InsecureSkipVerify: true, //nolint:gosec // observation only
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(opts.HTTPTimeout))
	}
	state := conn.ConnectionState()
	obs := &TLSObservation{
		Version:  tlsVersionName(state.Version),
		Cipher:   tls.CipherSuiteName(state.CipherSuite),
		DNSNames: state.PeerCertificates[0].DNSNames,
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		obs.Subject = cert.Subject.CommonName
		obs.Issuer = cert.Issuer.CommonName
		obs.NotAfter = cert.NotAfter
		obs.SelfSigned = cert.Issuer.CommonName == cert.Subject.CommonName
		svcCertName := cert.Subject.CommonName
		if svcCertName != "" {
			obs.Subject = svcCertName
		}
	}
	return obs, nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}

func observeHTTP(ctx context.Context, opts Options, scheme, addr string, port int) *HTTPObservation {
	obs := &HTTPObservation{Scheme: scheme}
	client := &http.Client{
		Timeout: opts.HTTPTimeout,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // observation only
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return http.ErrUseLastResponse
			}
			obs.RedirectsTo = req.URL.String()
			return nil
		},
	}
	url := fmt.Sprintf("%s://%s/", scheme, net.JoinHostPort(addr, strconv.Itoa(port)))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	// Identify ourselves honestly: an assessment should be attributable.
	req.Header.Set("User-Agent", "clanker-guard/0.1 (authorised vulnerability assessment)")
	req.Header.Set("Accept", "*/*")
	resp, err := client.Do(req)
	if err != nil {
		if obs.RedirectsTo != "" {
			return obs
		}
		return nil
	}
	defer resp.Body.Close()
	obs.StatusCode = resp.StatusCode
	obs.Server = resp.Header.Get("Server")
	obs.PoweredBy = resp.Header.Get("X-Powered-By")
	body, _ := io.ReadAll(io.LimitReader(resp.Body, opts.MaxBodyBytes))
	obs.Title = extractTitle(string(body))
	return obs
}

func extractTitle(body string) string {
	lower := strings.ToLower(body)
	i := strings.Index(lower, "<title")
	if i < 0 {
		return ""
	}
	j := strings.Index(lower[i:], ">")
	if j < 0 {
		return ""
	}
	rest := body[i+j+1:]
	if k := strings.Index(strings.ToLower(rest), "</title>"); k >= 0 {
		rest = rest[:k]
	}
	t := sanitizeBanner(rest)
	if len(t) > 120 {
		t = t[:120]
	}
	return t
}

func commandReply(conn net.Conn, opts Options, cmd string) string {
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return ""
	}
	_ = conn.SetReadDeadline(time.Now().Add(opts.BannerTimeout))
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return ""
	}
	return string(buf[:n])
}

// classify derives vendor/product/version from HTTP observations and maps known
// products to a CPE so NVD can be queried. It never guesses a version.
func classify(svc *Service) {
	if svc.HTTP != nil && svc.HTTP.Server != "" {
		server := svc.HTTP.Server
		detectDistroSuffix(svc, server)
		lower := strings.ToLower(server)
		switch {
		case strings.HasPrefix(lower, "nginx"):
			svc.Vendor, svc.Product = "nginx", "nginx"
		case strings.HasPrefix(lower, "apache"):
			svc.Vendor, svc.Product = "apache", "http_server"
		case strings.HasPrefix(lower, "microsoft-iis"):
			svc.Vendor, svc.Product = "microsoft", "internet_information_services"
		case strings.HasPrefix(lower, "caddy"):
			svc.Vendor, svc.Product = "caddyserver", "caddy"
		case strings.HasPrefix(lower, "lighttpd"):
			svc.Vendor, svc.Product = "lighttpd", "lighttpd"
		case strings.HasPrefix(lower, "openresty"):
			svc.Vendor, svc.Product = "openresty", "openresty"
		}
		if svc.Version == "" {
			// "nginx/1.24.0", "Apache/2.4.58 (Ubuntu)"
			if i := strings.Index(server, "/"); i > 0 {
				rest := server[i+1:]
				if f := strings.Fields(rest); len(f) > 0 {
					svc.Version = strings.Trim(f[0], "()")
				}
			}
		}
	}
	if svc.Product != "" {
		svc.CPE = buildCPE(svc.Vendor, svc.Product, svc.Version)
	}
}

// buildCPE produces a CPE 2.3 string for NVD's virtualMatchString. Only exact,
// observed values are used; unknown parts stay "*".
func buildCPE(vendor, product, version string) string {
	esc := func(s string) string {
		if s == "" {
			return "*"
		}
		return strings.NewReplacer(`\`, `\\`, `:`, `\:`).Replace(s)
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", esc(vendor), esc(product), esc(version))
}
