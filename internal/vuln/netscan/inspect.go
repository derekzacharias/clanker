package netscan

import (
	"fmt"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// InspectServices turns observations into configuration and exposure findings.
//
// These are observations of what the service is doing right now, not CVE
// matches: each one carries the evidence that produced it, and none of them is
// labelled "exploitable".
func InspectServices(services []Service, now time.Time) []Finding {
	var out []Finding
	seq := 0
	add := func(title, severity, host string, port int, evidence []model.Evidence, remediation string) {
		seq++
		out = append(out, Finding{
			ID:          fmt.Sprintf("NET-%04d", seq),
			Title:       title,
			Severity:    severity,
			Host:        host,
			Port:        port,
			Evidence:    evidence,
			Remediation: remediation,
		})
	}

	// A plain-HTTP listener is only noteworthy when the same host also speaks
	// HTTPS; otherwise it is simply the service.
	httpsHosts := map[string]bool{}
	for _, s := range services {
		if s.TLS != nil {
			httpsHosts[s.Host] = true
		}
	}

	for _, s := range services {
		where := fmt.Sprintf("%s:%d", s.Host, s.Port)

		if s.TLS != nil {
			if s.TLS.Version == "TLS 1.0" || s.TLS.Version == "TLS 1.1" {
				add(fmt.Sprintf("%s accepts deprecated %s", where, s.TLS.Version), "high", s.Host, s.Port,
					[]model.Evidence{
						{Kind: "tls_handshake", Detail: fmt.Sprintf("negotiated %s with %s", s.TLS.Version, s.TLS.Cipher)},
					},
					fmt.Sprintf("Disable %s and require TLS 1.2 or newer on port %d.", s.TLS.Version, s.Port))
			}
			if s.TLS.SelfSigned {
				add(fmt.Sprintf("%s presents a self-signed certificate", where), "medium", s.Host, s.Port,
					[]model.Evidence{
						{Kind: "tls_certificate", Detail: fmt.Sprintf("subject %q issued by itself", s.TLS.Subject)},
					},
					"Issue the service certificate from a trusted CA (or the organisation's internal CA).")
			}
			if !s.TLS.NotAfter.IsZero() && s.TLS.NotAfter.Before(now) {
				add(fmt.Sprintf("%s certificate expired", where), "high", s.Host, s.Port,
					[]model.Evidence{
						{Kind: "tls_certificate", Detail: fmt.Sprintf("expired %s (subject %q, issuer %q)",
							s.TLS.NotAfter.Format("2006-01-02"), s.TLS.Subject, s.TLS.Issuer)},
					},
					"Renew the certificate and automate renewal.")
			} else if !s.TLS.NotAfter.IsZero() && s.TLS.NotAfter.Sub(now) < 14*24*time.Hour {
				add(fmt.Sprintf("%s certificate expires within 14 days", where), "medium", s.Host, s.Port,
					[]model.Evidence{
						{Kind: "tls_certificate", Detail: "expires " + s.TLS.NotAfter.Format("2006-01-02")},
					},
					"Renew the certificate before it expires.")
			}
		}

		// Unauthenticated data stores and remote-control services.
		switch s.Port {
		case 6379:
			if strings.Contains(strings.ToUpper(s.Banner), "PONG") {
				add(fmt.Sprintf("%s responds to PING without authentication", where), "high", s.Host, s.Port,
					[]model.Evidence{{Kind: "service_reply", Detail: "replied to PING without credentials"}},
					"Require authentication (requirepass/ACL) and bind Redis to a trusted interface.")
			}
		case 11211, 27017, 9200, 3306, 5432, 1433, 1521, 2049, 5900, 3389:
			add(fmt.Sprintf("%s exposes a management or data service to this network", where), "medium", s.Host, s.Port,
				[]model.Evidence{
					{Kind: "service_reachable", Detail: "TCP handshake succeeded from an authorised assessment host"},
				},
				"Restrict this port to trusted networks and require authentication.")
		case 21:
			add(fmt.Sprintf("%s exposes FTP", where), "low", s.Host, s.Port,
				[]model.Evidence{{Kind: "service_reachable", Detail: "FTP listener reachable"}},
				"Prefer SFTP/FTPS; disable anonymous access.")
		}

		if s.HTTP != nil && s.HTTP.Scheme == "http" && httpsHosts[s.Host] {
			add(fmt.Sprintf("%s serves plaintext HTTP while HTTPS is available", where), "low", s.Host, s.Port,
				[]model.Evidence{{Kind: "http_probe", Detail: "HTTP listener answered on this host"}},
				"Redirect HTTP to HTTPS and enable HSTS.")
		}

		if s.HTTP != nil && s.HTTP.Server != "" && s.Version != "" {
			add(fmt.Sprintf("%s discloses its software version (%s)", where, strings.TrimSpace(s.HTTP.Server)), "low", s.Host, s.Port,
				[]model.Evidence{{Kind: "http_header", Detail: "Server: " + s.HTTP.Server}},
				"Remove version details from the Server header (server_tokens off, ServerTokens Prod).")
		}
	}
	return out
}
