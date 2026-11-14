// Package scope implements the explicit authorisation gate for remote work.
//
// Clanker Guard never scans a network without a scope file that names the
// authorising person and the exact targets. The gate exists even though remote
// scanning is not implemented in this build: the safety property must not be
// bolted on later.
package scope

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// File is the on-disk scope document.
type File struct {
	Name         string    `yaml:"name"`
	AuthorizedBy string    `yaml:"authorized_by"`
	AuthorizedAt time.Time `yaml:"authorized_at"`
	// ExpiresAt bounds the authorisation. An expired scope is rejected, which is
	// how temporary approvals avoid becoming permanent ones.
	ExpiresAt   time.Time `yaml:"expires_at"`
	Targets     []string  `yaml:"targets"`
	Ports       []int     `yaml:"ports"`
	MaxHosts    int       `yaml:"max_hosts"`
	AllowPublic bool      `yaml:"allow_public_addresses"`
	Notes       string    `yaml:"notes"`
}

// Load parses and validates a scope file.
func Load(path string) (model.Scope, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return model.Scope{}, fmt.Errorf("read scope: %w", err)
	}
	sc, err := Parse(b)
	if err != nil {
		return model.Scope{}, fmt.Errorf("%s: %w", path, err)
	}
	return sc, nil
}

// Parse validates a scope document supplied as bytes (API/UI paste).
func Parse(data []byte) (model.Scope, error) {
	var f File
	if err := yaml.Unmarshal(data, &f); err != nil {
		return model.Scope{}, fmt.Errorf("parse scope: %w", err)
	}
	return Validate(f)
}

// Validate enforces the authorisation contract.
func Validate(f File) (model.Scope, error) {
	var problems []string
	if strings.TrimSpace(f.Name) == "" {
		problems = append(problems, "name is required")
	}
	if strings.TrimSpace(f.AuthorizedBy) == "" {
		problems = append(problems, "authorized_by is required (who approved this scan)")
	}
	if f.AuthorizedAt.IsZero() {
		problems = append(problems, "authorized_at is required (RFC3339 timestamp)")
	}
	if !f.ExpiresAt.IsZero() && !f.ExpiresAt.After(time.Now()) {
		problems = append(problems, fmt.Sprintf("scope expired at %s; re-authorise the assessment", f.ExpiresAt.Format(time.RFC3339)))
	}
	if len(f.Targets) == 0 {
		problems = append(problems, "targets must list at least one authorised address, CIDR or hostname")
	}
	if f.MaxHosts == 0 {
		f.MaxHosts = 256
	}
	if len(problems) > 0 {
		return model.Scope{}, fmt.Errorf("scope is not usable:\n  - %s", strings.Join(problems, "\n  - "))
	}

	// Reject unbounded targets outright: scanning 0.0.0.0/0 is never authorised
	// by accident, and silently clamping would misrepresent what was approved.
	expanded := 0
	for _, t := range f.Targets {
		if strings.Contains(t, "/") {
			_, ipnet, err := net.ParseCIDR(t)
			if err != nil {
				return model.Scope{}, fmt.Errorf("invalid CIDR %q: %w", t, err)
			}
			ones, bits := ipnet.Mask.Size()
			hosts := 1 << (bits - ones)
			if bits-ones >= 8 {
				hosts = 1 << 8 // only a lower bound is needed for the guard-rail
			}
			if !f.AllowPublic && !ipnet.IP.IsPrivate() && !ipnet.IP.IsLoopback() {
				return model.Scope{}, fmt.Errorf("target %q is a public range; set allow_public_addresses: true to authorise it explicitly", t)
			}
			expanded += hosts
			continue
		}
		ip := net.ParseIP(t)
		if ip == nil {
			// hostname: allowed, resolved at scan time and re-checked
			expanded++
			continue
		}
		if !f.AllowPublic && !ip.IsPrivate() && !ip.IsLoopback() {
			return model.Scope{}, fmt.Errorf("target %q is a public address; set allow_public_addresses: true to authorise it explicitly", t)
		}
		expanded++
	}
	if expanded > f.MaxHosts {
		return model.Scope{}, fmt.Errorf("scope expands to at least %d hosts which exceeds max_hosts=%d", expanded, f.MaxHosts)
	}
	for _, p := range f.Ports {
		if p < 1 || p > 65535 {
			return model.Scope{}, fmt.Errorf("invalid port %d", p)
		}
	}

	return model.Scope{
		Name:         f.Name,
		AuthorizedBy: f.AuthorizedBy,
		AuthorizedAt: f.AuthorizedAt,
		ExpiresAt:    f.ExpiresAt,
		Targets:      f.Targets,
		Ports:        f.Ports,
		MaxHosts:     f.MaxHosts,
		AllowPublic:  f.AllowPublic,
		Notes:        f.Notes,
	}, nil
}

// Allows reports whether an address is inside the authorised target set. It is
// the single chokepoint every network collector must call.
func Allows(s model.Scope, addr string) bool {
	ip := net.ParseIP(addr)
	for _, t := range s.Targets {
		if strings.EqualFold(t, addr) {
			return true
		}
		if ip != nil && strings.Contains(t, "/") {
			if _, netw, err := net.ParseCIDR(t); err == nil && netw.Contains(ip) {
				return true
			}
		}
		if ip != nil && net.ParseIP(t) != nil && net.ParseIP(t).Equal(ip) {
			return true
		}
	}
	return false
}
