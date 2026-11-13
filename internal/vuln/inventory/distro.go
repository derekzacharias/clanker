package inventory

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// ParseDpkgStatus parses /var/lib/dpkg/status.
//
// The dpkg database is authoritative for what is installed (it is what apt
// itself reads), and its Version field carries the distribution revision that
// makes vendor-backport reasoning possible.
func ParseDpkgStatus(path, ecosystem, vendor string) ([]model.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open dpkg status: %w", err)
	}
	defer f.Close()
	return parseDpkg(f, ecosystem, vendor)
}

func parseDpkg(r io.Reader, ecosystem, vendor string) ([]model.Package, error) {
	var out []model.Package
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	fields := map[string]string{}
	flush := func() {
		if len(fields) == 0 {
			return
		}
		status := fields["Status"]
		name := fields["Package"]
		version := fields["Version"]
		if name != "" && version != "" && strings.Contains(status, "installed") && !strings.Contains(status, "not-installed") {
			p := model.Package{
				Name:      name,
				Version:   version,
				Ecosystem: ecosystem,
				Source:    model.OriginDpkg,
				Manager:   "dpkg",
				Arch:      fields["Architecture"],
				Vendor:    vendor,
				Origin:    fields["Source"],
			}
			if p.Ecosystem == "" {
				p.Ecosystem = model.EcosystemUnknown
			}
			out = append(out, p)
		}
		fields = map[string]string{}
	}

	var lastKey string
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			lastKey = ""
			continue
		}
		if (line[0] == ' ' || line[0] == '\t') && lastKey != "" {
			fields[lastKey] += " " + strings.TrimSpace(line)
			continue
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		lastKey = strings.TrimSpace(k)
		fields[lastKey] = strings.TrimSpace(v)
	}
	flush()
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// CollectRPM inventories packages via `rpm -qa`.
//
// Epoch is included (as "epoch:version-release") because advisory ranges are
// written against full EVR strings; dropping the epoch creates false negatives
// on packages where the epoch changed.
func CollectRPM(ctx context.Context, ecosystem, vendor string) ([]model.Package, error) {
	out, err := run(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{VENDOR}\t%{SOURCERPM}\n")
	if err != nil {
		return nil, err
	}
	return parseRPMOutput(string(out), ecosystem, vendor), nil
}

func parseRPMOutput(raw, ecosystem, vendor string) []model.Package {
	var pkgs []model.Package
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) < 4 || f[0] == "" {
			continue
		}
		epoch := strings.TrimSpace(f[1])
		if epoch == "0" || epoch == "(none)" {
			epoch = ""
		}
		version := strings.TrimSpace(f[2])
		release := strings.TrimSpace(f[3])
		full := version
		if release != "" {
			full += "-" + release
		}
		if epoch != "" {
			full = epoch + ":" + full
		}
		p := model.Package{
			Name:      f[0],
			Version:   full,
			Ecosystem: ecosystem,
			Source:    model.OriginRPM,
			Manager:   "rpm",
			Vendor:    vendor,
			Release:   release,
		}
		if len(f) > 4 {
			p.Arch = strings.TrimSpace(f[4])
		}
		if len(f) > 5 && strings.TrimSpace(f[5]) != "(none)" {
			p.Origin = strings.TrimSpace(f[5])
		}
		if p.Ecosystem == "" {
			p.Ecosystem = model.EcosystemUnknown
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

// ParseAPKInstalled parses the Alpine package database.
func ParseAPKInstalled(path, ecosystem, vendor string) ([]model.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open apk db: %w", err)
	}
	defer f.Close()
	return parseAPK(f, ecosystem, vendor)
}

func parseAPK(r io.Reader, ecosystem, vendor string) ([]model.Package, error) {
	var out []model.Package
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	fields := map[byte]string{}
	flush := func() {
		if name := fields['P']; name != "" {
			p := model.Package{
				Name:      name,
				Version:   fields['V'],
				Ecosystem: ecosystem,
				Source:    model.OriginAPK,
				Manager:   "apk",
				Arch:      fields['A'],
				Vendor:    vendor,
				Origin:    fields['o'],
			}
			if p.Ecosystem == "" {
				p.Ecosystem = model.EcosystemUnknown
			}
			out = append(out, p)
		}
		fields = map[byte]string{}
	}
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			flush()
			continue
		}
		if len(line) > 1 && line[1] == ':' {
			fields[line[0]] = line[2:]
		}
	}
	flush()
	return out, sc.Err()
}
