package inventory

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// ------------------------------------------------------------------ Python ---

// PipCollector inventories Python distributions by reading installed metadata
// (dist-info/egg-info), which is authoritative, fast, and does not require pip
// to be installed. The pip CLI is not invoked: on externally-managed
// environments (PEP 668) it is frequently absent or refuses to run.
type PipCollector struct {
	// Interpreters overrides interpreter discovery (tests, or an explicit
	// list of venvs to include).
	Interpreters []string
	// Exec overrides command execution (tests).
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
	// ExtraSiteDirs adds user-supplied site-packages directories.
	ExtraSiteDirs []string
}

func (c *PipCollector) Name() string { return "python_site_packages" }

func (c *PipCollector) exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	if c.Exec != nil {
		return c.Exec(ctx, name, args...)
	}
	return run(ctx, name, args...)
}

func (c *PipCollector) Collect(ctx context.Context, opts Options) ([]model.Package, error) {
	interpreters := c.Interpreters
	if len(interpreters) == 0 {
		interpreters = discoverInterpreters(opts.Root)
	}
	if len(interpreters) == 0 {
		return nil, fmt.Errorf("%w: no python3 interpreter found", ErrUnavailable)
	}

	var pkgs []model.Package
	seenDirs := map[string]bool{}
	for _, py := range interpreters {
		dirs, err := c.sitePackages(ctx, py)
		if err != nil {
			continue
		}
		for _, dir := range dirs {
			if dir == "" || seenDirs[dir] {
				continue
			}
			seenDirs[dir] = true
			got, err := readPythonDistributions(dir, py)
			if err != nil {
				continue
			}
			pkgs = append(pkgs, got...)
		}
	}
	for _, dir := range c.ExtraSiteDirs {
		if seenDirs[dir] {
			continue
		}
		got, err := readPythonDistributions(dir, "explicit")
		if err == nil {
			pkgs = append(pkgs, got...)
		}
	}
	if len(pkgs) == 0 && len(seenDirs) == 0 {
		return nil, fmt.Errorf("%w: python site-packages not readable", ErrUnavailable)
	}
	return pkgs, nil
}

// sitePackages asks the interpreter for its site-packages directories. This is
// a read-only introspection call with a fixed script.
func (c *PipCollector) sitePackages(ctx context.Context, py string) ([]string, error) {
	out, err := c.exec(ctx, py, "-c",
		`import json,site,sys`+
			`;d=list(site.getsitepackages())+[site.getusersitepackages()]`+
			`+[p for p in sys.path if p.endswith("site-packages")]`+
			`;print(json.dumps(sorted(set(x for x in d if x))))`)
	if err != nil {
		return nil, err
	}
	var dirs []string
	if err := json.Unmarshal(out, &dirs); err != nil {
		return nil, err
	}
	return dirs, nil
}

func readPythonDistributions(dir, interpreter string) ([]model.Package, error) {
	entries, err := filepath.Glob(filepath.Join(dir, "*.dist-info"))
	if err != nil {
		return nil, err
	}
	eggs, _ := filepath.Glob(filepath.Join(dir, "*.egg-info"))
	entries = append(entries, eggs...)

	var out []model.Package
	for _, entry := range entries {
		metaNames := []string{
			filepath.Join(entry, "METADATA"),
			filepath.Join(entry, "PKG-INFO"),
		}
		for _, m := range metaNames {
			name, version, ok := readPythonMetadata(m)
			if !ok {
				continue
			}
			out = append(out, model.Package{
				Name:      name,
				Version:   version,
				Ecosystem: model.EcosystemPyPI,
				Source:    model.OriginPip,
				Manager:   "pip (" + interpreter + ")",
				Origin:    entry,
			})
			break
		}
	}
	return out, nil
}

func readPythonMetadata(path string) (name, version string, ok bool) {
	f, err := osOpen(path)
	if err != nil {
		return "", "", false
	}
	defer f.Close()
	buf := make([]byte, 8192)
	n, _ := f.Read(buf)
	for _, line := range strings.Split(string(buf[:n]), "\n") {
		if line == "" {
			break // end of headers
		}
		key, val, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(key)) {
		case "name":
			name = strings.TrimSpace(val)
		case "version":
			version = strings.TrimSpace(val)
		}
	}
	return name, version, name != "" && version != ""
}

// discoverInterpreters finds python3 binaries in standard locations. It never
// walks the filesystem broadly.
func discoverInterpreters(root string) []string {
	if root == "" {
		root = "/"
	}
	seen := map[string]bool{}
	var out []string
	add := func(p string) {
		resolved, err := filepath.EvalSymlinks(p)
		if err != nil || resolved == "" || seen[resolved] {
			return
		}
		seen[resolved] = true
		out = append(out, p)
	}
	if p, err := exec.LookPath("python3"); err == nil {
		add(p)
	}
	for _, pattern := range []string{"usr/bin/python3.*", "usr/local/bin/python3*", "opt/homebrew/bin/python3*", ".local/bin/python3*"} {
		matches, _ := filepath.Glob(filepath.Join(root, pattern))
		sort.Strings(matches)
		for _, m := range matches {
			if strings.HasSuffix(m, "-config") || strings.HasSuffix(m, "m-config") {
				continue
			}
			add(m)
		}
	}
	return out
}

// --------------------------------------------------------------------- npm ---

// NpmCollector inventories globally installed npm packages.
type NpmCollector struct {
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
	// ProjectDirs additionally inventories local node_modules roots.
	ProjectDirs []string
}

func (c *NpmCollector) Name() string { return "npm_packages" }

func (c *NpmCollector) exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	if c.Exec != nil {
		return c.Exec(ctx, name, args...)
	}
	return run(ctx, name, args...)
}

func (c *NpmCollector) Collect(ctx context.Context, opts Options) ([]model.Package, error) {
	out, err := c.exec(ctx, npmBinary(), "ls", "-g", "--json", "--depth=0", "--long")
	if err != nil {
		if errors.Is(err, ErrUnavailable) {
			return nil, err
		}
		// npm exits non-zero on unrelated warnings but still prints JSON.
		if len(out) == 0 {
			return nil, err
		}
	}
	pkgs := parseNpmLS(string(out), "global")
	for _, dir := range c.ProjectDirs {
		local, err := c.exec(ctx, npmBinary(), "ls", "--json", "--depth=0", "--prefix", dir)
		if err != nil && len(local) == 0 {
			continue
		}
		pkgs = append(pkgs, parseNpmLS(string(local), "project:"+dir)...)
	}
	if len(pkgs) == 0 {
		return nil, fmt.Errorf("%w: npm produced no package data", ErrUnavailable)
	}
	return pkgs, nil
}

func npmBinary() string {
	if platform() == "windows" {
		return "npm.cmd"
	}
	return "npm"
}

func parseNpmLS(raw, scope string) []model.Package {
	start := strings.Index(raw, "{")
	if start < 0 {
		return nil
	}
	var doc struct {
		Dependencies map[string]struct {
			Version string `json:"version"`
		} `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(raw[start:]), &doc); err != nil {
		return nil
	}
	names := make([]string, 0, len(doc.Dependencies))
	for name := range doc.Dependencies {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]model.Package, 0, len(names))
	for _, name := range names {
		dep := doc.Dependencies[name]
		if dep.Version == "" {
			continue
		}
		out = append(out, model.Package{
			Name:      name,
			Version:   dep.Version,
			Ecosystem: model.EcosystemNPM,
			Source:    model.OriginNpm,
			Manager:   "npm (" + scope + ")",
		})
	}
	return out
}

// --------------------------------------------------------------------- gem ---

// RubyGemCollector inventories Ruby gems via the gem CLI.
type RubyGemCollector struct {
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (c *RubyGemCollector) Name() string { return "ruby_gems" }

func (c *RubyGemCollector) Collect(ctx context.Context, opts Options) ([]model.Package, error) {
	execFn := c.Exec
	if execFn == nil {
		execFn = run
	}
	out, err := execFn(ctx, "gem", "list", "--local")
	if err != nil {
		return nil, err
	}
	return parseGemList(string(out)), nil
}

// parseGemList parses lines like `rails (7.0.4, 6.1.7)`.
func parseGemList(raw string) []model.Package {
	var out []model.Package
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "*") || strings.HasPrefix(line, "***") {
			continue
		}
		name, rest, ok := strings.Cut(line, " (")
		if !ok {
			continue
		}
		rest = strings.TrimSuffix(rest, ")")
		for _, v := range strings.Split(rest, ",") {
			v = strings.TrimSpace(v)
			if v == "" || v == "default:" {
				continue
			}
			out = append(out, model.Package{
				Name:      strings.TrimSpace(name),
				Version:   v,
				Ecosystem: model.EcosystemRubyGems,
				Source:    model.OriginGem,
				Manager:   "gem",
			})
		}
	}
	return out
}
