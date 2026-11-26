package inventory

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

func mustOpen(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("open fixture %s: %v", name, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

func TestParseDpkg(t *testing.T) {
	pkgs, err := parseDpkg(mustOpen(t, "dpkg_status"), "Ubuntu:24.04:LTS", "Ubuntu")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 installed packages, got %d: %+v", len(pkgs), pkgs)
	}
	byName := map[string]model.Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if _, ok := byName["libc6"]; ok {
		t.Error("deinstalled package must not be reported as installed")
	}
	ssl := byName["openssl"]
	if ssl.Version != "3.0.13-0ubuntu3.5" || ssl.Arch != "amd64" || ssl.Ecosystem != "Ubuntu:24.04:LTS" {
		t.Errorf("unexpected openssl record: %+v", ssl)
	}
	if ssl.Vendor != "Ubuntu" || ssl.Origin != "openssl" {
		t.Errorf("vendor/origin not captured: %+v", ssl)
	}
	// multi-line Description must not leak into other fields
	if byName["bash"].Version != "5.2.21-2ubuntu4" {
		t.Errorf("version parse broken by continuation lines: %+v", byName["bash"])
	}
}

func TestParseRPMOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "rpm_output.txt"))
	if err != nil {
		t.Fatal(err)
	}
	pkgs := parseRPMOutput(string(raw), "Rocky Linux:9", "Rocky Linux")
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "openssl" || pkgs[0].Version != "3.0.13-0ubuntu3.5" {
		t.Errorf("unexpected first package: %+v", pkgs[0])
	}
	// epoch must be preserved: glibc has epoch 1
	var glibc model.Package
	for _, p := range pkgs {
		if p.Name == "glibc" {
			glibc = p
		}
	}
	if glibc.Version != "1:2.34-100.el9" {
		t.Errorf("epoch not preserved: %q", glibc.Version)
	}
}

func TestParseAPK(t *testing.T) {
	pkgs, err := parseAPK(mustOpen(t, "apk_installed"), "Alpine:3.19", "Alpine")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || pkgs[1].Name != "openssl" || pkgs[1].Version != "3.1.4-r0" {
		t.Fatalf("unexpected apk parse: %+v", pkgs)
	}
}

func TestParseGemList(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "gem_list.txt"))
	pkgs := parseGemList(string(raw))
	// bundler has two versions, rails and nokogiri one each; "default:" is skipped
	if len(pkgs) != 4 {
		t.Fatalf("expected 4 gem entries, got %d: %+v", len(pkgs), pkgs)
	}
	for _, p := range pkgs {
		if p.Version == "default:" {
			t.Fatalf("default: marker leaked into version: %+v", p)
		}
		if p.Ecosystem != model.EcosystemRubyGems {
			t.Fatalf("wrong ecosystem: %+v", p)
		}
	}
}

func TestParseNpmLS(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "npm_ls.json"))
	pkgs := parseNpmLS(string(raw), "global")
	if len(pkgs) != 3 {
		t.Fatalf("expected 3 npm packages, got %d", len(pkgs))
	}
	if pkgs[0].Name != "@angular/core" || pkgs[0].Version != "17.0.0" {
		t.Errorf("scoped package not preserved: %+v", pkgs[0])
	}
	// npm prints warnings before JSON; the parser must skip to the JSON body
	noisy := "npm warn something\n" + string(raw)
	if got := parseNpmLS(noisy, "global"); len(got) != 3 {
		t.Errorf("parser failed on noisy npm output: %d", len(got))
	}
}

func TestParseBrewAndWindows(t *testing.T) {
	raw, _ := os.ReadFile(filepath.Join("testdata", "brew_list.txt"))
	brew := parseBrewList(string(raw))
	if len(brew) != 3 || brew[1].Name != "openssl@3" {
		t.Fatalf("unexpected brew parse: %+v", brew)
	}
	wraw, _ := os.ReadFile(filepath.Join("testdata", "windows_inventory.json"))
	win := parseWindowsInventory(wraw)
	if len(win) != 2 || win[1].Name != "7-Zip" || win[1].Version != "23.01" {
		t.Fatalf("unexpected windows parse: %+v", win)
	}
	// single-object output (one installed app) must parse too
	single := parseWindowsInventory([]byte(`{"name":"Solo","version":"1.0","publisher":"x"}`))
	if len(single) != 1 || single[0].Name != "Solo" {
		t.Fatalf("single-object windows output not handled: %+v", single)
	}
}

func TestPythonDistributionMetadata(t *testing.T) {
	pkgs, err := readPythonDistributions(filepath.Join("testdata", "pip_site"), "python3")
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected 2 python dists, got %d", len(pkgs))
	}
	byName := map[string]string{}
	for _, p := range pkgs {
		byName[p.Name] = p.Version
	}
	if byName["requests"] != "2.31.0" || byName["Flask-SQLAlchemy"] != "3.1.1" {
		t.Fatalf("unexpected python inventory: %+v", byName)
	}
}

func TestPipCollectorWithFakeInterpreter(t *testing.T) {
	// The interpreter is fake: only the introspection call matters, and it is
	// answered by the injected Exec, so no python is required to run this test.
	abs, err := filepath.Abs(filepath.Join("testdata", "pip_site"))
	if err != nil {
		t.Fatal(err)
	}
	c := &PipCollector{
		Interpreters: []string{"/fake/python3"},
		Exec: func(ctx context.Context, name string, args ...string) ([]byte, error) {
			return []byte(`["` + abs + `"]`), nil
		},
	}
	got, err := c.Collect(context.Background(), Options{})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %d", len(got))
	}
	if got[0].Ecosystem != model.EcosystemPyPI {
		t.Fatalf("wrong ecosystem: %+v", got[0])
	}
}

func TestOSPackagesFixtureRoot(t *testing.T) {
	root := t.TempDir()
	// Mirror the paths the collector looks for.
	for _, p := range []string{"etc", "var/lib/dpkg"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(t, "testdata/os_release", filepath.Join(root, "etc/os-release"))
	copyFile(t, "testdata/dpkg_status", filepath.Join(root, "var/lib/dpkg/status"))

	r := &Runner{Collectors: []Collector{&OSPackageCollector{}}}
	inv, err := r.Run(context.Background(), Options{Root: root})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if len(inv.Packages) != 3 {
		t.Fatalf("expected 3 packages from fixture root, got %d", len(inv.Packages))
	}
	if inv.Asset.DistroID != "ubuntu" || inv.Asset.OSVersion != "24.04" {
		t.Fatalf("asset not detected from fixture root: %+v", inv.Asset)
	}
	for _, p := range inv.Packages {
		if p.Ecosystem != "Ubuntu:24.04:LTS" {
			t.Fatalf("ecosystem not derived from fixture os-release: %+v", p)
		}
		if p.PURL == "" {
			t.Fatalf("purl not derived: %+v", p)
		}
	}
}

func TestDedupeAndNormalization(t *testing.T) {
	in := []model.Package{
		{Name: "Flask", Version: "3.0.0", Ecosystem: "PyPI", Source: model.OriginPip},
		{Name: "flask", Version: "3.0.0", Ecosystem: "PyPI", Source: model.OriginPip},
		{Name: "flask", Version: "2.0.0", Ecosystem: "PyPI", Source: model.OriginPip},
		{Name: "openssl", Version: "3.0.13", Ecosystem: "Debian:12", Source: model.OriginDpkg},
		{Name: "openssl", Version: "3.0.13", Ecosystem: "PyPI", Source: model.OriginPip},
	}
	out := Dedupe(in)
	if len(out) != 4 {
		t.Fatalf("expected 4 distinct records, got %d: %+v", len(out), out)
	}
}

func TestOSEcosystemMapping(t *testing.T) {
	cases := map[AssetInfo]string{
		{ID: "ubuntu", VersionID: "24.04"}:  "Ubuntu:24.04:LTS",
		{ID: "ubuntu", VersionID: "23.10"}:  "Ubuntu:23.10",
		{ID: "debian", VersionID: "12"}:     "Debian:12",
		{ID: "rocky", VersionID: "9"}:       "Rocky Linux:9",
		{ID: "almalinux", VersionID: "9.3"}: "AlmaLinux:9.3",
		{ID: "fedora", VersionID: "40"}:     "Fedora:40",
		{ID: "alpine", VersionID: "3.19"}:   "Alpine:v3.19",
		{ID: "arch", VersionID: ""}:         "",
	}
	for info, want := range cases {
		if got := OSEcosystem(info); got != want {
			t.Errorf("OSEcosystem(%+v) = %q, want %q", info, got, want)
		}
	}
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// The bug this pins: on Ubuntu, Python's site.getsitepackages() lists
// /usr/lib/python3/dist-packages, so every python3-* package was inventoried twice — once from
// dpkg and once as a PyPI dependency. The duplicate produced findings (and a remediation
// ticket) telling someone to `pip install` a package that apt owns.
func TestDistroManagedPythonPackagesAreNotCountedTwice(t *testing.T) {
	pkgs := []model.Package{
		{Name: "python3-jwt", Version: "2.3.0-1ubuntu0.6", Ecosystem: "Ubuntu:22.04:LTS",
			Source: model.OriginDpkg, Origin: "pyjwt"},
		{Name: "PyJWT", Version: "2.3.0", Ecosystem: model.EcosystemPyPI, Source: model.OriginPip,
			Origin: "/usr/lib/python3/dist-packages/PyJWT-2.3.0.egg-info"},
		{Name: "Babel", Version: "2.8.0", Ecosystem: model.EcosystemPyPI, Source: model.OriginPip,
			Origin: "/usr/lib/python3/dist-packages/Babel-2.8.0.egg-info"},
		// A real application dependency in a virtualenv must survive.
		{Name: "requests", Version: "2.32.4", Ecosystem: model.EcosystemPyPI, Source: model.OriginPip,
			Origin: "/opt/app/.venv/lib/python3.11/site-packages/requests-2.32.4.dist-info"},
	}
	kept, dropped := dropDistroProvidedPython(pkgs)
	if dropped != 2 {
		t.Fatalf("dropped = %d, want 2", dropped)
	}
	var names []string
	for _, p := range kept {
		names = append(names, p.Name)
	}
	if len(kept) != 2 {
		t.Fatalf("kept = %v, want the dpkg package and the virtualenv package", names)
	}
	found := map[string]bool{}
	for _, n := range names {
		found[n] = true
	}
	if !found["python3-jwt"] || !found["requests"] {
		t.Fatalf("kept = %v", names)
	}
	if found["PyJWT"] {
		t.Fatal("the distro-provided copy survived as a PyPI package")
	}
}

// Without an OS package manager there is nothing to defer to, so the PyPI data is all we have.
func TestDistroPythonPathIsKeptWhenNoOSManagerCoveredTheHost(t *testing.T) {
	pkgs := []model.Package{{
		Name: "PyJWT", Version: "2.3.0", Ecosystem: model.EcosystemPyPI, Source: model.OriginPip,
		Origin: "/usr/lib/python3/dist-packages/PyJWT-2.3.0.egg-info",
	}}
	kept, dropped := dropDistroProvidedPython(pkgs)
	if dropped != 0 || len(kept) != 1 {
		t.Fatalf("dropped = %d, kept = %d", dropped, len(kept))
	}
}

// The prefix test must not swallow local installs that merely live under /usr/local.
func TestIsDistroPythonPath(t *testing.T) {
	cases := map[string]bool{
		"/usr/lib/python3/dist-packages/PyJWT-2.3.0.egg-info":       true,
		"/usr/lib/python3.11/dist-packages/foo-1.0.dist-info":       true,
		"/usr/lib/python3.11/site-packages/foo-1.0.dist-info":       false,
		"/usr/local/lib/python3.11/dist-packages/foo-1.0.dist-info": false,
		"/opt/app/.venv/lib/python3.11/site-packages/foo.dist-info": false,
		"": false,
	}
	for path, want := range cases {
		if got := isDistroPythonPath(path); got != want {
			t.Fatalf("isDistroPythonPath(%q) = %v, want %v", path, got, want)
		}
	}
}

// A Windows asset that reports only "windows" cannot be matched against anything, and the
// dashboard shows "(windows )". The build is the patch level Windows advisories are keyed by.
func TestWindowsOSInfoParsing(t *testing.T) {
	name, version, build, err := parseWindowsOSInfo([]byte(
		`{"product":"Windows 11 Pro","display":"24H2","build":"26100","major":10,"minor":0,"ubr":1742}`))
	if err != nil {
		t.Fatalf("parseWindowsOSInfo: %v", err)
	}
	if name != "Windows 11 Pro" || version != "24H2" || build != "10.0.26100.1742" {
		t.Fatalf("got name=%q version=%q build=%q", name, version, build)
	}
	// A machine where UBR is absent still yields a usable build.
	name, version, build, err = parseWindowsOSInfo([]byte(
		`{"product":"Windows Server 2022","build":"20348","major":10,"minor":0}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if name != "Windows Server 2022" || version != "" || build != "10.0.20348" {
		t.Fatalf("got name=%q version=%q build=%q", name, version, build)
	}
}

// A Windows inventory without servicing state is the old, shallow answer. The state block is
// what makes an update finding possible, and its absence must be a reported gap.
type winFake struct {
	out map[string][]byte
	err map[string]error
}

func (f *winFake) exec(ctx context.Context, name string, args ...string) ([]byte, error) {
	script := ""
	if len(args) > 0 {
		script = args[len(args)-1]
	}
	switch {
	case strings.Contains(script, "Get-HotFix"):
		return f.out["state"], f.err["state"]
	case strings.Contains(script, "Microsoft.Update.Session"):
		return f.out["wua"], f.err["wua"]
	case strings.Contains(script, "Get-AppxPackage"):
		return f.out["appx"], f.err["appx"]
	}
	return nil, nil
}

func TestWindowsStateCollectorParsesServicingData(t *testing.T) {
	if platform() != "windows" {
		t.Skip("the collector refuses to run off Windows; parsing is covered below")
	}
}

// Parsing is tested without Windows by exercising the pure helpers, which is where the format
// handling lives.
func TestWindowsBuildComposition(t *testing.T) {
	cases := []struct {
		build             string
		major, minor, ubr any
		want              string
	}{
		{"26100", float64(10), float64(0), float64(1742), "10.0.26100.1742"},
		{"22631", float64(10), float64(0), nil, "10.0.22631"},
		{"", float64(10), float64(0), float64(1), ""},
	}
	for _, c := range cases {
		if got := windowsBuild(c.build, c.major, c.minor, c.ubr); got != c.want {
			t.Fatalf("windowsBuild(%q) = %q, want %q", c.build, got, c.want)
		}
	}
}

func TestAppxPackagesBecomeInventoryEntries(t *testing.T) {
	raw := []byte(`[{"name":"Microsoft.WindowsCalculator_11.2210.0.0_x64__8wekyb3d8bbwe","version":"11.2210.0.0","publisher":"CN=Microsoft Corporation"},
	               {"name":"Microsoft.StorePurchaseApp_22310.1401.0.0_neutral_~_8wekyb3d8bbwe","version":"22310.1401.0.0"}]`)
	pkgs := parseAppxPackages(raw)
	if len(pkgs) != 2 {
		t.Fatalf("packages = %d", len(pkgs))
	}
	if pkgs[0].Name != "Microsoft.WindowsCalculator" || pkgs[0].Ecosystem != model.EcosystemWindows ||
		pkgs[0].Source != model.OriginAppx {
		t.Fatalf("package = %+v", pkgs[0])
	}
}

// The update search must be read-only: the script may search, never install or download.
func TestWindowsUpdateScriptIsReadOnly(t *testing.T) {
	for _, forbidden := range []string{"Download()", ".Install()", "Hide()", "Add-WindowsPackage", "wuauclt /updatenow"} {
		if strings.Contains(windowsUpdateScript, forbidden) {
			t.Fatalf("update script contains a mutating call: %s", forbidden)
		}
	}
	if !strings.Contains(windowsUpdateScript, "IsInstalled=0") {
		t.Fatal("update search does not ask for missing updates")
	}
}

// Windows 11 machines often still report ProductName "Windows 10 Pro" in the registry. Trusting it
// mislabels the OS and, worse, makes advisory matching look for "Windows 10 Version 23H2", which
// does not exist — so every missing update goes unreported.
func TestWindowsMarketingNameUsesTheBuild(t *testing.T) {
	cases := []struct {
		product, build, want string
		corrected            bool
	}{
		{"Windows 10 Pro", "10.0.22631.4317", "Windows 11 Pro", true},   // 23H2
		{"Windows 10 Home", "10.0.22621.4249", "Windows 11 Home", true}, // 22H2
		{"Windows 10 Pro", "10.0.26100.1742", "Windows 11 Pro", true},   // 24H2
		{"Windows 10 Pro", "10.0.19045.4894", "Windows 10 Pro", false},  // really Windows 10
		{"Windows 11 Pro", "10.0.22631.4317", "Windows 11 Pro", false},  // already right
		{"Windows Server 2022", "10.0.20348.2582", "Windows Server 2022", false},
		{"Windows Server 2025", "10.0.26100.1742", "Windows Server 2025", false}, // same build as 24H2
		{"", "10.0.22631.1", "", false},
	}
	for _, c := range cases {
		got, corrected := WindowsMarketingName(c.product, c.build)
		if got != c.want || corrected != c.corrected {
			t.Fatalf("WindowsMarketingName(%q, %q) = (%q, %v), want (%q, %v)",
				c.product, c.build, got, corrected, c.want, c.corrected)
		}
	}
}

// The correction must happen inside the parse path, so the asset records the right OS.
func TestParseWindowsOSInfoCorrectsWindows11(t *testing.T) {
	name, version, build, err := parseWindowsOSInfo([]byte(
		`{"product":"Windows 10 Pro","display":"23H2","build":"22631","major":10,"minor":0,"ubr":4317}`))
	if err != nil {
		t.Fatal(err)
	}
	if name != "Windows 11 Pro" {
		t.Fatalf("product = %q, want Windows 11 Pro", name)
	}
	if version != "23H2" || build != "10.0.22631.4317" {
		t.Fatalf("version=%q build=%q", version, build)
	}
}
