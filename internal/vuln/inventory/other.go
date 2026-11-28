package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// osOpen is a variable so tests can substitute fixture readers.
var osOpen = os.Open

// rpmAvail reports whether the rpm binary is on PATH; used to pick the correct
// package database before attempting a query.
func rpmAvail(ctx context.Context) bool {
	_, err := run(ctx, "rpm", "--version")
	return err == nil
}

// ------------------------------------------------------------------- brew ---

// BrewCollector inventories Homebrew formulae on macOS.
//
// Homebrew has no OSV ecosystem, so these entries are collected for inventory
// completeness but cannot be correlated against OSV advisories. The assessor
// records that gap instead of reporting "no vulnerabilities".
type BrewCollector struct {
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (c *BrewCollector) Name() string { return "homebrew" }

func (c *BrewCollector) Collect(ctx context.Context, opts Options) ([]model.Package, error) {
	execFn := c.Exec
	if execFn == nil {
		execFn = run
	}
	out, err := execFn(ctx, "brew", "list", "--versions")
	if err != nil {
		return nil, err
	}
	return parseBrewList(string(out)), nil
}

func parseBrewList(raw string) []model.Package {
	var out []model.Package
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		for _, v := range fields[1:] {
			out = append(out, model.Package{
				Name:      fields[0],
				Version:   v,
				Ecosystem: "Homebrew",
				Source:    model.OriginManifest,
				Manager:   "brew",
			})
		}
	}
	return out
}

// --------------------------------------------------------------- Windows ----

// WindowsRegistryCollector inventories installed applications from the
// Uninstall registry hives (machine 64-bit, machine 32-bit via WOW6432Node,
// per-user), the Windows Installer Products key, and the Office Click-to-Run
// configuration. It is strictly read-only; Win32_Product is never used
// because enumerating it triggers MSI consistency checks and repairs.
//
// Every record carries its source and scope so deduplication can merge the
// same application observed through several hives while keeping the evidence.
type WindowsRegistryCollector struct {
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (c *WindowsRegistryCollector) Name() string { return "windows_registry" }

const windowsInventoryScript = `$ErrorActionPreference='SilentlyContinue';
$out=@();
$hives=@(
  @{path='HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; scope='machine'; arch='x64'},
  @{path='HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'; scope='machine'; arch='x86'},
  @{path='HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*'; scope='user'; arch='x64'}
);
foreach($h in $hives){
  Get-ItemProperty $h.path | ForEach-Object {
    if(-not $_.DisplayName){ return }
    if($_.SystemComponent -eq 1){ return }
    $out += [pscustomobject]@{
      name=$_.DisplayName; version=$_.DisplayVersion; publisher=$_.Publisher;
      install_date=$_.InstallDate; location=$_.InstallLocation; scope=$h.scope; arch=$h.arch;
      product_id=$_.PSChildName; msi=[bool]$_.WindowsInstaller; url_about=$_.URLInfoAbout;
      source='registry'
    }
  }
}
# Windows Installer metadata: one row per installed MSI product. Entries whose
# product code already appeared in the Uninstall hives are dropped by the
# deduplicator, not here (dedupe keeps the evidence).
Get-ItemProperty 'HKLM:\SOFTWARE\Classes\Installer\Products\*' | ForEach-Object {
  if(-not $_.ProductName){ return }
  $out += [pscustomobject]@{
    name=$_.ProductName; version=$_.Version; publisher='';
    install_date=''; location=''; scope='machine'; arch='x64';
    product_id=$_.PSChildName; msi=$true; url_about=''; source='msi'
  }
}
# Office Click-to-Run carries the real product version in its configuration key.
$c2r='HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration';
if(Test-Path $c2r){
  $c=(Get-ItemProperty $c2r);
  if($c.VersionToReport){
    $out += [pscustomobject]@{
      name='Microsoft 365 Apps'; version=[string]$c.VersionToReport; publisher='Microsoft Corporation';
      install_date=''; location=$c.InstallPath; scope='machine'; arch='x64';
      product_id='office-click-to-run'; msi=$false; url_about=''; source='click_to_run'
    }
  }
}
$out | ConvertTo-Json -Compress -Depth 3`

// windowsFileVersionScript probes the standard install paths of well-known
// applications that sometimes install without a usable registry version
// (portable or per-user installs). The path list is a fixed constant — no
// scanned data is ever interpolated.
const windowsFileVersionScript = `$ErrorActionPreference='SilentlyContinue';
$out=@();
$probes=@(
  @{name='Google Chrome'; paths=@('${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe','${env:ProgramFiles}\Google\Chrome\Application\chrome.exe','$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe')},
  @{name='Mozilla Firefox'; paths=@('${env:ProgramFiles}\Mozilla Firefox\firefox.exe','${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe')},
  @{name='Microsoft Edge'; paths=@('${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe','${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe')},
  @{name='VLC media player'; paths=@('${env:ProgramFiles}\VideoLAN\VLC\vlc.exe','${env:ProgramFiles(x86)}\VideoLAN\VLC\vlc.exe')},
  @{name='Notepad++'; paths=@('${env:ProgramFiles}\Notepad++\notepad++.exe','${env:ProgramFiles(x86)}\Notepad++\notepad++.exe')},
  @{name='7-Zip'; paths=@('${env:ProgramFiles}\7-Zip\7zFM.exe','${env:ProgramFiles(x86)}\7-Zip\7zFM.exe')},
  @{name='PuTTY'; paths=@('${env:ProgramFiles}\PuTTY\putty.exe','${env:ProgramFiles(x86)}\PuTTY\putty.exe')},
  @{name='WinSCP'; paths=@('${env:ProgramFiles(x86)}\WinSCP\WinSCP.exe','${env:ProgramFiles}\WinSCP\WinSCP.exe')}
);
foreach($p in $probes){
  foreach($path in $p.paths){
    if(Test-Path $path){
      $vi=(Get-Item $path).VersionInfo;
      $out += [pscustomobject]@{ name=$p.name; version=$vi.ProductVersion; publisher=$vi.CompanyName;
        install_date=''; location=Split-Path $path; scope='machine'; arch='x64';
        product_id=('file-version:' + $path); msi=$false; url_about=''; source='file_version' };
      break
    }
  }
}
$out | ConvertTo-Json -Compress -Depth 3`

func (c *WindowsRegistryCollector) Collect(ctx context.Context, opts Options) ([]model.Package, error) {
	if platform() != "windows" {
		return nil, fmt.Errorf("%w: windows registry collector only runs on Windows", ErrUnavailable)
	}
	execFn := c.Exec
	if execFn == nil {
		execFn = run
	}
	out, err := execFn(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", windowsInventoryScript)
	if err != nil {
		return nil, err
	}
	pkgs := parseWindowsInventory(out)

	// File-version metadata fills the gaps the registry leaves for portable
	// and per-user installs of well-known applications.
	if fv, err := execFn(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", windowsFileVersionScript); err == nil {
		pkgs = append(pkgs, parseWindowsInventory(fv)...)
	}

	// winget, where available: the package-manager identifier is the most
	// stable cross-source identifier Windows has. Best effort, strictly
	// bounded; its absence is a coverage note, never an error.
	if wingetPkgs, ok := collectWinget(ctx, execFn, pkgs); ok {
		pkgs = append(pkgs, wingetPkgs...)
	}
	return pkgs, nil
}

// windowsPackage is the PowerShell object shape (an array serialises as a list,
// a single application as an object, so both are handled).
// NOTE: the JSON object shape for the collector result is in the script above;
// the fields here mirror it.
type windowsPackage struct {
	Name        string `json:"name"`
	Version     string `json:"version"`
	Publisher   string `json:"publisher"`
	InstallDate string `json:"install_date"`
	Location    string `json:"location"`
	Scope       string `json:"scope"`
	Arch        string `json:"arch"`
	ProductID   string `json:"product_id"`
	MSI         bool   `json:"msi"`
	URLAbout    string `json:"url_about"`
	Source      string `json:"source"`
	PkgID       string `json:"pkg_id"`
}

func parseWindowsInventory(raw []byte) []model.Package {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return nil
	}
	var list []windowsPackage
	if err := json.Unmarshal(raw, &list); err != nil {
		var single windowsPackage
		if err2 := json.Unmarshal(raw, &single); err2 != nil {
			return nil
		}
		list = []windowsPackage{single}
	}
	out := make([]model.Package, 0, len(list))
	for _, p := range list {
		if p.Name == "" {
			continue
		}
		// An MSI entry whose product code already produced an Uninstall
		// record adds no identity; the deduplicator merges them.
		pkg := model.Package{
			Name:            strings.TrimSpace(p.Name),
			Version:         strings.TrimSpace(p.Version),
			Ecosystem:       model.EcosystemWindows,
			Source:          model.OriginManifest,
			Manager:         sourceManager(p.Source),
			Vendor:          strings.TrimSpace(p.Publisher),
			Publisher:       strings.TrimSpace(p.Publisher),
			InstallDate:     strings.TrimSpace(p.InstallDate),
			Location:        strings.TrimSpace(p.Location),
			Scope:           strings.TrimSpace(p.Scope),
			Arch:            normalizeArchField(p.Arch),
			ProductID:       strings.TrimSpace(p.ProductID),
			PkgManagerID:    strings.TrimSpace(p.PkgID),
			EvidenceSources: []string{evSource(p.Source, p.Scope, p.Arch)},
		}
		if pkg.Version == "" && p.Source == "registry" {
			// A registry entry without a DisplayVersion cannot be evaluated;
			// keep it with an empty version so coverage shows it was skipped.
		}
		out = append(out, pkg)
	}
	return out
}

func sourceManager(source string) string {
	switch source {
	case "registry":
		return "windows-registry"
	case "msi":
		return "windows-installer"
	case "click_to_run":
		return "office-click-to-run"
	case "file_version":
		return "file-version"
	case "winget":
		return "winget"
	}
	return "windows-registry"
}

func evSource(source, scope, arch string) string {
	return strings.Join([]string{source, scope, arch}, "/")
}

func normalizeArchField(arch string) string {
	switch strings.ToLower(strings.TrimSpace(arch)) {
	case "x64", "x86", "arm64":
		return strings.ToLower(strings.TrimSpace(arch))
	}
	return ""
}

// collectWinget inventories the Windows Package Manager database when winget
// is present. It is strictly best-effort: winget is not part of every Windows
// build, and its first run can be slow, so the command is bounded by a hard
// timeout and its absence is a coverage note, not an error. The export is
// JSON (winget export) and is parsed as data.
func collectWinget(ctx context.Context, execFn func(context.Context, string, ...string) ([]byte, error), registry []model.Package) ([]model.Package, bool) {
	if _, err := execFn(ctx, "winget", "--version"); err != nil {
		return nil, false
	}
	// A temporary output file keeps the export out of memory and unparseable
	// tables out of the pipeline entirely.
	tmp, err := os.CreateTemp("", "clanker-winget-*.json")
	if err != nil {
		return nil, false
	}
	name := tmp.Name()
	tmp.Close()
	defer os.Remove(name)

	cctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	if _, err := execFn(cctx, "winget", "export", "-o", name, "--accept-source-agreements"); err != nil {
		return nil, false
	}
	raw, err := os.ReadFile(name)
	if err != nil {
		return nil, false
	}
	var doc struct {
		Sources []struct {
			Packages []struct {
				PackageIdentifier string `json:"PackageIdentifier"`
				Name              string `json:"Name"`
				Version           string `json:"Version"`
				Publisher         string `json:"Publisher"`
				InstalledVersion  string `json:"InstalledVersion"`
			} `json:"Packages"`
		} `json:"Sources"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false
	}
	var out []model.Package
	for _, src := range doc.Sources {
		for _, p := range src.Packages {
			id := strings.TrimSpace(p.PackageIdentifier)
			if id == "" {
				continue
			}
			version := strings.TrimSpace(p.InstalledVersion)
			if version == "" {
				version = strings.TrimSpace(p.Version)
			}
			out = append(out, model.Package{
				Name:            strings.TrimSpace(p.Name),
				Version:         version,
				Ecosystem:       model.EcosystemWindows,
				Source:          model.OriginManifest,
				Manager:         "winget",
				Vendor:          strings.TrimSpace(p.Publisher),
				Publisher:       strings.TrimSpace(p.Publisher),
				PkgManagerID:    id,
				EvidenceSources: []string{"winget"},
			})
		}
	}
	return out, true
}
