package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

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
// Uninstall registry hives (64-bit, 32-bit and per-user). It is read-only and
// uses a fixed PowerShell query; no Windows Update API is touched here.
type WindowsRegistryCollector struct {
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (c *WindowsRegistryCollector) Name() string { return "windows_registry" }

const windowsInventoryScript = `$ErrorActionPreference='SilentlyContinue';
$paths=@('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
         'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*');
$out=@();
foreach($p in $paths){
  Get-ItemProperty $p | Where-Object { $_.DisplayName -and $_.DisplayVersion } |
    ForEach-Object { $out += [pscustomobject]@{name=$_.DisplayName; version=$_.DisplayVersion; publisher=$_.Publisher} }
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
	return parseWindowsInventory(out), nil
}

// windowsPackage is the PowerShell object shape (an array serialises as a list,
// a single application as an object, so both are handled).
type windowsPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
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
		if p.Name == "" || p.Version == "" {
			continue
		}
		out = append(out, model.Package{
			Name:      p.Name,
			Version:   p.Version,
			Ecosystem: model.EcosystemWindows,
			Source:    model.OriginManifest,
			Manager:   "windows-registry",
			Vendor:    p.Publisher,
		})
	}
	return out
}
