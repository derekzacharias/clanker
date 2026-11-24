package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bgdnvk/clanker/internal/vuln/model"
)

// Windows servicing state.
//
// The rules this collector follows, all of them because a silent empty answer is worse than a
// loud missing one:
//   - nothing here writes: no update is downloaded, installed or hidden, no policy is touched;
//   - every source records its own outcome ("ok", "failed: …", "unavailable"), so partial
//     coverage is visible instead of looking like a clean host;
//   - the Windows Update Agent is asked what it considers *applicable and not installed*,
//     which is Windows' own answer and the strongest evidence available on the endpoint;
//   - Win32_Product is never used (it triggers MSI reconfiguration and is unreliable).

// WindowsStateCollector gathers servicing identity, installed updates, applicable missing
// security updates, .NET versions, pending-reboot state, and packaged (MSIX/Store) applications.
type WindowsStateCollector struct {
	Exec func(ctx context.Context, name string, args ...string) ([]byte, error)
}

func (c *WindowsStateCollector) Name() string { return "windows_state" }

func (c *WindowsStateCollector) exec(ctx context.Context, script string) ([]byte, error) {
	fn := c.Exec
	if fn == nil {
		fn = run
	}
	return fn(ctx, "powershell", "-NoProfile", "-NonInteractive", "-Command", script)
}

// windowsStateScript reads identity, hotfixes, .NET releases and pending-reboot flags.
const windowsStateScript = `$ErrorActionPreference='SilentlyContinue'
$k=Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$kbs=@(Get-HotFix | ForEach-Object { $_.HotFixID } | Where-Object { $_ -like 'KB*' } | Sort-Object -Unique)
$dotnet=@()
$ndp='HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full'
if (Test-Path $ndp) { $r=(Get-ItemProperty $ndp).Release; if ($r) { $dotnet += "NET Framework 4.x ($r)" } }
$runtimes='HKLM:\SOFTWARE\dotnet\Setup\InstalledVersions\x64\sharedfx'
if (Test-Path $runtimes) { $dotnet += @(Get-ChildItem $runtimes | ForEach-Object { $_.PSChildName }) }
$pending=@()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $pending += 'CBS reboot pending' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $pending += 'Windows Update reboot required' }
if (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations') { $pending += 'pending file renames' }
[pscustomobject]@{
  product=$k.ProductName; display=$k.DisplayVersion; build=$k.CurrentBuild;
  major=$k.CurrentMajorVersionNumber; minor=$k.CurrentMinorVersionNumber; ubr=$k.UBR;
  installed_kbs=$kbs; dotnet=$dotnet; pending_reboot=$pending
} | ConvertTo-Json -Compress -Depth 4`

// windowsUpdateScript asks the Windows Update Agent what is applicable and missing.
//
// Read-only: CreateUpdateSearcher + Search. Nothing is downloaded, installed or hidden.
const windowsUpdateScript = `$ErrorActionPreference='Stop'
try {
  $session = New-Object -ComObject Microsoft.Update.Session
  $searcher = $session.CreateUpdateSearcher()
  $result = $searcher.Search("IsInstalled=0 and IsHidden=0 and Type='Software'")
  $out = @()
  foreach ($u in $result.Updates) {
    $kbs = @()
    foreach ($kb in $u.KBArticleIDs) { $kbs += "KB" + $kb }
    $cats = @()
    foreach ($c in $u.Categories) { $cats += $c.Name }
    $out += [pscustomobject]@{
      title=$u.Title; kb_ids=$kbs; msrc_severity=$u.MsrcSeverity;
      classifications=$cats; reboot_behavior=[string]$u.InstallationBehavior.RebootBehavior;
      downloaded=$u.IsDownloaded; support_url=$u.SupportURL
    }
  }
  [pscustomobject]@{ status='ok'; updates=$out } | ConvertTo-Json -Compress -Depth 5
} catch {
  [pscustomobject]@{ status='unavailable'; error=$_.Exception.Message } | ConvertTo-Json -Compress
}`

// windowsAppxScript lists packages installed for the user running the scan.
const windowsAppxScript = `$ErrorActionPreference='SilentlyContinue'
@(Get-AppxPackage | Where-Object { $_.Name -and $_.Version } | ForEach-Object {
  [pscustomobject]@{ name=$_.Name; version=$_.Version; publisher=$_.Publisher; family=$_.PackageFamilyName }
}) | ConvertTo-Json -Compress -Depth 3`

// CollectState implements StateCollector.
func (c *WindowsStateCollector) CollectState(ctx context.Context, opts Options) (model.WindowsState, error) {
	if platform() != "windows" {
		return model.WindowsState{}, fmt.Errorf("%w: windows state collector only runs on Windows", ErrUnavailable)
	}
	state := model.WindowsState{CollectorStatus: map[string]string{}}

	out, err := c.exec(ctx, windowsStateScript)
	if err != nil {
		state.CollectorStatus["identity"] = "failed: " + trimErr(err)
		return state, nil
	}
	var raw struct {
		Product   string   `json:"product"`
		Display   string   `json:"display"`
		Build     string   `json:"build"`
		Major     any      `json:"major"`
		Minor     any      `json:"minor"`
		UBR       any      `json:"ubr"`
		Installed []string `json:"installed_kbs"`
		DotNet    []string `json:"dotnet"`
		Pending   []string `json:"pending_reboot"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		state.CollectorStatus["identity"] = "failed: unreadable output"
		return state, nil
	}
	state.Product = strings.TrimSpace(raw.Product)
	state.DisplayVersion = strings.TrimSpace(raw.Display)
	state.Build = windowsBuild(raw.Build, raw.Major, raw.Minor, raw.UBR)
	state.InstalledUpdates = raw.Installed
	state.DotNet = raw.DotNet
	state.PendingReasons = raw.Pending
	state.PendingReboot = len(raw.Pending) > 0
	state.CollectorStatus["identity"] = "ok"
	if len(state.InstalledUpdates) == 0 {
		state.CollectorStatus["hotfix"] = "no KB updates reported (Get-HotFix returned none; this may be a permission limit)"
	} else {
		state.CollectorStatus["hotfix"] = "ok"
	}

	// Windows Update Agent: the authoritative applicability answer.
	if wua, err := c.exec(ctx, windowsUpdateScript); err == nil {
		var res struct {
			Status  string `json:"status"`
			Error   string `json:"error"`
			Updates []struct {
				Title           string   `json:"title"`
				KBs             []string `json:"kb_ids"`
				Severity        string   `json:"msrc_severity"`
				Classifications []string `json:"classifications"`
				Reboot          string   `json:"reboot_behavior"`
				Downloaded      bool     `json:"downloaded"`
				SupportURL      string   `json:"support_url"`
			} `json:"updates"`
		}
		if err := json.Unmarshal(wua, &res); err == nil && res.Status == "ok" {
			state.WUAStatus = "ok"
			for _, u := range res.Updates {
				state.MissingUpdates = append(state.MissingUpdates, model.WindowsUpdate{
					Title: u.Title, KBs: u.KBs, MsrcSeverity: u.Severity,
					Classification: u.Classifications, RebootBehavior: u.Reboot,
					Downloaded: u.Downloaded, SupportURL: u.SupportURL,
				})
			}
			state.CollectorStatus["windows_update"] = fmt.Sprintf("ok (%d applicable updates)", len(state.MissingUpdates))
		} else {
			reason := "unavailable"
			if res.Error != "" {
				reason = "unavailable: " + res.Error
			}
			state.WUAStatus = reason
			state.CollectorStatus["windows_update"] = reason
		}
	} else {
		state.WUAStatus = "unavailable: " + trimErr(err)
		state.CollectorStatus["windows_update"] = state.WUAStatus
	}
	return state, nil
}

// Collect returns MSIX/Store packages, which the registry collector cannot see.
func (c *WindowsStateCollector) Collect(ctx context.Context, opts Options) ([]model.Package, error) {
	if platform() != "windows" {
		return nil, fmt.Errorf("%w: windows appx collector only runs on Windows", ErrUnavailable)
	}
	out, err := c.exec(ctx, windowsAppxScript)
	if err != nil {
		return nil, fmt.Errorf("%w: appx query failed: %v", ErrUnavailable, err)
	}
	return parseAppxPackages(out), nil
}

type appxPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Publisher string `json:"publisher"`
	Family    string `json:"family"`
}

func parseAppxPackages(raw []byte) []model.Package {
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == 0 {
		return nil
	}
	var list []appxPackage
	if err := json.Unmarshal(raw, &list); err != nil {
		var single appxPackage
		if err2 := json.Unmarshal(raw, &single); err2 != nil {
			return nil
		}
		list = []appxPackage{single}
	}
	out := make([]model.Package, 0, len(list))
	for _, p := range list {
		if p.Name == "" || p.Version == "" {
			continue
		}
		// Package names look like Microsoft.WindowsCalculator_11.2210.0.0_x64__8wekyb3d8bbwe;
		// the readable product is the first segment before the version.
		name := p.Name
		if i := strings.Index(name, "_"); i > 0 {
			name = name[:i]
		}
		out = append(out, model.Package{
			Name: name, Version: p.Version, Ecosystem: model.EcosystemWindows,
			Source: model.OriginAppx, Manager: "appx", Vendor: p.Publisher, Origin: p.Family,
		})
	}
	return out
}

// windowsBuild composes major.minor.build.UBR from the registry values.
func windowsBuild(build string, major, minor, ubr any) string {
	build = strings.TrimSpace(build)
	if build == "" {
		return ""
	}
	maj, min := jsonNumber(major), jsonNumber(minor)
	if maj != "" && min != "" {
		build = maj + "." + min + "." + build
	}
	if u := jsonNumber(ubr); u != "" {
		build += "." + u
	}
	return build
}

func jsonNumber(v any) string {
	switch n := v.(type) {
	case float64:
		return fmt.Sprintf("%d", int(n))
	case string:
		return strings.TrimSpace(n)
	}
	return ""
}

func trimErr(err error) string {
	s := strings.TrimSpace(err.Error())
	if len(s) > 160 {
		s = s[:160] + "…"
	}
	return strings.ReplaceAll(s, "\n", " ")
}
