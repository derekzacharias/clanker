# Windows assessment

Windows endpoints are assessed by the same agent, reported into the same findings, and remediated
through the same tickets as Linux. This document describes what is actually collected, how a
Windows finding is decided, and what is deliberately not covered yet.

---

## 1. What the agent collects

| Source | Collected | Notes |
|---|---|---|
| Registry `CurrentVersion` | product, edition, release, build, UBR | e.g. `Windows 11 Pro`, `24H2`, `10.0.26100.1742` |
| `Get-HotFix` | installed KB identifiers | a permission failure is recorded, not silently empty |
| **Windows Update Agent** (COM) | **applicable, not-installed updates** with KB IDs, MSRC severity, classification, reboot behaviour | read-only `Search("IsInstalled=0 and IsHidden=0 and Type='Software'")`; nothing is downloaded or installed |
| `Get-AppxPackage` | MSIX / Store packages | per-user: only the packages of the account running the scan are visible |
| Registry Uninstall hives | 32/64-bit and per-user desktop applications | Edge, Chrome, Office, VMware Tools, runtimes |
| NDP / shared FX keys | .NET Framework and runtime versions | |
| CBS / WU / pending-file-rename keys | pending reboot state | a staged-but-unapplied update is visible as such |

Nothing is written to the host: no update is downloaded, installed or hidden, no policy is
changed and no reboot is initiated. `Win32_Product` is never used (it triggers MSI
reconfiguration).

## 2. How a Windows finding is decided

```
Windows Update Agent: "KB5044284 is applicable and not installed"
        → Microsoft advisory data: which CVEs does KB5044284 fix for this product?
        → finding per CVE, evidence = WUA result + build + advisory
```

The rule is deliberate:

* **Applicability comes from Windows**, not from an absent KB. A machine that never had a KB
  because it shipped with a later build is not flagged.
* **Security classifications only.** Feature packs and drivers are not vulnerabilities.
* **Product matching uses family, release and architecture** (`Windows 11` + `24H2` + x64). An
  advisory naming `Windows 11 Version 23H2` never matches a `24H2` host.
* **No data means no finding, and it says so.** If the agent did not run, the release is unknown,
  or Microsoft's advisories are missing, the report carries a coverage note instead of a clean
  result.
* **Updates with no CVE mapping stay visible** as indeterminate coverage: the update is still
  missing even when no advisory names a CVE for it.
* Findings are deterministic: the identity is host + KB + CVE, so repeated scans dedupe.

## 3. Advisory data

`clanker-guard-agent feeds update --with-msrc` (on by default on Windows) imports Microsoft's
Security Update Guide CVRF documents:

* the last **6 months** by default (`--msrc-months`), never more than 24 per run;
* every monthly bundle is parsed for products, CVEs, severity, CVSS and KB remediations;
* the bound is *recorded*: the sync state lists how many bundles were available, imported and
  skipped, so a small import is visible rather than implied;
* a failed document is skipped and recorded; a run where every document fails is an error.

`clanker-guard-agent feeds status` prints the last sync and warns when it is older than 35 days.

Migrations are additive: `msrc_products`, `msrc_cves`, `msrc_fixes`, `msrc_sync`. Existing caches
gain them on open; no report or remediation data is touched.

## 4. What a Windows finding contains

Hostname, product, CVE, installed build, fixed-by KB, Microsoft severity and CVSS, the WUA
evidence (update title, "applicable and not installed"), the advisory link, reboot requirement and
a remediation that names Windows Update and explains that cumulative updates supersede earlier
ones. Verification is unchanged from Linux: a later scan that no longer reports the update.

## 5. Coverage states

The inventory reports each source separately (`identity`, `hotfix`, `windows_update`, `appx`), and
the report carries coverage notes when something was not assessed. The asset page renders them under
**What this assessment does not cover**. Absence of a source is never rendered as zero risk.

## 5a. One ticket per remediation action

A Windows cumulative update closes hundreds or thousands of CVEs. Filing one ticket per CVE is
technically traceable and operationally useless, so the tracker gets **one issue per action** while
every individual finding stays in Clanker Guard for audit and reporting.

* `POST /api/integrations/gitlab/group-tickets {asset, product, fixed_version}` files the ticket
  for one action; the Remediation → **By upgrade** tab has a *File ticket* button per group.
* The issue lists the host, IP, OS, product, installed and fixed versions, the KB, severity counts,
  the KEV count, every CVE in a collapsible block, installation commands, reboot requirement and
  verification steps.
* Idempotent: the group key (asset + product + fixed version) is the dedupe key, so a second scan
  reuses the issue. If a later scan finds *more* CVEs behind the same action, the existing issue is
  rewritten (its content digest changes) rather than a second one being opened.
* Closing the ticket is a human action; Clanker Guard only resolves findings when a later
  assessment stops reporting them.

## 6. Deliberately not implemented

| Gap | Why it matters | Next step |
|---|---|---|
| Offline scanning from `wsusscn2.cab` | air-gapped fleets cannot reach WUA online | parse the signed catalog; it is a separate binary-format project |
| Windows Update *history* (vs `Get-HotFix`) | superseded updates can disappear from the current list | combine both sources into `installed_updates` |
| NVD/CPE matching for third-party apps | desktop apps have no MSRC advisory; today they produce no findings | a CPE normalisation layer with version-range logic |
| Per-KB ticket grouping | one cumulative update yields many CVE findings (grouped in the UI by upgrade, but not yet when filing a ticket) | file one ticket per KB, listing the CVEs |
| Verification of *superseding* updates | a newer cumulative update resolves older CVEs implicitly | treat "fixed by a superseding KB" as verified once WUA stops listing the older one |

Until those exist, a Windows host with a fully updated WUA and imported advisories produces
accurate findings; a host where any link is missing produces an explicit coverage gap.
