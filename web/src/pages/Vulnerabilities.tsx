import { Filter, Search, ShieldAlert, X } from "lucide-react";
import { useCallback, useMemo, useState } from "react";
import { api, type Applicability, type Severity } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { navigate, useLocation } from "../lib/router";
import { applicabilityLabel, pct, pluralize, relativeTime, riskTone, severityLabel, SEVERITY_ORDER } from "../lib/format";
import { PageHeader } from "../components/PageHeader";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingBlock, Banner } from "../components/ui/Feedback";
import { Input, Select } from "../components/ui/Field";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { ApplicabilityBadge, FixBadge, KevBadge, SeverityBadge } from "../components/badges";
import { VulnerabilityDetail } from "./VulnerabilityDetail";
import { cn } from "../lib/cn";

const APPLICABILITY_FILTERS: Applicability[] = [
  "confirmed_applicability",
  "probable",
  "potential",
  "needs_investigation",
  "validated_behavior",
];

export default function Vulnerabilities() {
  const location = useLocation();
  const params = useMemo(() => new URLSearchParams(location.split("?")[1] ?? ""), [location]);
  const [query, setQuery] = useState(params.get("q") ?? "");
  const [severities, setSeverities] = useState<Severity[]>([]);
  const [applicability, setApplicability] = useState<Applicability[]>([]);
  const [kevOnly, setKevOnly] = useState(false);
  const [fix, setFix] = useState("all");
  const [asset, setAsset] = useState("all");
  const [sort, setSort] = useState("risk");
  const [openId, setOpenId] = useState<string | null>(null);

  // Keep the URL in sync from the handlers (not an effect) so filtering never
  // triggers a render-time navigation loop, while links stay shareable.
  const syncUrl = useCallback(
    (nextQuery: string, nextSeverities: Severity[]) => {
      const next = new URLSearchParams();
      if (nextQuery) next.set("q", nextQuery);
      if (nextSeverities.length) next.set("severity", nextSeverities.join(","));
      const qs = next.toString();
      const target = `/vulnerabilities${qs ? `?${qs}` : ""}`;
      if (location !== target) navigate(target, { replace: true });
    },
    [location],
  );

  const fetcher = useCallback(
    () =>
      api.vulnerabilities({
        q: query || undefined,
        severity: severities.length ? severities.join(",") : undefined,
        applicability: applicability.length ? applicability.join(",") : undefined,
        kev: kevOnly || undefined,
        fix: fix === "all" ? undefined : fix,
        asset: asset === "all" ? undefined : asset,
        sort,
        order: sort === "cve" || sort === "asset" ? "asc" : "desc",
        limit: 100,
      }),
    [query, severities, applicability, kevOnly, fix, asset, sort],
  );
  const { data, error, loading, reload } = useAsync(fetcher, [fetcher]);

  const [filtersOpen, setFiltersOpen] = useState(false);
  const shown = data?.items ?? [];
  const hasFilters = query || severities.length > 0 || applicability.length > 0 || kevOnly || fix !== "all" || asset !== "all";
  const activeFilterCount =
    severities.length + applicability.length + (kevOnly ? 1 : 0) + (fix !== "all" ? 1 : 0) + (asset !== "all" ? 1 : 0);

  function clearFilters() {
    setQuery("");
    setSeverities([]);
    setApplicability([]);
    setKevOnly(false);
    setFix("all");
    setAsset("all");
  }

  return (
    <div>
      <PageHeader
        title="Findings"
        description="One row per affected package and advisory. Applicability and confidence come from the backend — a version match alone is never presented as validated."
        actions={
          data ? (
            <span className="text-sm text-muted">
              {pluralize(data.total, "finding")}
              {data.facets.kev > 0 ? ` · ${data.facets.kev} KEV` : ""}
            </span>
          ) : null
        }
      />

      <Card>
        <div className="space-y-3 border-b border-border p-3">
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-[16rem] flex-1">
              <label htmlFor="vuln-search" className="sr-only">
                Search by CVE, package, or asset
              </label>
              <div className="relative">
                <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-subtle" aria-hidden="true" />
                <Input
                  id="vuln-search"
                  value={query}
                  onChange={(e) => {
                    setQuery(e.target.value);
                    syncUrl(e.target.value, severities);
                  }}
                  placeholder="CVE, package, host or advisory ID…"
                  className="pl-8"
                />
              </div>
            </div>
            <div>
              <label htmlFor="sort" className="sr-only">
                Sort findings
              </label>
              <Select id="sort" value={sort} onChange={(e) => setSort(e.target.value)}>
                <option value="risk">Sort: remediation priority</option>
                <option value="severity">Sort: severity</option>
                <option value="epss">Sort: EPSS probability</option>
                <option value="kev">Sort: known exploited first</option>
                <option value="first_seen">Sort: first detected</option>
                <option value="cve">Sort: CVE</option>
                <option value="asset">Sort: asset</option>
              </Select>
            </div>
            <Button
              variant={filtersOpen ? "secondary" : "ghost"}
              size="sm"
              onClick={() => setFiltersOpen((v) => !v)}
              aria-expanded={filtersOpen}
              aria-controls="finding-filters"
            >
              <Filter className="h-3.5 w-3.5" aria-hidden="true" />
              Filters{activeFilterCount > 0 ? ` (${activeFilterCount})` : ""}
            </Button>
          </div>

          <div id="finding-filters" hidden={!filtersOpen} className="space-y-3">
          <div className="flex flex-wrap items-end gap-2">
            <div>
              <label htmlFor="fix" className="sr-only">
                Filter by fix availability
              </label>
              <Select id="fix" value={fix} onChange={(e) => setFix(e.target.value)}>
                <option value="all">Any fix state</option>
                <option value="available">Fix available</option>
                <option value="none">No published fix</option>
              </Select>
            </div>
            <div>
              <label htmlFor="asset" className="sr-only">
                Filter by asset
              </label>
              <Select id="asset" value={asset} onChange={(e) => setAsset(e.target.value)}>
                <option value="all">All assets</option>
                {(data?.facets.assets ?? []).map((a) => (
                  <option key={a.key} value={a.key}>
                    {a.key} ({a.count})
                  </option>
                ))}
              </Select>
            </div>
            {hasFilters ? (
              <Button variant="ghost" size="sm" onClick={clearFilters}>
                <X className="h-3.5 w-3.5" aria-hidden="true" /> Clear
              </Button>
            ) : null}
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 flex items-center gap-1 text-xs font-medium text-muted">
              <Filter className="h-3.5 w-3.5" aria-hidden="true" /> Severity
            </span>
            {SEVERITY_ORDER.map((sev) => {
              const active = severities.includes(sev);
              const count = data?.facets.severity.find((s) => s.key === sev)?.count ?? 0;
              return (
                <button
                  key={sev}
                  type="button"
                  aria-pressed={active}
                  onClick={() => {
                    const next = active ? severities.filter((x) => x !== sev) : [...severities, sev];
                    setSeverities(next);
                    syncUrl(query, next);
                  }}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-xs",
                    active ? "border-accent bg-accent-soft font-medium text-accent" : "border-border text-muted hover:bg-surface-2",
                  )}
                >
                  {severityLabel[sev]} <span className="num">{count}</span>
                </button>
              );
            })}
            <span className="mx-2 h-4 w-px bg-border" aria-hidden="true" />
            <button
              type="button"
              aria-pressed={kevOnly}
              onClick={() => setKevOnly((v) => !v)}
              className={cn(
                "rounded-full border px-2.5 py-1 text-xs",
                kevOnly ? "border-critical bg-critical-soft font-medium text-critical" : "border-border text-muted hover:bg-surface-2",
              )}
            >
              Known exploited (KEV) <span className="num">{data?.facets.kev ?? 0}</span>
            </button>
            <button
              type="button"
              aria-pressed={fix === "available"}
              onClick={() => setFix(fix === "available" ? "all" : "available")}
              className={cn(
                "rounded-full border px-2.5 py-1 text-xs",
                fix === "available" ? "border-accent bg-accent-soft font-medium text-accent" : "border-border text-muted hover:bg-surface-2",
              )}
            >
              Fix available <span className="num">{data?.facets.fix_available ?? 0}</span>
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-xs font-medium text-muted">Applicability</span>
            {APPLICABILITY_FILTERS.map((app) => {
              const active = applicability.includes(app);
              return (
                <button
                  key={app}
                  type="button"
                  aria-pressed={active}
                  onClick={() => setApplicability((s) => (active ? s.filter((x) => x !== app) : [...s, app]))}
                  className={cn(
                    "rounded-full border px-2.5 py-1 text-xs",
                    active ? "border-accent bg-accent-soft font-medium text-accent" : "border-border text-muted hover:bg-surface-2",
                  )}
                >
                  {applicabilityLabel[app]}
                </button>
              );
            })}
          </div>
          </div>
        </div>

        {error ? <ErrorState message={error.message} onRetry={reload} /> : null}
        {loading && !data ? <LoadingBlock label="Loading findings" /> : null}

        {data && shown.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert className="h-5 w-5" />}
            title={data.total === 0 && !hasFilters ? "No findings in the assessed scope" : "No findings match these filters"}
            description={
              data.total === 0 && !hasFilters
                ? "The last scan completed without identifying applicable vulnerabilities in the packages it covered. That is not a guarantee the environment is secure — review scan coverage and limitations on the Overview page."
                : "Adjust or clear the filters to see other findings."
            }
            action={hasFilters ? <Button onClick={clearFilters}>Clear filters</Button> : undefined}
          />
        ) : null}

        {shown.length > 0 ? (
          <TableWrap>
            <Table caption="Vulnerability findings">
              <thead>
                <tr>
                  <Th>CVE / advisory</Th>
                  <Th>Affected asset</Th>
                  <Th>Package</Th>
                  <Th>Severity</Th>
                  <Th>Applicability</Th>
                  <Th>Exploitation</Th>
                  <Th>Fix</Th>
                  <Th className="text-right">Risk</Th>
                </tr>
              </thead>
              <tbody>
                {shown.map((v) => (
                  <Tr key={v.id} className="cursor-pointer" onClick={() => setOpenId(v.id)}>
                    <Td>
                      <button
                        type="button"
                        className="mono text-left text-accent underline underline-offset-2"
                        onClick={(e) => {
                          e.stopPropagation();
                          setOpenId(v.id);
                        }}
                      >
                        {v.cve}
                      </button>
                      <div className="text-xs text-muted">
                        {v.source}
                        {v.aliases && v.aliases.length > 1 ? ` · ${v.aliases.length} aliases` : ""}
                      </div>
                    </Td>
                    <Td>
                      <span className="mono text-xs">{v.asset}</span>
                      <div className="whitespace-nowrap text-xs text-muted">first seen {relativeTime(v.first_seen)}</div>
                    </Td>
                    <Td>
                      <span className="text-sm">{v.product}</span>
                      <div className="mono text-xs text-muted">
                        {v.installed_version} · {v.ecosystem}
                      </div>
                    </Td>
                    <Td>
                      <SeverityBadge severity={v.severity} />
                      {v.cvss !== null ? <div className="num mt-1 text-xs text-muted">CVSS {v.cvss.toFixed(1)}</div> : null}
                    </Td>
                    <Td>
                      <ApplicabilityBadge value={v.affected} />
                    </Td>
                    <Td>
                      <div className="flex flex-col gap-1">
                        {v.kev ? <KevBadge ransomware={v.kev_ransomware} /> : <span className="text-xs text-muted">Not in KEV</span>}
                        <span className="num text-xs text-muted">EPSS {pct(v.epss)}</span>
                      </div>
                    </Td>
                    <Td>
                      <FixBadge version={v.fixed_version} />
                    </Td>
                    <Td className={cn("num text-right font-semibold", riskTone(v.risk_score))}>{v.risk_score.toFixed(1)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        ) : null}

        {data && data.total > shown.length ? (
          <Banner tone="info">
            Showing {shown.length} of {data.total} findings. Narrow the filters or search for a specific CVE to see the
            rest.
          </Banner>
        ) : null}
      </Card>

      <VulnerabilityDetail id={openId} onClose={() => setOpenId(null)} />
    </div>
  );
}
