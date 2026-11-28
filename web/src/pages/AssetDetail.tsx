import { ChevronDown, Play, Server } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { Link, navigate } from "../lib/router";
import { formatDate, relativeTime, riskTone } from "../lib/format";
import { PageHeader } from "../components/PageHeader";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Banner, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Input, Select } from "../components/ui/Field";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { ApplicabilityBadge, FixBadge, KevBadge, SeverityBadge } from "../components/badges";
import { cn } from "../lib/cn";

export default function AssetDetail({ host }: { host: string }) {
  const { data, error, loading, reload } = useAsync(() => api.asset(host), [host]);
  const [pkgQuery, setPkgQuery] = useState("");
  const [pkgEcosystem, setPkgEcosystem] = useState("all");
  const [openSection, setOpenSection] = useState<Record<string, boolean>>({ packages: false });

  const findings = data?.findings ?? [];
  const history = data?.history ?? [];
  const skipped = data?.skipped ?? [];
  const suppressed = data?.suppressed ?? [];
  const coverageNotices = data?.coverage_notices ?? [];
  const runErrors = data?.errors ?? [];
  const apps = data?.coverage.apps;
  const ecosystems = useMemo(
    () => Array.from(new Set((data?.packages ?? []).map((p) => p.ecosystem))).sort(),
    [data?.packages],
  );
  // Findings per installed package: matched by the inventory reference
  // (package_ref = name@version), so the software inventory can jump from
  // an application to its vulnerabilities even when the finding's display
  // product is the normalized CPE name.
  const findingsByPackage = useMemo(() => {
    const m = new Map<string, { count: number; actionable: number; q: string }>();
    for (const f of findings) {
      if (f.affected === "not_affected") continue;
      const keys = new Set<string>();
      if (f.package_ref) keys.add(f.package_ref.toLowerCase());
      keys.add(`${f.product.toLowerCase()}\u0000${f.installed_version}`);
      for (const key of keys) {
        const cur = m.get(key) ?? { count: 0, actionable: 0, q: f.product };
        cur.count++;
        if (f.affected !== "needs_investigation") cur.actionable++;
        m.set(key, cur);
      }
    }
    return m;
  }, [findings]);
  const packages = (data?.packages ?? []).filter((p) => {
    if (pkgQuery && !`${p.name} ${p.version}`.toLowerCase().includes(pkgQuery.toLowerCase())) return false;
    if (pkgEcosystem !== "all" && p.ecosystem !== pkgEcosystem) return false;
    return true;
  });

  if (loading && !data) return <LoadingBlock label="Loading asset" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return null;

  const actionable = findings.filter(
    (f) => f.affected !== "needs_investigation" && f.affected !== "not_affected",
  ).length;

  return (
    <div className="space-y-4">
      <PageHeader
        title={data.asset.hostname}
        description={
          <span className="mono">
            {data.asset.os} {data.asset.os_version}
            {data.asset.kernel ? ` · kernel ${data.asset.kernel}` : ""}
            {data.asset.arch ? ` · ${data.asset.arch}` : ""}
          </span>
        }
        actions={
          <>
            <Button onClick={() => navigate("/vulnerabilities?asset=" + encodeURIComponent(data.host))}>
              View findings
            </Button>
            <Button variant="primary" onClick={() => navigate("/scans/new")}>
              <Play className="h-4 w-4" aria-hidden="true" /> Scan asset
            </Button>
          </>
        }
      />

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-4">
        <Card className="p-4">
          <p className="text-xs uppercase tracking-wide text-muted">Findings</p>
          <p className="num mt-1 text-2xl font-semibold">{actionable}</p>
          <p className="text-xs text-muted">{findings.length} total records</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs uppercase tracking-wide text-muted">Packages</p>
          <p className="num mt-1 text-2xl font-semibold">{data.package_count}</p>
          <p className="text-xs text-muted">from package-manager metadata</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs uppercase tracking-wide text-muted">Last scan</p>
          <p className="mt-1 text-lg font-semibold">{relativeTime(data.last_scan)}</p>
          <p className="text-xs text-muted">{formatDate(data.last_scan)}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs uppercase tracking-wide text-muted">Agent</p>
          <p className="mono mt-1 text-lg font-semibold">{data.agent.version}</p>
          <p className="text-xs text-muted">{data.mode} mode · {data.offline ? "offline intelligence" : "online intelligence"}</p>
        </Card>
      </div>

      {runErrors.length > 0 ? (
        <Banner tone="warn" title="This assessment was incomplete">
          <ul className="list-disc pl-4">
            {runErrors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </Banner>
      ) : null}

      <Card>
        <CardHeader title="Findings on this asset" description={`${findings.length} records from the latest assessment`} />
        {findings.length === 0 ? (
          <CardBody>
            <p className="text-sm text-muted">
              No findings recorded for this asset in the assessed scope. Review the coverage limitations below.
            </p>
          </CardBody>
        ) : (
          <TableWrap>
            <Table caption={`Findings on ${data.host}`}>
              <thead>
                <tr>
                  <Th>CVE</Th>
                  <Th>Package</Th>
                  <Th>Severity</Th>
                  <Th>Applicability</Th>
                  <Th>Fix</Th>
                  <Th className="text-right">Risk</Th>
                </tr>
              </thead>
              <tbody>
                {findings.slice(0, 200).map((f) => (
                  <Tr key={f.id}>
                    <Td>
                      <Link to={`/vulnerabilities?q=${encodeURIComponent(f.cve)}`} className="mono text-accent underline underline-offset-2">
                        {f.cve}
                      </Link>
                      <div className="text-xs text-muted">{f.source}</div>
                    </Td>
                    <Td>
                      {f.product}
                      <div className="mono text-xs text-muted">{f.installed_version}</div>
                    </Td>
                    <Td>
                      <SeverityBadge severity={f.severity} />
                    </Td>
                    <Td>
                      <ApplicabilityBadge value={f.affected} />
                      {f.kev ? <div className="mt-1"><KevBadge ransomware={f.kev_ransomware} /></div> : null}
                    </Td>
                    <Td>
                      <FixBadge version={f.fixed_version} />
                    </Td>
                    <Td className={`num text-right font-semibold ${riskTone(f.risk_score)}`}>{f.risk_score.toFixed(1)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>

      <section className="card">
        <button
          type="button"
          className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left"
          aria-expanded={openSection.packages}
          onClick={() => setOpenSection((s) => ({ ...s, packages: !s.packages }))}
        >
          <span>
            <span className="block text-sm font-semibold">Installed software</span>
            <span className="block text-xs text-muted">
              {data.package_count} packages{data.packages_truncated ? " (first 500 shown)" : ""}
            </span>
          </span>
          <ChevronDown className={`h-4 w-4 transition-transform ${openSection.packages ? "rotate-180" : ""}`} aria-hidden="true" />
        </button>
        {openSection.packages ? (
          <div className="border-t border-border">
            <div className="flex flex-wrap gap-2 p-3">
              <div className="min-w-[14rem] flex-1">
                <label htmlFor="pkg-search" className="sr-only">
                  Search packages
                </label>
                <Input
                  id="pkg-search"
                  value={pkgQuery}
                  onChange={(e) => setPkgQuery(e.target.value)}
                  placeholder="Filter packages or versions…"
                />
              </div>
              <div>
                <label htmlFor="pkg-eco" className="sr-only">
                  Filter by ecosystem
                </label>
                <Select id="pkg-eco" value={pkgEcosystem} onChange={(e) => setPkgEcosystem(e.target.value)}>
                  <option value="all">All ecosystems</option>
                  {ecosystems.map((e) => (
                    <option key={e} value={e}>
                      {e}
                    </option>
                  ))}
                </Select>
              </div>
            </div>
            <TableWrap>
              <Table caption="Installed packages">
                <thead>
                  <tr>
                    <Th>Package</Th>
                    <Th>Version</Th>
                    <Th>Ecosystem</Th>
                    <Th>Source</Th>
                    <Th>Findings</Th>
                  </tr>
                </thead>
                <tbody>
                  {packages.slice(0, 300).map((p) => {
                    const fk =
                      findingsByPackage.get(`${p.name.toLowerCase()}\u0000${p.version}`) ??
                      findingsByPackage.get(`${p.name.toLowerCase()}@${p.version}`);
                    return (
                      <Tr key={`${p.ecosystem}-${p.name}-${p.version}`}>
                        <Td className="mono">
                          {p.name}
                          {p.publisher ? <div className="text-xs text-muted">{p.publisher}</div> : null}
                        </Td>
                        <Td className="mono text-xs">{p.version}</Td>
                        <Td className="text-xs text-muted">
                          {p.ecosystem}
                          {p.evidence_sources && p.evidence_sources.length > 1 ? (
                            <div className="text-[10px] text-subtle">via {p.evidence_sources.join(", ")}</div>
                          ) : null}
                        </Td>
                        <Td className="text-xs text-muted">{p.source}</Td>
                        <Td>
                          {fk && fk.count > 0 ? (
                            <Link
                              to={`/vulnerabilities?q=${encodeURIComponent(fk.q)}`}
                              className={`num text-xs font-semibold underline underline-offset-2 ${fk.actionable > 0 ? "text-high" : "text-muted"}`}
                            >
                              {fk.actionable > 0 ? `${fk.actionable} finding${fk.actionable === 1 ? "" : "s"}` : `${fk.count} record${fk.count === 1 ? "" : "s"}`}
                            </Link>
                          ) : (
                            <span className="text-xs text-subtle">—</span>
                          )}
                        </Td>
                      </Tr>
                    );
                  })}
                </tbody>
              </Table>
            </TableWrap>
            {packages.length > 300 ? (
              <p className="px-3 py-2 text-xs text-muted">Showing the first 300 matches. Use the filters to narrow down.</p>
            ) : null}
          </div>
        ) : null}
      </section>

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card>
          <CardHeader title="Coverage" description="What this assessment actually inspected" />
          <CardBody className="space-y-2 text-sm">
            <Row label="Packages inspected" value={String(data.coverage.packages_inspected)} />
            <Row label="Packages with matches" value={String(data.coverage.packages_matched)} />
            <Row label="Advisories checked" value={String(data.coverage.advisories_checked)} />
            <Row label="Sources" value={data.coverage.sources_used.join(", ") || "none"} />
            {(data.coverage.not_covered ?? []).length > 0 ? (
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-muted">Not covered</p>
                <ul className="mt-1 list-disc pl-4 text-muted">
                  {(data.coverage.not_covered ?? []).map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {(data.coverage.notes ?? []).length > 0 ? (
              <div className="rounded-md border border-low/30 bg-low-soft p-2">
                <p className="text-xs font-semibold text-low">What was assessed</p>
                <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-low/90">
                  {(data.coverage.notes ?? []).map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {apps ? (
              <div className={cn(
                "rounded-md border p-2",
                apps.evaluated === 0 ? "border-high/40 bg-high-soft" : "border-accent/30 bg-accent-soft",
              )}>
                <p className="text-xs font-semibold">Application assessment</p>
                <dl className="mt-1 space-y-0.5 text-xs">
                  <div className="flex justify-between gap-2">
                    <dt className="text-muted">Installed applications discovered</dt>
                    <dd className="num">{apps.discovered}</dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-muted">Successfully evaluated</dt>
                    <dd className="num">{apps.evaluated}</dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-muted">Without a vulnerability mapping</dt>
                    <dd className="num">{(apps.unrecognized ?? []).length}</dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-muted">Confirmed vulnerability matches</dt>
                    <dd className="num">{apps.confirmed_matches}</dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-muted">Potential matches (uncertain)</dt>
                    <dd className="num">{apps.potential_matches}</dd>
                  </div>
                  <div className="flex justify-between gap-2">
                    <dt className="text-muted">NVD intelligence</dt>
                    <dd className="text-xs">
                      {apps.intel_freshness && apps.intel_freshness !== "never synchronized"
                        ? formatDate(apps.intel_freshness)
                        : "never synchronized"}
                    </dd>
                  </div>
                </dl>
                {apps.evaluated === 0 && apps.discovered > 0 ? (
                  <p className="mt-1.5 text-xs">
                    Installed applications were inventoried but NOT evaluated for known vulnerabilities{" "}
                    {apps.intel_freshness === "never synchronized"
                      ? "because NVD intelligence has never been synchronized (run `feeds update --with-nvd`)."
                      : "because none could be mapped to a vulnerability identity."}{" "}
                    Zero application findings here means &ldquo;not assessed&rdquo;, not &ldquo;secure&rdquo;.
                  </p>
                ) : null}
              </div>
            ) : null}
            {(data.coverage.limitations ?? []).length > 0 ? (
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-muted">Limitations</p>
                <ul className="mt-1 list-disc pl-4 text-muted">
                  {(data.coverage.limitations ?? []).map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {coverageNotices.length > 0 ? (
              <div className="rounded-md border border-high/30 bg-high-soft p-2">
                <p className="text-xs font-semibold text-high">What this assessment does not cover</p>
                <ul className="mt-1 list-disc space-y-0.5 pl-4 text-xs text-high/90">
                  {coverageNotices.map((n) => (
                    <li key={n}>{n}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {suppressed.length > 0 ? (
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-muted">
                  Not listed separately
                </p>
                <ul className="mt-1 list-disc pl-4 text-muted">
                  {suppressed.slice(0, 5).map((reason) => (
                    <li key={reason}>{reason}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            {skipped.length > 0 ? (
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-muted">Skipped checks</p>
                <ul className="mt-1 list-disc pl-4 text-muted">
                  {skipped.map((s) => (
                    <li key={s.check}>
                      <span className="mono">{s.check}</span> — {s.reason}
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </CardBody>
        </Card>

        <Card>
          <CardHeader title="Scan history" description="Assessments stored for this host" />
          <CardBody className="p-0">
            <ul className="divide-y divide-border">
              {history.map((h) => (
                <li key={h.id} className="flex items-center justify-between gap-3 px-4 py-2.5 text-sm">
                  <span>
                    <span className="block">{formatDate(h.finished_at)}</span>
                    <span className="mono text-xs text-muted">{h.id}</span>
                  </span>
                  <Badge className="border-border bg-surface-2 text-muted">{h.actionable} actionable</Badge>
                </li>
              ))}
            </ul>
          </CardBody>
        </Card>
      </div>

      <Card>
        <CardHeader title="Endpoint identification" description="Where the inventory came from" />
        <CardBody className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
          <Row label="Hostname" value={data.asset.hostname} />
          <Row label="Distribution" value={data.asset.distro_id || "unknown"} />
          <Row label="OS" value={`${data.asset.os} ${data.asset.os_version}`} />
          <Row label="Codename" value={data.asset.os_codename || "—"} />
          <Row label="Kernel" value={data.asset.kernel || "—"} />
          <Row label="Architecture" value={data.asset.arch || "—"} />
          <Row label="Container" value={data.asset.is_container ? "yes" : "no"} />
          <Row label="Report" value={<span className="mono text-xs">{data.report_id}</span>} />
        </CardBody>
      </Card>
      <p className="flex items-center gap-1 text-xs text-muted">
        <Server className="h-3.5 w-3.5" aria-hidden="true" /> Inventory is read-only package-manager metadata; no files,
        credentials or documents were collected.
      </p>
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/60 pb-1.5">
      <span className="text-muted">{label}</span>
      <span className="text-right font-medium">{value}</span>
    </div>
  );
}
