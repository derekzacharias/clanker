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

export default function AssetDetail({ host }: { host: string }) {
  const { data, error, loading, reload } = useAsync(() => api.asset(host), [host]);
  const [pkgQuery, setPkgQuery] = useState("");
  const [pkgEcosystem, setPkgEcosystem] = useState("all");
  const [openSection, setOpenSection] = useState<Record<string, boolean>>({ packages: false });

  const ecosystems = useMemo(
    () => Array.from(new Set((data?.packages ?? []).map((p) => p.ecosystem))).sort(),
    [data?.packages],
  );
  const packages = (data?.packages ?? []).filter((p) => {
    if (pkgQuery && !`${p.name} ${p.version}`.toLowerCase().includes(pkgQuery.toLowerCase())) return false;
    if (pkgEcosystem !== "all" && p.ecosystem !== pkgEcosystem) return false;
    return true;
  });

  if (loading && !data) return <LoadingBlock label="Loading asset" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return null;

  const actionable = data.findings.filter((f) => f.affected !== "needs_investigation" && f.affected !== "not_affected").length;

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

      <div className="grid gap-3 lg:grid-cols-4">
        <Card className="p-4">
          <p className="text-xs uppercase tracking-wide text-muted">Findings</p>
          <p className="num mt-1 text-2xl font-semibold">{actionable}</p>
          <p className="text-xs text-muted">{data.findings.length} total records</p>
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

      {data.errors.length > 0 ? (
        <Banner tone="warn" title="This assessment was incomplete">
          <ul className="list-disc pl-4">
            {data.errors.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </Banner>
      ) : null}

      <Card>
        <CardHeader title="Findings on this asset" description={`${data.findings.length} records from the latest assessment`} />
        {data.findings.length === 0 ? (
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
                {data.findings.slice(0, 200).map((f) => (
                  <Tr key={f.id}>
                    <Td>
                      <Link to={`/vulnerabilities?q=${encodeURIComponent(f.cve)}`} className="mono text-accent hover:underline">
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
                  </tr>
                </thead>
                <tbody>
                  {packages.slice(0, 300).map((p) => (
                    <Tr key={`${p.ecosystem}-${p.name}-${p.version}`}>
                      <Td className="mono">{p.name}</Td>
                      <Td className="mono text-xs">{p.version}</Td>
                      <Td className="text-xs text-muted">{p.ecosystem}</Td>
                      <Td className="text-xs text-muted">{p.source}</Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
            {packages.length > 300 ? (
              <p className="px-3 py-2 text-xs text-muted">Showing the first 300 matches. Use the filters to narrow down.</p>
            ) : null}
          </div>
        ) : null}
      </section>

      <div className="grid gap-3 lg:grid-cols-2">
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
            {(data.skipped ?? []).length > 0 ? (
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-muted">Skipped checks</p>
                <ul className="mt-1 list-disc pl-4 text-muted">
                  {data.skipped.map((s) => (
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
              {data.history.map((h) => (
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
        <CardBody className="grid gap-2 text-sm sm:grid-cols-2">
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
