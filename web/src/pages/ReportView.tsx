import { ArrowLeft, Download } from "lucide-react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { Link } from "../lib/router";
import { formatDate, num, pct, relativeTime, riskTone, severityLabel } from "../lib/format";
import { PageHeader } from "../components/PageHeader";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Banner, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { ApplicabilityBadge, ConfidenceBadge, FixBadge, KevBadge, SeverityBadge } from "../components/badges";
import type { Applicability, Severity } from "../lib/api";

interface ReportFinding {
  finding_id: string;
  product: string;
  installed_version: string;
  ecosystem: string;
  vulnerability_id: string;
  severity: Severity;
  affected: Applicability;
  confidence: "high" | "medium" | "low";
  cisa_kev: boolean;
  epss?: { score: number } | null;
  fixed_version?: string;
  risk_score: number;
  source: string;
}

const FORMATS = ["json", "markdown", "sarif", "html"] as const;

export default function ReportView({ id }: { id: string }) {
  const { data, error, loading, reload } = useAsync(() => api.report(id), [id]);

  if (loading && !data) return <LoadingBlock label="Loading report" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return null;

  const findings = (data.findings as unknown as ReportFinding[]).filter((f) => f.affected !== "not_affected");
  const summary = data.summary;

  return (
    <div className="space-y-4">
      <PageHeader
        title={`Report ${data.report_id}`}
        description={
          <>
            {data.metadata.host} · {data.metadata.mode} scan · completed{" "}
            {relativeTime(data.metadata.finished_at)} · {data.metadata.offline ? "offline intelligence" : "online intelligence"} · tool{" "}
            {data.metadata.tool_version}
          </>
        }
        actions={
          <>
            <Link to="/reports" className="inline-flex items-center gap-1 text-sm text-muted hover:text-fg">
              <ArrowLeft className="h-4 w-4" aria-hidden="true" /> All reports
            </Link>
            {FORMATS.map((f) => (
              <a
                key={f}
                href={api.exportUrl(id, f)}
                className="inline-flex h-8 items-center gap-1 rounded-md border border-border-strong px-2.5 text-[0.8125rem] hover:bg-surface-2"
              >
                <Download className="h-3.5 w-3.5" aria-hidden="true" />
                {f}
              </a>
            ))}
          </>
        }
      />

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-5">
        {(["critical", "high", "medium", "low"] as Severity[]).map((s) => (
          <Card key={s} className="p-4">
            <p className="text-xs uppercase tracking-wide text-muted">{severityLabel[s]}</p>
            <p className="num mt-1 text-2xl font-semibold">{summary.by_severity?.[s] ?? 0}</p>
          </Card>
        ))}
        <Card className="p-4">
          <p className="text-xs uppercase tracking-wide text-muted">Known exploited</p>
          <p className="num mt-1 text-2xl font-semibold">{summary.kev_count}</p>
        </Card>
      </div>

      <Card>
        <CardHeader title="Assessment summary" description="What the scan did and did not cover" />
        <CardBody className="grid gap-3 text-sm sm:grid-cols-2">
          <div className="space-y-2">
            <Row label="Packages inspected" value={String(data.metadata.coverage?.packages_inspected ?? 0)} />
            <Row label="Packages with matches" value={String(data.metadata.coverage?.packages_matched ?? 0)} />
            <Row label="Advisories checked" value={String(data.metadata.coverage?.advisories_checked ?? 0)} />
            <Row label="Actionable findings" value={String(summary.actionable)} />
            <Row label="Started" value={formatDate(data.metadata.started_at)} />
            <Row label="Finished" value={formatDate(data.metadata.finished_at)} />
          </div>
          <div className="space-y-2">
            <p className="text-xs font-semibold uppercase tracking-wide text-muted">Sources</p>
            <ul className="flex flex-wrap gap-1.5">
              {(data.metadata.coverage?.sources_used ?? []).map((s) => (
                <li key={s} className="rounded border border-border px-1.5 py-0.5 text-xs text-muted">
                  {s}
                </li>
              ))}
            </ul>
            {(data.metadata.coverage?.limitations ?? []).length > 0 ? (
              <>
                <p className="pt-2 text-xs font-semibold uppercase tracking-wide text-muted">Limitations</p>
                <ul className="list-disc space-y-1 pl-4 text-xs text-muted">
                  {(data.metadata.coverage?.limitations ?? []).map((l) => (
                    <li key={l}>{l}</li>
                  ))}
                </ul>
              </>
            ) : null}
          </div>
        </CardBody>
      </Card>

      {(data.metadata.errors ?? []).length > 0 ? (
        <Banner tone="warn" title="Degraded coverage">
          <ul className="list-disc pl-4">
            {(data.metadata.errors ?? []).map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        </Banner>
      ) : null}

      <Card>
        <CardHeader title="Findings" description={`${findings.length} actionable or unresolved records`} />
        {findings.length === 0 ? (
          <CardBody>
            <p className="text-sm text-muted">
              No findings were identified within this scan's coverage. That is not a statement that the environment is
              secure — see the limitations above.
            </p>
          </CardBody>
        ) : (
          <TableWrap>
            <Table caption="Report findings">
              <thead>
                <tr>
                  <Th>CVE</Th>
                  <Th>Package</Th>
                  <Th>Severity</Th>
                  <Th>Applicability</Th>
                  <Th>Confidence</Th>
                  <Th>EPSS</Th>
                  <Th>Fix</Th>
                  <Th className="text-right">Risk</Th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <Tr key={f.finding_id + f.vulnerability_id}>
                    <Td>
                      <Link
                        to={`/vulnerabilities?q=${encodeURIComponent(f.vulnerability_id)}`}
                        className="mono text-xs text-accent hover:underline"
                      >
                        {f.vulnerability_id}
                      </Link>
                      <div className="text-xs text-muted">{f.source}</div>
                    </Td>
                    <Td>
                      {f.product}
                      <div className="mono text-xs text-muted">{f.installed_version}</div>
                    </Td>
                    <Td>
                      <SeverityBadge severity={f.severity} />
                      {f.cisa_kev ? <div className="mt-1"><KevBadge /></div> : null}
                    </Td>
                    <Td>
                      <ApplicabilityBadge value={f.affected} />
                    </Td>
                    <Td>
                      <ConfidenceBadge value={f.confidence} />
                    </Td>
                    <Td className="num text-xs">{pct(f.epss?.score ?? null)}</Td>
                    <Td>
                      <FixBadge version={f.fixed_version} />
                    </Td>
                    <Td className={`num text-right font-semibold ${riskTone(f.risk_score)}`}>{num(f.risk_score)}</Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>

      <div className="flex flex-wrap gap-2">
        <Button onClick={() => window.location.assign(api.exportUrl(id, "json"))}>Download JSON</Button>
        <Button onClick={() => window.location.assign(api.exportUrl(id, "sarif"))}>Download SARIF</Button>
        <Button onClick={() => window.location.assign(api.exportUrl(id, "html"))}>Download HTML</Button>
      </div>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/60 pb-1.5">
      <span className="text-muted">{label}</span>
      <span className="num font-medium">{value}</span>
    </div>
  );
}
