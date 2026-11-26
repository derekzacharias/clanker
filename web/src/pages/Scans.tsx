import { Radar } from "lucide-react";
import { useState } from "react";
import Reports from "./Reports";
import { api } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { navigate, useQueryParam } from "../lib/router";
import { formatDate, relativeTime } from "../lib/format";
import { PageHeader } from "../components/PageHeader";
import { Card, CardHeader } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";

const statusTone: Record<string, string> = {
  completed: "border-low/30 bg-low-soft text-low",
  running: "border-accent/30 bg-accent-soft text-accent",
  queued: "border-border bg-surface-2 text-muted",
  failed: "border-critical/30 bg-critical-soft text-critical",
  canceled: "border-high/30 bg-high-soft text-high",
};

export default function Scans({ initialTab = "activity" }: { initialTab?: "activity" | "reports" }) {
  const { data, error, loading, reload } = useAsync(() => api.scans());
  const tabParam = useQueryParam("tab");
  const [tab, setTab] = useState<"activity" | "reports">(tabParam === "reports" ? "reports" : initialTab);

  return (
    <div className="space-y-4">
      <PageHeader
        title="Scans"
        description="Start an assessment, follow its progress, and open what it produced."
        help={`A scan reads the software installed on a system, then compares what it finds against vulnerability information. Nothing is changed on the system being scanned. Results are kept as reports, so you can compare what changed between two scans.`}
        actions={
          <Button variant="primary" onClick={() => navigate("/scans/new")}>
            <Radar className="h-4 w-4" aria-hidden="true" /> New scan
          </Button>
        }
      />

      <div className="flex gap-1 border-b border-border" role="tablist" aria-label="Scan views">
        {[
          ["activity", "Activity"],
          ["reports", "Reports and exports"],
        ].map(([value, label]) => (
          <button
            key={value}
            role="tab"
            aria-selected={tab === value}
            onClick={() => setTab(value as typeof tab)}
            className={`-mb-px border-b-2 px-3 py-2 text-sm ${
              tab === value ? "border-accent font-medium text-accent" : "border-transparent text-muted hover:text-fg"
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {loading && !data ? <LoadingBlock label="Loading scans" /> : null}
      {error ? <ErrorState message={error.message} onRetry={reload} /> : null}

      {tab === "reports" ? <Reports embedded /> : null}

      {tab === "activity" && data ? (
        <>
          <Card>
            <CardHeader
              title="Recent jobs"
              description="Jobs started from the web interface. Progress is reported by the scanner."
              actions={data.active > 0 ? <Badge className="border-accent/30 bg-accent-soft text-accent">{data.active} running</Badge> : null}
            />
            {(data.jobs ?? []).length === 0 ? (
              <EmptyState
                title="No scans started from the interface"
                description="Assessments run from the CLI still appear below in the report history."
                action={
                  <Button variant="primary" onClick={() => navigate("/scans/new")}>
                    Start a scan
                  </Button>
                }
              />
            ) : (
              <TableWrap>
                <Table caption="Scan jobs">
                  <thead>
                    <tr>
                      <Th>Job</Th>
                      <Th>Status</Th>
                      <Th>Stage</Th>
                      <Th>Started</Th>
                      <Th />
                    </tr>
                  </thead>
                  <tbody>
                    {(data.jobs ?? []).map((j) => (
                      <Tr key={j.id}>
                        <Td>
                          <span className="mono text-xs">{j.id}</span>
                          <div className="text-xs text-muted">{j.kind}</div>
                        </Td>
                        <Td>
                          <Badge className={statusTone[j.status] ?? ""}>{j.status}</Badge>
                          {j.error ? <div className="mt-1 max-w-sm text-xs text-critical">{j.error}</div> : null}
                        </Td>
                        <Td className="text-xs text-muted">
                          {j.stage ?? "—"}
                          {j.stage_detail ? <div>{j.stage_detail}</div> : null}
                          {j.status === "running" ? (
                            <div className="mt-1 h-1.5 w-32 overflow-hidden rounded-full bg-surface-3">
                              <div className="h-full bg-accent" style={{ width: `${j.percent}%` }} />
                            </div>
                          ) : null}
                        </Td>
                        <Td className="text-xs" title={formatDate(j.started_at)}>
                          {relativeTime(j.started_at)}
                        </Td>
                        <Td className="text-right">
                          {j.report_id ? (
                            <Button size="sm" variant="ghost" onClick={() => navigate(`/reports/${encodeURIComponent(j.report_id!)}`)}>
                              Open report
                            </Button>
                          ) : null}
                        </Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              </TableWrap>
            )}
          </Card>

          <Card>
            <CardHeader title="Assessment history" description="Stored reports on this host" />
            {(data.runs ?? []).length === 0 ? (
              <EmptyState title="No assessments yet" description="Run your first scan to create a baseline." />
            ) : (
              <TableWrap>
                <Table caption="Assessment history">
                  <thead>
                    <tr>
                      <Th>Report</Th>
                      <Th>Host</Th>
                      <Th className="text-right">Findings</Th>
                      <Th className="text-right">Actionable</Th>
                      <Th className="text-right">KEV</Th>
                      <Th>Finished</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {(data.runs ?? []).map((r) => (
                      <Tr key={r.id}>
                        <Td>
                          <button
                            type="button"
                            className="mono text-xs text-accent underline underline-offset-2"
                            onClick={() => navigate(`/reports/${encodeURIComponent(r.id)}`)}
                          >
                            {r.id}
                          </button>
                        </Td>
                        <Td className="mono text-xs">{r.host}</Td>
                        <Td className="num text-right">{r.findings}</Td>
                        <Td className="num text-right font-medium">{r.actionable}</Td>
                        <Td className="num text-right">{r.kev_count}</Td>
                        <Td className="text-xs" title={formatDate(r.finished_at)}>
                          {relativeTime(r.finished_at)}
                        </Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              </TableWrap>
            )}
          </Card>
        </>
      ) : null}
    </div>
  );
}
