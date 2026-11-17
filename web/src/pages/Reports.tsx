import { Download, FileBarChart2 } from "lucide-react";
import { api, downloadReportExport, downloadSoftwareInventory } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { navigate } from "../lib/router";
import { formatDate } from "../lib/format";
import { PageHeader } from "../components/PageHeader";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { useToast } from "../components/ui/Toast";

const FORMATS = ["json", "markdown", "sarif", "html"] as const;

export default function Reports({ embedded = false }: { embedded?: boolean }) {
  const { data, error, loading, reload } = useAsync(() => api.reports());
  const { push } = useToast();

  return (
    <div className={embedded ? "space-y-3" : undefined}>
      {embedded ? (
        <p className="text-sm text-muted">
          Stored assessments, newest first. Every export preserves evidence, confidence, sources and stated
          limitations.
        </p>
      ) : (
      <PageHeader
        title="Reports"
        description="Stored assessments. Every export preserves evidence, confidence, sources and stated limitations."
        actions={
          <>
            {/* The asset register, not the findings report: one row per installed
                package per host, newest assessment each. */}
            <Button
              onClick={async () => {
                try {
                  const name = await downloadSoftwareInventory({ format: "csv" });
                  push(`Downloaded ${name}`);
                } catch (err) {
                  push(err instanceof Error ? err.message : String(err), "error");
                }
              }}
            >
              <Download className="h-4 w-4" aria-hidden="true" />
              Software inventory (all hosts)
            </Button>
          </>
        }
      />
      )}

      {loading && !data ? <LoadingBlock label="Loading reports" /> : null}
      {error ? <ErrorState message={error.message} onRetry={reload} /> : null}

      {data ? (
        <Card>
          {(data.items ?? []).length === 0 ? (
            <EmptyState
              icon={<FileBarChart2 className="h-5 w-5" />}
              title="No reports yet"
              description="A report is created by every completed assessment."
              action={<Button variant="primary" onClick={() => navigate("/scans/new")}>Run a scan</Button>}
            />
          ) : (
            <TableWrap>
              <Table caption="Stored assessment reports">
                <thead>
                  <tr>
                    <Th>Report</Th>
                    <Th>Host</Th>
                    <Th className="text-right">Findings</Th>
                    <Th className="text-right">KEV</Th>
                    <Th>Completed</Th>
                    <Th>Export</Th>
                  </tr>
                </thead>
                <tbody>
                  {(data.items ?? []).map((r) => (
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
                      <Td className="text-right">
                        <span className="num font-medium">{r.actionable}</span>
                        <span className="text-xs text-muted"> / {r.findings}</span>
                      </Td>
                      <Td className="num text-right">{r.kev_count}</Td>
                      <Td className="text-xs">{formatDate(r.finished_at)}</Td>
                      <Td>
                        <div className="flex flex-wrap gap-1">
                          {FORMATS.map((f) => (
                            <button
                              key={f}
                              type="button"
                              onClick={async () => {
                                try {
                                  await downloadReportExport(r.id, f);
                                } catch (err) {
                                  push(err instanceof Error ? err.message : String(err), "error");
                                }
                              }}
                              className="inline-flex items-center gap-1 rounded border border-border px-1.5 py-0.5 text-[0.6875rem] text-muted hover:bg-surface-2 hover:text-fg"
                            >
                              <Download className="h-3 w-3" aria-hidden="true" />
                              {f}
                            </button>
                          ))}
                        </div>
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}
        </Card>
      ) : null}
    </div>
  );
}
