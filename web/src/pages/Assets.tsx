import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { Link } from "../lib/router";
import { formatDate, isStale, relativeTime } from "../lib/format";
import { PageHeader } from "../components/PageHeader";
import { Card } from "../components/ui/Card";
import { EmptyState, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Input, Select } from "../components/ui/Field";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { Badge } from "../components/ui/Badge";

export default function Assets() {
  const { data, error, loading, reload } = useAsync(() => api.assets());
  const [query, setQuery] = useState("");
  const [osFilter, setOsFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [scanAge, setScanAge] = useState("all");

  const items = data?.items ?? [];
  const osOptions = useMemo(() => Array.from(new Set(items.map((a) => a.os).filter(Boolean))).sort(), [items]);

  const filtered = items.filter((a) => {
    if (query && !`${a.host} ${a.os} ${a.os_version}`.toLowerCase().includes(query.toLowerCase())) return false;
    if (osFilter !== "all" && a.os !== osFilter) return false;
    if (severityFilter === "critical" && a.critical === 0) return false;
    if (severityFilter === "high" && a.high === 0) return false;
    if (severityFilter === "kev" && a.kev === 0) return false;
    if (scanAge === "stale" && !a.stale) return false;
    if (scanAge === "recent" && a.stale) return false;
    return true;
  });

  if (loading && !data) return <LoadingBlock label="Loading assets" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;

  return (
    <div>
      <PageHeader
        title="Assets"
        description="Every endpoint with a completed assessment. Counts reflect the latest scan for that host."
      />

      <Card>
        <div className="flex flex-wrap items-end gap-2 border-b border-border p-3">
          <div className="min-w-[14rem] flex-1">
            <label htmlFor="asset-search" className="sr-only">
              Search assets by hostname or operating system
            </label>
            <div className="relative">
              <Search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-subtle" aria-hidden="true" />
              <Input
                id="asset-search"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="Filter by host or OS…"
                className="pl-8"
              />
            </div>
          </div>
          <div>
            <label htmlFor="os-filter" className="sr-only">
              Filter by operating system
            </label>
            <Select id="os-filter" value={osFilter} onChange={(e) => setOsFilter(e.target.value)}>
              <option value="all">All operating systems</option>
              {osOptions.map((os) => (
                <option key={os} value={os}>
                  {os}
                </option>
              ))}
            </Select>
          </div>
          <div>
            <label htmlFor="sev-filter" className="sr-only">
              Filter by findings
            </label>
            <Select id="sev-filter" value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
              <option value="all">Any findings</option>
              <option value="critical">Has critical</option>
              <option value="high">Has high</option>
              <option value="kev">Has known exploited</option>
            </Select>
          </div>
          <div>
            <label htmlFor="age-filter" className="sr-only">
              Filter by last scan
            </label>
            <Select id="age-filter" value={scanAge} onChange={(e) => setScanAge(e.target.value)}>
              <option value="all">Any scan date</option>
              <option value="recent">Scanned in last 7 days</option>
              <option value="stale">Not scanned in 7 days</option>
            </Select>
          </div>
        </div>

        {filtered.length === 0 ? (
          <EmptyState
            title={items.length === 0 ? "No assets assessed yet" : "No assets match these filters"}
            description={
              items.length === 0
                ? "Assets appear here after a completed assessment. Run a scan to create the first one."
                : "Clear the filters to see every assessed asset."
            }
          />
        ) : (
          <TableWrap>
            <Table caption="Assessed assets">
              <thead>
                <tr>
                  <Th>Asset</Th>
                  <Th>Operating system</Th>
                  <Th className="text-right">Packages</Th>
                  <Th className="text-right">Findings</Th>
                  <Th>Last scan</Th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((a) => (
                  <Tr key={a.host}>
                    <Td>
                      <Link to={`/assets/${encodeURIComponent(a.host)}`} className="font-medium text-accent underline underline-offset-2">
                        {a.host}
                      </Link>
                      <div className="text-xs text-muted">
                        {a.mode} scan
                        {a.agent_version ? ` · agent ${a.agent_version}` : a.scan_tool ? ` · scanned by ${a.scan_tool}` : ""}
                        {a.agent_outdated ? (
                          <span
                            className="ml-1 text-high"
                            title={`The last report came from build ${a.scan_tool}, but the agent is running ${a.agent_version}. Scan again to use the current build.`}
                          >
                            · rescan needed
                          </span>
                        ) : null}
                      </div>
                    </Td>
                    <Td>
                      <span>{a.os}</span>
                      <div className="mono text-xs text-muted">{a.os_version}{a.arch ? ` · ${a.arch}` : ""}</div>
                    </Td>
                    <Td className="num text-right">{a.packages}</Td>
                    <Td className="text-right">
                      <span className="num font-medium">{a.actionable}</span>
                      <span className="text-xs text-muted"> / {a.findings}</span>
                      <div className="mt-1 flex justify-end gap-1">
                        {a.critical > 0 ? <Badge className="border-critical/30 bg-critical-soft text-critical">{a.critical} critical</Badge> : null}
                        {a.high > 0 ? <Badge className="border-high/30 bg-high-soft text-high">{a.high} high</Badge> : null}
                        {a.kev > 0 ? <Badge className="border-critical/40 bg-critical-soft text-critical">KEV</Badge> : null}
                      </div>
                    </Td>
                    <Td>
                      <span title={formatDate(a.last_scan)}>{relativeTime(a.last_scan)}</span>
                      {a.stale || isStale(a.last_scan) ? (
                        <div>
                          <Badge className="mt-1 border-high/30 bg-high-soft text-high">Stale</Badge>
                        </div>
                      ) : null}
                    </Td>
                  </Tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
      </Card>
    </div>
  );
}
