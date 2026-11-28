import { ChevronDown, Loader2, RefreshCw, TriangleAlert, X } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { api, ApiError, type IntelSyncHistoryRow, type IntelSyncSource } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { formatBytes, formatDate, relativeTime } from "../lib/format";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Banner } from "./ui/Feedback";
import { InfoTooltip } from "./ui/InfoTooltip";
import { Table, TableWrap, Td, Th, Tr } from "./ui/Table";
import { Select } from "./ui/Field";
import { useToast } from "./ui/Toast";
import { cn } from "../lib/cn";

// Adaptive polling: fast while anything is running, slow otherwise. No
// fabricated numbers anywhere — every value comes from the backend registry.
const ACTIVE_POLL_MS = 1500;
const IDLE_POLL_MS = 30000;

type Tone = "ok" | "active" | "warn" | "bad" | "muted";

function statusTone(s: IntelSyncSource): Tone {
  switch (s.status) {
    case "up_to_date":
      return s.freshness === "stale" ? "warn" : "ok";
    case "failed":
    case "cancelled":
      return "bad";
    case "not_initialized":
      return "muted";
    default:
      return "active";
  }
}

function statusLabel(s: IntelSyncSource): string {
  switch (s.status) {
    case "up_to_date":
      return s.freshness === "stale" ? "stale" : "up to date";
    case "not_initialized":
      return "not initialized";
    default:
      return s.status.replace(/_/g, " ");
  }
}

function toneClasses(tone: Tone) {
  switch (tone) {
    case "ok":
      return "border-low/30 bg-low-soft text-low";
    case "active":
      return "border-accent/30 bg-accent-soft text-accent";
    case "warn":
      return "border-high/30 bg-high-soft text-high";
    case "bad":
      return "border-critical/30 bg-critical-soft text-critical";
    default:
      return "border-border bg-surface-2 text-muted";
  }
}

function SourceCard({ s, onSync, onCancel, running }: { s: IntelSyncSource; onSync: (id: string) => void; onCancel: (id: string) => void; running: boolean }) {
  const [open, setOpen] = useState(false);
  const tone = statusTone(s);
  const active = running;
  const pct = s.percent >= 0 ? s.percent : null;

  return (
    <div className="rounded-md border border-border">
      <div className="flex flex-wrap items-center gap-3 px-3 py-2.5">
        <div className="min-w-0 flex-1">
          <p className="flex items-center gap-1.5 text-sm font-semibold">
            {s.name}
            <InfoTooltip label={`About ${s.name}`}>
              {s.description} Needed for: {s.depends_on}.
              {s.freshness === "stale"
                ? " The active dataset is older than its freshness threshold; recent vulnerabilities may be missing until the next successful sync."
                : ""}
            </InfoTooltip>
          </p>
          <p className="truncate text-xs text-muted">{s.description}</p>
        </div>
        <div className="flex items-center gap-2">
          <Badge className={toneClasses(tone)}>{statusLabel(s)}</Badge>
          {active ? (
            <Button size="sm" variant="ghost" onClick={() => onCancel(s.source)}>
              <X className="h-3.5 w-3.5" aria-hidden="true" /> Cancel
            </Button>
          ) : (
            <Button size="sm" variant="secondary" onClick={() => onSync(s.source)}>
              <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" /> Sync now
            </Button>
          )}
          <button
            type="button"
            className="text-xs text-muted underline-offset-2 hover:underline"
            onClick={() => setOpen((v) => !v)}
            aria-expanded={open}
          >
            <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-180")} aria-hidden="true" />
          </button>
        </div>
      </div>

      {active ? (
        <div className="border-t border-border px-3 py-2">
          <div className="flex items-center justify-between text-xs text-muted">
            <span className="flex items-center gap-1.5">
              <Loader2 className="h-3 w-3 animate-spin" aria-hidden="true" />
              {s.stage || "working"}
            </span>
            {pct !== null ? <span className="num">{pct}%</span> : null}
          </div>
          {pct !== null ? (
            <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-surface-2" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100} aria-label={`${s.name} progress`}>
              <div className="h-full rounded-full bg-accent transition-all duration-700" style={{ width: `${pct}%` }} />
            </div>
          ) : (
            <div className="mt-1.5 h-1.5 w-full overflow-hidden rounded-full bg-surface-2" role="progressbar" aria-valuetext="in progress">
              <div className="h-full w-1/3 animate-pulse rounded-full bg-accent" />
            </div>
          )}
          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-0.5 text-xs text-muted">
            {s.bytes > 0 ? <span>{formatBytes(s.bytes)} downloaded{s.expected_bytes > 0 ? ` of ${formatBytes(s.expected_bytes)}` : ""}</span> : null}
            {s.records > 0 ? (
              <span>
                {s.records.toLocaleString()} record{s.records === 1 ? "" : "s"}{s.expected_records > 0 ? ` of ${s.expected_records.toLocaleString()}` : ""} processed
              </span>
            ) : null}
            {s.started_at ? <span>started {relativeTime(s.started_at)}</span> : null}
          </div>
        </div>
      ) : null}

      <div className="flex flex-wrap gap-x-4 gap-y-0.5 border-t border-border/60 px-3 py-1.5 text-xs text-muted">
        {s.last_success ? (
          <span>
            Last successful sync: {formatDate(s.last_success)} ({relativeTime(s.last_success)})
          </span>
        ) : (
          <span>Never successfully synchronized</span>
        )}
        {s.dataset_records > 0 ? <span>{s.dataset_records.toLocaleString()} records available</span> : null}
        {s.freshness === "approaching" ? <span className="text-high">approaching its freshness threshold</span> : null}
        {s.last_error ? <span className="text-critical">last error: {s.last_error}</span> : null}
      </div>

      {open ? (
        <dl className="grid grid-cols-1 gap-1 border-t border-border px-3 py-2 text-xs sm:grid-cols-3">
          <div><dt className="text-subtle">Dataset freshness</dt><dd>{s.freshness.replace(/_/g, " ")}</dd></div>
          <div><dt className="text-subtle">Last attempt</dt><dd>{s.last_attempt ? `${formatDate(s.last_attempt)} (${relativeTime(s.last_attempt)})` : "never"}</dd></div>
          <div><dt className="text-subtle">Next scheduled check</dt><dd>{s.next_scheduled ? relativeTime(s.next_scheduled) : "—"}</dd></div>
          {s.job_id ? <div><dt className="text-subtle">Job</dt><dd className="mono">{s.job_id}</dd></div> : null}
          {s.trigger ? <div><dt className="text-subtle">Trigger</dt><dd>{s.trigger} {s.actor ? `by ${s.actor}` : ""}</dd></div> : null}
          <div><dt className="text-subtle">Used by</dt><dd>{s.depends_on}</dd></div>
        </dl>
      ) : null}
    </div>
  );
}

export default function IntelligenceSync() {
  const { data, error, reload } = useAsync(() => api.intelSync());
  const { push } = useToast();
  const [history, setHistory] = useState<IntelSyncHistoryRow[] | null>(null);
  const [histSource, setHistSource] = useState("all");
  const [histOutcome, setHistOutcome] = useState("all");
  const [historyOpen, setHistoryOpen] = useState(false);

  const running = (data?.running ?? 0) > 0;

  // Adaptive polling: 1.5s while active, 30s when idle. The interval change
  // is the only difference — no duplicated in-flight requests.
  useEffect(() => {
    const ms = running ? ACTIVE_POLL_MS : IDLE_POLL_MS;
    const timer = window.setInterval(() => reload(), ms);
    return () => window.clearInterval(timer);
  }, [running, reload]);

  const loadHistory = useCallback(async () => {
    try {
      const res = await api.intelSyncHistory({
        source: histSource === "all" ? undefined : histSource,
        outcome: histOutcome === "all" ? undefined : histOutcome,
        limit: 50,
      });
      setHistory(res.items);
    } catch {
      setHistory([]);
    }
  }, [histSource, histOutcome]);

  useEffect(() => {
    if (historyOpen && history === null) void loadHistory();
  }, [historyOpen, history, loadHistory]);

  const act = useCallback(
    async (source: string, cancel: boolean) => {
      if (cancel) {
        try {
          await api.intelSyncCancel(source);
          push("Cancellation requested");
        } catch (err) {
          push(err instanceof ApiError ? err.message : String(err), "error");
        }
        reload();
        return;
      }
      try {
        await api.intelSyncStart(source);
        push("Synchronization accepted; progress updates live");
        reload();
      } catch (err) {
        push(err instanceof ApiError ? err.message : String(err), "error");
      }
    },
    [push, reload],
  );

  const sources = data?.sources ?? [];
  const staleNames = sources.filter((s) => s.freshness === "stale" || s.status === "failed").map((s) => s.name);

  const summary = useMemo(() => {
    const counts: Record<string, number> = { ok: 0, active: 0, warn: 0, bad: 0, muted: 0 };
    for (const s of sources) counts[statusTone(s)]++;
    return counts;
  }, [sources]);

  return (
    <div className="space-y-3">
      {error ? <Banner tone="warn" title="Could not load synchronization status">{error.message}</Banner> : null}
      {data && !data.readiness.ready ? (
        <Banner tone="warn" title="Intelligence readiness needs attention">
          {data.readiness.notes.map((n) => (
            <div key={n}>{n}</div>
          ))}
        </Banner>
      ) : null}

      <div className="grid grid-cols-2 gap-2 text-sm sm:grid-cols-5">
        <div className="rounded-md border border-border px-3 py-2">
          <p className="text-xs uppercase tracking-wide text-muted">Up to date</p>
          <p className="num text-lg font-semibold text-low">{summary.ok}</p>
        </div>
        <div className="rounded-md border border-border px-3 py-2">
          <p className="text-xs uppercase tracking-wide text-muted">Active</p>
          <p className="num text-lg font-semibold text-accent">{summary.active}</p>
        </div>
        <div className="rounded-md border border-border px-3 py-2">
          <p className="text-xs uppercase tracking-wide text-muted">Needs attention</p>
          <p className="num text-lg font-semibold text-high">{summary.warn}</p>
        </div>
        <div className="rounded-md border border-border px-3 py-2">
          <p className="text-xs uppercase tracking-wide text-muted">Failed</p>
          <p className="num text-lg font-semibold text-critical">{summary.bad}</p>
        </div>
        <div className="rounded-md border border-border px-3 py-2">
          <p className="text-xs uppercase tracking-wide text-muted">Never synced</p>
          <p className="num text-lg font-semibold text-muted">{data?.never_synced ?? 0}</p>
        </div>
      </div>

      <div className="space-y-2">
        {sources.map((s) => (
          <SourceCard key={s.source} s={s} running={Boolean(s.job_id) && s.status !== "up_to_date" && s.status !== "failed" && s.status !== "cancelled" && s.status !== "not_initialized"} onSync={(id) => void act(id, false)} onCancel={(id) => void act(id, true)} />
        ))}
      </div>

      {staleNames.length > 0 ? (
        <p className="flex items-center gap-1.5 text-xs text-muted">
          <TriangleAlert className="h-3.5 w-3.5 text-high" aria-hidden="true" />
          Stale or failed sources mean recent vulnerabilities may be missing: {staleNames.join(", ")}.
        </p>
      ) : null}

      <div className="rounded-md border border-border">
        <button
          type="button"
          className="flex w-full items-center justify-between gap-2 px-3 py-2.5 text-left text-sm font-semibold"
          aria-expanded={historyOpen}
          onClick={() => setHistoryOpen((v) => !v)}
        >
          <span>Synchronization history</span>
          <ChevronDown className={cn("h-4 w-4 transition-transform", historyOpen && "rotate-180")} aria-hidden="true" />
        </button>
        {historyOpen ? (
          <div className="border-t border-border">
            <div className="flex flex-wrap gap-2 p-3">
              <Select value={histSource} onChange={(e) => { setHistSource(e.target.value); setHistory(null); }} aria-label="Filter history by source">
                <option value="all">All sources</option>
                {sources.map((s) => <option key={s.source} value={s.source}>{s.name}</option>)}
              </Select>
              <Select value={histOutcome} onChange={(e) => { setHistOutcome(e.target.value); setHistory(null); }} aria-label="Filter history by outcome">
                <option value="all">All outcomes</option>
                <option value="ok">Succeeded</option>
                <option value="failed">Failed</option>
                <option value="cancelled">Cancelled</option>
              </Select>
              <Button size="sm" variant="ghost" onClick={() => void loadHistory()}><RefreshCw className="h-3.5 w-3.5" aria-hidden="true" /></Button>
            </div>
            {history === null ? null : history.length === 0 ? (
              <p className="px-3 pb-3 text-sm text-muted">No synchronization attempts match these filters.</p>
            ) : (
              <TableWrap>
                <Table caption="Intelligence synchronization history">
                  <thead>
                    <tr>
                      <Th>Source</Th>
                      <Th>Started</Th>
                      <Th>Outcome</Th>
                      <Th>Records</Th>
                      <Th>Trigger</Th>
                      <Th>Detail</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((h) => (
                      <Tr key={h.seq}>
                        <Td className="mono text-xs">{h.source}</Td>
                        <Td className="text-xs text-muted">{formatDate(h.started_at)}</Td>
                        <Td>
                          <Badge className={h.status === "ok" ? "border-low/30 bg-low-soft text-low" : h.status === "failed" ? "border-critical/30 bg-critical-soft text-critical" : "border-border bg-surface-2 text-muted"}>
                            {h.status}
                          </Badge>
                        </Td>
                        <Td className="num text-xs text-muted">
                          {h.imported > 0 || h.updated > 0 ? `${h.imported.toLocaleString()} added, ${h.updated.toLocaleString()} updated` : h.total_seen > 0 ? h.total_seen.toLocaleString() : "—"}
                        </Td>
                        <Td className="text-xs text-muted">{h.trigger || "—"}{h.actor ? ` · ${h.actor}` : ""}</Td>
                        <Td className="max-w-[20rem] truncate text-xs text-muted" title={h.detail}>{h.detail || "—"}</Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              </TableWrap>
            )}
          </div>
        ) : null}
      </div>
      <p className="text-xs text-muted">
        Status refreshes automatically ({running ? "1.5s while active" : "30s when idle"}). Progress values come from the synchronization
        itself — nothing here is estimated.
      </p>
    </div>
  );
}
