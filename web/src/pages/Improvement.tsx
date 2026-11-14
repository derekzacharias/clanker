import { ArrowRight, Check, FlaskConical, RotateCcw, ShieldAlert, X } from "lucide-react";
import { useState } from "react";
import {
  api,
  ApiError,
  type CaseResult,
  type Evaluation,
  type ImprovementEvent,
  type ImprovementStatus,
  type QualityResponse,
} from "../lib/api";
import { useAsync } from "../lib/useApi";
import { Link } from "../lib/router";
import { formatDate, relativeTime } from "../lib/format";
import { Card, CardHeader } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Banner, EmptyState, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Drawer, Modal } from "../components/ui/Dialog";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { useToast } from "../components/ui/Toast";
import { cn } from "../lib/cn";

const STATUS_TONE: Record<string, string> = {
  discovered: "border-border bg-surface-2 text-muted",
  researching: "border-border bg-surface-2 text-muted",
  proposed: "border-accent/30 bg-accent-soft text-accent",
  testing: "border-accent/30 bg-accent-soft text-accent",
  awaiting_approval: "border-high/40 bg-high-soft text-high",
  approved: "border-low/40 bg-low-soft text-low",
  deployed: "border-low/40 bg-low-soft text-low",
  monitoring: "border-low/30 bg-low-soft text-low",
  rolled_back: "border-high/30 bg-high-soft text-high",
  rejected: "border-critical/30 bg-critical-soft text-critical",
};

const RISK_TONE: Record<string, string> = {
  low: "border-low/30 bg-low-soft text-low",
  medium: "border-medium/30 bg-medium-soft text-medium",
  high: "border-critical/30 bg-critical-soft text-critical",
};

export default function Improvement() {
  const { data: improvements, error, loading, reload } = useAsync(() => api.improvements());
  const { data: quality, reload: reloadQuality } = useAsync(() => api.quality());
  const [openId, setOpenId] = useState<string | null>(null);
  const [rejectId, setRejectId] = useState<string | null>(null);
  const [rejectNote, setRejectNote] = useState("");
  const { push } = useToast();

  function refresh() {
    reload();
    reloadQuality();
  }

  async function act(id: string, to: ImprovementStatus, note?: string) {
    const actor = localStorage.getItem("clanker-guard.analyst") || "web-ui";
    try {
      await api.transitionImprovement(id, { to, actor, note });
      push(`Improvement ${to.replace(/_/g, " ")}`);
      refresh();
    } catch (err) {
      push(err instanceof ApiError ? err.message : String(err), "error");
    }
  }

  if (loading && !improvements) return <LoadingBlock label="Loading improvement proposals" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;

  const items = improvements?.items ?? [];

  return (
    <div className="space-y-3">
      <Banner tone="info" title="How this loop works">
        Analysts review findings; reviews that advisory evidence supports change <em>that finding</em> and, when a pattern
        repeats, generate a proposal. A proposal is a versioned detection policy tested against fixtures. Nothing is
        deployed without an explicit approval, and every deployment can be rolled back.
      </Banner>

      <QualityCards quality={quality} />

      <Card>
        <CardHeader
          title="Improvement proposals"
          description="Each proposal lists the findings behind it, its test results and its current lifecycle state."
          actions={
            <Button
              size="sm"
              onClick={async () => {
                try {
                  const res = await api.improvements();
                  push(`${res.items.length} proposal(s)`);
                  refresh();
                } catch (err) {
                  push(err instanceof Error ? err.message : String(err), "error");
                }
              }}
            >
              Refresh
            </Button>
          }
        />
        {items.length === 0 ? (
          <EmptyState
            icon={<ShieldAlert className="h-5 w-5" />}
            title="No improvement proposals yet"
            description={
              <>
                Mark a finding as a false positive with a reason on the{" "}
                <Link to="/vulnerabilities" className="text-accent underline underline-offset-2">
                  Vulnerabilities
                </Link>{" "}
                page. When advisory evidence supports the review, a proposal appears here with generated test fixtures.
              </>
            }
          />
        ) : (
          <ul className="divide-y divide-border">
            {items.map((imp) => (
              <li key={imp.id} className="p-4">
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge className={STATUS_TONE[imp.status]}>{imp.status.replace(/_/g, " ")}</Badge>
                      <Badge className="border-border bg-surface-2 text-muted">{imp.category.replace(/_/g, " ")}</Badge>
                      <Badge className={RISK_TONE[imp.risk_level]}>risk: {imp.risk_level}</Badge>
                      <span className="mono text-xs text-muted">{imp.id}</span>
                    </div>
                    <h3 className="mt-1.5 text-sm font-semibold">{imp.title}</h3>
                    <p className="mt-0.5 line-clamp-2 max-w-3xl text-sm text-muted">{imp.problem}</p>
                    <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
                      <span>{imp.affected_findings.length} affected finding(s)</span>
                      {imp.evaluation ? (
                        <span className={imp.evaluation.passed ? "text-low" : "text-critical"}>
                          tests {imp.evaluation.passed ? "passed" : "failed"} · {imp.evaluation.cases.length} fixtures ·{" "}
                          {imp.evaluation.fixed_cases?.length ?? 0} corrected
                        </span>
                      ) : (
                        <span>no tests yet</span>
                      )}
                      <span>updated {relativeTime(imp.updated_at)}</span>
                    </div>
                  </div>
                  <div className="flex shrink-0 flex-wrap gap-1.5">
                    <Button size="sm" onClick={() => setOpenId(imp.id)}>
                      View changes
                    </Button>
                    {imp.status === "awaiting_approval" ? (
                      <>
                        <Button size="sm" variant="primary" onClick={() => act(imp.id, "approved", "approved from web UI")}>
                          <Check className="h-3.5 w-3.5" aria-hidden="true" /> Approve
                        </Button>
                        <Button
                          size="sm"
                          variant="danger"
                          onClick={() => {
                            setRejectNote("");
                            setRejectId(imp.id);
                          }}
                        >
                          <X className="h-3.5 w-3.5" aria-hidden="true" /> Reject
                        </Button>
                      </>
                    ) : null}
                    {imp.status === "approved" ? (
                      <Button size="sm" variant="primary" onClick={() => act(imp.id, "deployed", "deployed from web UI")}>
                        <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" /> Deploy
                      </Button>
                    ) : null}
                    {imp.status === "deployed" || imp.status === "monitoring" ? (
                      <Button size="sm" onClick={() => act(imp.id, "rolled_back", "rolled back from web UI")}>
                        <RotateCcw className="h-3.5 w-3.5" aria-hidden="true" /> Roll back
                      </Button>
                    ) : null}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <RecentFeedback quality={quality} />

      <Modal
        open={Boolean(rejectId)}
        onOpenChange={(open) => {
          if (!open) setRejectId(null);
        }}
        title="Reject this proposal"
        description="A reason is required and is recorded in the audit trail with your name."
        footer={
          <>
            <Button variant="ghost" onClick={() => setRejectId(null)}>
              Cancel
            </Button>
            <Button
              variant="danger"
              disabled={!rejectNote.trim()}
              onClick={async () => {
                if (!rejectId) return;
                await act(rejectId, "rejected", rejectNote.trim());
                setRejectId(null);
              }}
            >
              Reject proposal
            </Button>
          </>
        }
      >
        <label htmlFor="reject-reason" className="block text-xs font-medium text-muted">
          Reason
        </label>
        <textarea
          id="reject-reason"
          value={rejectNote}
          onChange={(e) => setRejectNote(e.target.value)}
          rows={3}
          autoFocus
          placeholder="Why is this proposal not acceptable?"
          className="mt-1 w-full rounded-md border border-border-strong bg-surface px-2.5 py-1.5 text-sm"
        />
      </Modal>

      <ImprovementDrawer
        id={openId}
        onClose={() => setOpenId(null)}
        onChanged={refresh}
        onAct={act}
      />
    </div>
  );
}

function QualityCards({ quality }: { quality: QualityResponse | null }) {
  if (!quality) return null;
  const m = quality.metrics;
  const counts = quality.improvement_counts ?? {};
  return (
    <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
      <Card className="p-4">
        <p className="text-xs uppercase tracking-wide text-muted">Reviewed findings</p>
        <p className="num mt-1 text-2xl font-semibold">{m.reviewed}</p>
        <p className="text-xs text-muted">
          {m.reviewed_rate !== null ? `${(m.reviewed_rate * 100).toFixed(1)}% of ${m.findings_considered} findings` : "of no findings yet"}
        </p>
      </Card>
      <Card className="p-4">
        <p className="text-xs uppercase tracking-wide text-muted">Documented false positives</p>
        <p className="num mt-1 text-2xl font-semibold">{m.false_positives}</p>
        <p className="text-xs text-muted">
          {m.false_positive_rate !== null
            ? `${(m.false_positive_rate * 100).toFixed(0)}% of reviewed findings`
            : "no reviews yet — no rate can be computed"}
        </p>
      </Card>
      <Card className="p-4">
        <p className="text-xs uppercase tracking-wide text-muted">Verification outcomes</p>
        <p className="mt-1 text-sm">
          <span className="text-low">{m.verification_supported} supported</span> ·{" "}
          <span className="text-critical">{m.verification_contradicted} contradicted</span> ·{" "}
          <span className="text-high">{m.verification_inconclusive} inconclusive</span>
        </p>
        <p className="mt-1 text-xs text-muted">Only supported reviews change a classification.</p>
      </Card>
      <Card className="p-4">
        <p className="text-xs uppercase tracking-wide text-muted">Improvements</p>
        <p className="mt-1 text-sm">
          {m.open_improvements} open · {m.deployed_improvements} deployed · {m.rejected_improvements} rejected
        </p>
        <p className="mt-1 text-xs text-muted">
          awaiting review: {(counts["awaiting_approval"] ?? 0) + (counts["proposed"] ?? 0) + (counts["testing"] ?? 0)}
        </p>
      </Card>
      {m.notes && m.notes.length > 0 ? (
        <div className="sm:col-span-2 xl:col-span-4">
          <Banner tone="info" title="Measurement caveats">
            <ul className="list-disc pl-4">
              {m.notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </Banner>
        </div>
      ) : null}
    </div>
  );
}

function RecentFeedback({ quality }: { quality: QualityResponse | null }) {
  const rows = quality?.recent_feedback ?? [];
  if (rows.length === 0) return null;
  return (
    <Card>
      <CardHeader title="Recent reviews" description="Newest analyst reviews and whether evidence supported them" />
      <TableWrap>
        <Table caption="Recent analyst reviews">
          <thead>
            <tr>
              <Th>CVE</Th>
              <Th>Product</Th>
              <Th>Verdict</Th>
              <Th>Reason</Th>
              <Th>Verification</Th>
              <Th>Analyst</Th>
              <Th>When</Th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <Tr key={`${r.finding_id}-${r.created_at}`}>
                <Td className="mono text-xs">{r.cve}</Td>
                <Td>{r.product}</Td>
                <Td>{r.verdict.replace(/_/g, " ")}</Td>
                <Td className="text-xs text-muted">{r.reason?.replace(/_/g, " ") ?? "—"}</Td>
                <Td>
                  {r.supported === undefined ? (
                    <span className="text-xs text-muted">—</span>
                  ) : r.supported ? (
                    <Badge className="border-low/30 bg-low-soft text-low">supported</Badge>
                  ) : (
                    <Badge className="border-high/30 bg-high-soft text-high">not supported</Badge>
                  )}
                </Td>
                <Td className="text-xs">{r.analyst}</Td>
                <Td className="text-xs text-muted">{relativeTime(r.created_at)}</Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      </TableWrap>
    </Card>
  );
}

function ImprovementDrawer({
  id,
  onClose,
  onChanged,
  onAct,
}: {
  id: string | null;
  onClose: () => void;
  onChanged: () => void;
  onAct: (id: string, to: ImprovementStatus, note?: string) => Promise<void>;
}) {
  const { data, error, loading, reload } = useAsync(
    () => (id ? api.improvement(id) : Promise.resolve(null)),
    [id],
  );
  const { push } = useToast();

  async function runTests() {
    if (!id) return;
    try {
      await api.evaluateImprovement(id);
      push("Fixture suite re-run");
      reload();
      onChanged();
    } catch (err) {
      push(err instanceof ApiError ? err.message : String(err), "error");
    }
  }

  const imp = data?.improvement;
  return (
    <Drawer
      open={Boolean(id)}
      onOpenChange={(open) => {
        if (!open) onClose();
      }}
      width="lg"
      title={imp ? imp.id : "Improvement"}
      description={imp ? `${imp.status.replace(/_/g, " ")} · ${imp.category.replace(/_/g, " ")}` : undefined}
      footer={
        imp ? (
          <div className="flex flex-wrap items-center gap-2">
            <Button size="sm" onClick={runTests} disabled={!imp.policy}>
              <FlaskConical className="h-3.5 w-3.5" aria-hidden="true" /> Run tests
            </Button>
            {imp.status === "awaiting_approval" ? (
              <Button size="sm" variant="primary" onClick={() => onAct(imp.id, "approved", "approved")}>
                Approve
              </Button>
            ) : null}
            {imp.status === "approved" ? (
              <Button size="sm" variant="primary" onClick={() => onAct(imp.id, "deployed", "deployed")}>
                Deploy
              </Button>
            ) : null}
            {imp.status === "deployed" || imp.status === "monitoring" ? (
              <Button size="sm" onClick={() => onAct(imp.id, "rolled_back", "rolled back")}>
                Roll back
              </Button>
            ) : null}
            <span className="ml-auto text-xs text-muted">
              {data?.active?.rule_id ? `active rule ${data.active.rule_id}` : "no active rule"}
            </span>
          </div>
        ) : null
      }
    >
      {loading && !imp ? <LoadingBlock label="Loading proposal" /> : null}
      {error ? <ErrorState message={error.message} /> : null}
      {imp ? (
        <div className="space-y-5">
          <div className="flex flex-wrap gap-1.5">
            <Badge className={STATUS_TONE[imp.status]}>{imp.status.replace(/_/g, " ")}</Badge>
            <Badge className={RISK_TONE[imp.risk_level]}>risk: {imp.risk_level}</Badge>
            {imp.rule_id ? <Badge className="border-border bg-surface-2 text-muted">rule {imp.rule_id}</Badge> : null}
          </div>

          <Block title="Problem">{imp.problem}</Block>
          <Block title="Proposed change">{imp.proposed_change}</Block>
          <Block title="Expected benefit">{imp.expected_benefit}</Block>

          {imp.policy_notes && imp.policy_notes.length > 0 ? (
            <Block title="Detection policy change">
              <ul className="list-disc pl-4">
                {imp.policy_notes.map((n) => (
                  <li key={n} className="mono text-xs">
                    {n}
                  </li>
                ))}
              </ul>
            </Block>
          ) : (
            <Block title="Detection policy change">
              No automated rule change is defined, so this proposal cannot be tested or deployed. It is recorded for research.
            </Block>
          )}

          {(imp.evidence ?? []).length > 0 ? (
            <section>
              <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Supporting evidence</h3>
              <ul className="space-y-1.5">
                {(imp.evidence ?? []).map((e, i) => (
                  <li key={i} className="rounded border border-border bg-surface-2 p-2 text-sm">
                    <span className="mono text-xs text-muted">{e.kind}</span>
                    {e.source ? <span className="ml-2 text-xs text-muted">{e.source}</span> : null}
                    <p className="mt-0.5">{e.detail}</p>
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {imp.evaluation ? <EvaluationView evaluation={imp.evaluation} /> : null}

          <section>
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Lifecycle</h3>
            <ol className="space-y-1 text-sm">
              {(data?.events ?? []).map((ev: ImprovementEvent) => (
                <li key={ev.id} className="flex flex-wrap gap-2">
                  <span className="text-muted">{formatDate(ev.created_at)}</span>
                  <span>
                    {ev.from} → <span className="font-medium">{ev.to}</span>
                  </span>
                  <span className="text-muted">by {ev.actor}</span>
                  {ev.note ? <span className="text-muted">— {ev.note}</span> : null}
                </li>
              ))}
            </ol>
          </section>

          <section>
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-muted">Affected findings</h3>
            <ul className="flex flex-wrap gap-1.5">
              {(imp.affected_findings ?? []).map((fid) => (
                <li key={fid} className="mono rounded border border-border px-1.5 py-0.5 text-xs text-muted">
                  {fid}
                </li>
              ))}
            </ul>
          </section>

          {imp.rejected_reason ? (
            <Banner tone="danger" title="Rejection reason">
              {imp.rejected_reason}
            </Banner>
          ) : null}
        </div>
      ) : null}
    </Drawer>
  );
}

function EvaluationView({ evaluation }: { evaluation: Evaluation }) {
  return (
    <section>
      <h3 className="mb-1.5 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-muted">
        Fixture suite
        <Badge className={evaluation.passed ? "border-low/30 bg-low-soft text-low" : "border-critical/30 bg-critical-soft text-critical"}>
          {evaluation.passed ? "passed" : "failed"}
        </Badge>
      </h3>
      <p className="mb-2 text-xs text-muted">
        Baseline precision {(evaluation.baseline.precision * 100).toFixed(0)}% / recall{" "}
        {(evaluation.baseline.recall * 100).toFixed(0)}% → candidate precision{" "}
        {(evaluation.candidate.precision * 100).toFixed(0)}% / recall{" "}
        {(evaluation.candidate.recall * 100).toFixed(0)}%. Detection of vulnerable builds must not drop.
      </p>
      <TableWrap>
        <Table caption="Fixture results">
          <thead>
            <tr>
              <Th>Fixture</Th>
              <Th>Ground truth</Th>
              <Th>Baseline</Th>
              <Th>Candidate</Th>
              <Th>Result</Th>
            </tr>
          </thead>
          <tbody>
            {(evaluation.cases ?? []).map((c: CaseResult) => (
              <Tr key={c.fixture}>
                <Td className="mono text-xs">{c.fixture}</Td>
                <Td className="text-xs">{c.label}</Td>
                <Td className="mono text-xs text-muted">{c.baseline}</Td>
                <Td className={cn("mono text-xs", c.pass ? "text-fg" : "text-critical")}>{c.candidate}</Td>
                <Td>
                  {c.pass ? (
                    <Badge className="border-low/30 bg-low-soft text-low">pass</Badge>
                  ) : (
                    <Badge className="border-critical/30 bg-critical-soft text-critical">fail</Badge>
                  )}
                  {c.note ? <div className="mt-0.5 text-[0.6875rem] text-muted">{c.note}</div> : null}
                </Td>
              </Tr>
            ))}
          </tbody>
        </Table>
      </TableWrap>
      {evaluation.regressions && evaluation.regressions.length > 0 ? (
        <div className="mt-2">
          <Banner tone="danger" title="Regressions">
            <ul className="list-disc pl-4">
              {evaluation.regressions.map((r) => (
                <li key={r}>{r}</li>
              ))}
            </ul>
          </Banner>
        </div>
      ) : null}
    </section>
  );
}

function Block({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">{title}</h3>
      <p className="text-sm leading-relaxed">{children}</p>
    </section>
  );
}
