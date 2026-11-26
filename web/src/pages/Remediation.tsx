import { useMemo, useState } from "react";
import { Timer } from "lucide-react";
import { useAsync } from "../lib/useApi";
import { api, type RemediationGroup, type RemediationItem, type RemediationState } from "../lib/api";
import { PageHeader } from "../components/PageHeader";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Field, Input, Select } from "../components/ui/Field";
import { Modal } from "../components/ui/Dialog";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { useToast } from "../components/ui/Toast";
import { formatDate, relativeTime } from "../lib/format";
import Ownership from "./Ownership";

/**
 * Remediation work queue.
 *
 * The question this page answers is "who owes what, by when" — not "what did the
 * scanner find" (that is Vulnerabilities). Findings are evidence; these rows are the
 * work items derived from them, each with an owner, a state and an SLA deadline.
 *
 * Automated execution does not exist in this build, so the one action that would be
 * unsafe to fake — "remediate" — is absent, and the API reports automation as
 * disabled rather than the UI implying it works.
 */
const ASSIGNABLE_TEAMS = [
  "Infrastructure",
  "Development",
  "DevOps",
  "Platform Engineering",
  "Cloud Engineering",
  "Security",
];

const STATE_LABEL: Record<string, string> = {
  detected: "detected",
  validated: "validated",
  awaiting_ownership: "awaiting owner",
  assigned: "assigned",
  awaiting_approval: "awaiting approval",
  scheduled: "scheduled",
  in_progress: "in progress",
  remediation_applied: "applied",
  pending_verification: "pending verification",
  resolved: "resolved",
  failed: "failed",
  risk_accepted: "risk accepted",
  false_positive: "false positive",
};

function stateTone(state: RemediationState): string {
  switch (state) {
    case "resolved":
      return "border-low/30 bg-low-soft text-low";
    case "failed":
      return "border-critical/30 bg-critical-soft text-critical";
    case "awaiting_ownership":
      return "border-high/30 bg-high-soft text-high";
    case "pending_verification":
      return "border-accent/40 bg-accent-soft text-accent";
    case "risk_accepted":
    case "false_positive":
      return "border-border bg-surface-2 text-muted";
    default:
      return "border-border-strong bg-surface-2 text-fg";
  }
}

function severityTone(severity: string): string {
  switch (severity) {
    case "critical":
      return "border-critical/30 bg-critical-soft text-critical";
    case "high":
      return "border-high/30 bg-high-soft text-high";
    case "medium":
      return "border-medium/30 bg-medium-soft text-medium";
    case "low":
      return "border-low/30 bg-low-soft text-low";
    default:
      return "border-border bg-surface-2 text-muted";
  }
}

export default function Remediation({ initialTab = "queue" }: { initialTab?: "queue" | "upgrades" | "ownership" }) {
  const [team, setTeam] = useState("");
  const [state, setState] = useState("");
  const [overdueOnly, setOverdueOnly] = useState(false);
  // Operators land on their own queue: it is the work they are accountable for. Admins and
  // anyone else start with the whole queue, because triage is their job.
  const access = useAsync(() => api.accessMe());
  const role = access.data?.role ?? "";
  const [mineOnly, setMineOnly] = useState(false);
  const [roleApplied, setRoleApplied] = useState(false);
  if (!roleApplied && access.data) {
    setRoleApplied(true);
    if (role === "operator" && access.data.username) setMineOnly(true);
  }
  const [tab, setTab] = useState<"queue" | "upgrades" | "ownership">(initialTab);
  const grouped = tab === "upgrades";
  const [accepting, setAccepting] = useState<RemediationItem | null>(null);
  const [acceptReason, setAcceptReason] = useState("");
  const [acceptDays, setAcceptDays] = useState(30);
  const [ticketing, setTicketing] = useState<string | null>(null);
  const { push } = useToast();

  const summary = useAsync(() => api.remediationSummary());
  // "Mine" is scoped to the signed-in operator, which is what makes the queue
  // claimable: an engineer can see only the work they took on.
  const session = useAsync(() => api.session());
  const me = session.data?.username ?? "";
  const items = useAsync(
    () =>
      api.remediation({
        team: team || undefined,
        state: state || undefined,
        overdue: overdueOnly || undefined,
        owner: mineOnly && me ? me : undefined,
      }),
    [team, state, overdueOnly, mineOnly, me],
  );

  const groups = useAsync(() => (grouped ? api.remediationGroups() : Promise.resolve(null)), [grouped]);
  const metrics = useAsync(() => api.metrics(), []);

  const s = summary.data?.summary;

  const teams = useMemo(() => {
    const known = new Set<string>(ASSIGNABLE_TEAMS);
    (summary.data?.teams ?? []).forEach((t) => known.add(t));
    return [...known].sort();
  }, [summary.data]);

  // File one ticket for the whole upgrade instead of one per CVE: that is the difference
  // between a thousand tickets and "install KB5127648 once".
  async function fileGroupTicket(g: RemediationGroup) {
    setTicketing(g.key);
    try {
      const res = await api.createGitLabGroupTicket({
        asset: g.asset,
        product: g.product,
        fixed_version: g.fixed_version ?? "",
      });
      push(res.message);
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not file the ticket");
    } finally {
      setTicketing(null);
    }
  }

  async function claim(item: RemediationItem) {
    if (!me) return;
    try {
      await api.updateRemediation(item.id, { owner: me });
      push(`${item.vulnerability_id} assigned to you`);
      items.reload();
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not assign this item to you");
    }
  }

  async function submitAcceptance() {
    if (!accepting) return;
    try {
      const res = await api.acceptRisk(accepting.id, { reason: acceptReason, days: acceptDays });
      push(
        `${accepting.vulnerability_id} accepted by ${res.item.accepted_by} until ${
          res.item.accept_expires_at ? new Date(res.item.accept_expires_at).toLocaleDateString() : `${acceptDays} days`
        }`,
      );
      setAccepting(null);
      setAcceptReason("");
      items.reload();
      summary.reload();
      metrics.reload();
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not record the acceptance");
    }
  }

  async function assign(item: RemediationItem, nextTeam: string) {
    try {
      await api.updateRemediation(item.id, { team: nextTeam });
      push(nextTeam ? `${item.vulnerability_id} assigned to ${nextTeam}` : `${item.vulnerability_id} returned to triage`);
      items.reload();
      summary.reload();
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not assign this item");
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Remediation"
        description="Who owes each fix, by when, and the upgrade that closes it. Findings stay evidence; this is the work."
      />

      <div className="flex gap-1 border-b border-border" role="tablist" aria-label="Remediation views">
        {[
          ["queue", "Queue"],
          ["upgrades", "By upgrade"],
          ["ownership", "Ownership"],
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
            {value === "ownership" && s?.triage_assets ? (
              <span className="ml-1.5 rounded-full bg-high-soft px-1.5 text-xs text-high">{s.triage_assets}</span>
            ) : null}
          </button>
        ))}
      </div>

      {summary.loading && !summary.data ? <LoadingBlock label="Loading remediation summary" /> : null}
      {summary.error ? <ErrorState message={summary.error.message} onRetry={summary.reload} /> : null}

      {s ? (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 xl:grid-cols-5">
          {[
            { label: "Open work", value: s.open, hint: "not resolved" },
            { label: "Unassigned", value: s.unassigned, hint: "in triage" },
            { label: "Overdue", value: s.overdue, hint: "past SLA" },
            { label: "Pending verification", value: s.by_state?.pending_verification ?? 0, hint: "waiting for a rescan" },
            { label: "Resolved", value: s.resolved, hint: "verified" },
          ].map((card) => (
            <Card key={card.label} className="p-4">
              <p className="text-xs font-semibold uppercase tracking-wide text-muted">{card.label}</p>
              <p className="num mt-1 text-2xl font-semibold">{card.value}</p>
              <p className="mt-0.5 text-xs text-subtle">{card.hint}</p>
            </Card>
          ))}
        </div>
      ) : null}

      {metrics.data ? (
        <Card className="p-4">
          <div className="flex flex-wrap items-center gap-2">
            <Timer className="h-4 w-4 text-muted" aria-hidden="true" />
            <p className="text-sm font-medium">Is the programme getting better?</p>
            <span className="ml-auto text-xs text-subtle">from stored evidence, not counters</span>
          </div>
          <div className="mt-3 grid gap-3 sm:grid-cols-2">
            <div>
              <p className="text-xs uppercase tracking-wide text-muted">Age of open work</p>
              <ul className="mt-1 space-y-1 text-sm">
                {(metrics.data.age_buckets ?? []).map((b) => (
                  <li key={b.label} className="flex items-baseline justify-between gap-2">
                    <span className="text-muted">{b.label}</span>
                    <span className="num font-medium">{b.count}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <p className="text-xs uppercase tracking-wide text-muted">Time to fix</p>
              {(metrics.data.time_to_fix ?? []).length === 0 ? (
                <p className="mt-1 text-sm text-muted">
                  Nothing verified yet. This fills in as findings are closed by a later scan.
                </p>
              ) : (
                <ul className="mt-1 space-y-1 text-sm">
                  {(metrics.data.time_to_fix ?? []).map((t) => (
                    <li key={t.severity} className="flex items-baseline justify-between gap-2">
                      <span className="text-muted">
                        {t.severity} <span className="text-subtle">({t.resolved} closed)</span>
                      </span>
                      <span className="num">
                        {t.median_days}d median · {t.p90_days}d p90
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </div>
          <p className="mt-3 text-xs text-subtle">
            {metrics.data.units} remediation units for {metrics.data.findings} open findings ·{" "}
            {metrics.data.acceptances_due} acceptance{metrics.data.acceptances_due === 1 ? "" : "s"} expiring within two weeks ·{" "}
            {metrics.data.reopened} reopened
          </p>
        </Card>
      ) : null}

      {tab === "ownership" ? <Ownership /> : null}

      <Card className={tab === "ownership" ? "hidden" : undefined}>
        <CardHeader
          title={tab === "upgrades" ? "Remediation units" : "Work queue"}
          description="Routed from asset ownership, then the responsibility mapping. Unknown assets wait for a human instead of defaulting to a team — set them in Ownership."
        />
        <CardBody className="space-y-3">
          <div className="flex flex-wrap items-end gap-2">
            <label className="text-xs text-muted">
              <span className="mb-1 block">Team</span>
              <Select value={team} onChange={(e) => setTeam(e.target.value)} aria-label="Filter by team">
                <option value="">All teams</option>
                {teams.map((t) => (
                  <option key={t} value={t}>
                    {t}
                  </option>
                ))}
              </Select>
            </label>
            <label className="text-xs text-muted">
              <span className="mb-1 block">State</span>
              <Select value={state} onChange={(e) => setState(e.target.value)} aria-label="Filter by state">
                <option value="">All states</option>
                {Object.entries(STATE_LABEL).map(([value, label]) => (
                  <option key={value} value={value}>
                    {label}
                  </option>
                ))}
              </Select>
            </label>
            <Button variant={overdueOnly ? "primary" : "secondary"} onClick={() => setOverdueOnly((v) => !v)}>
              {overdueOnly ? "Overdue only" : "Show overdue"}
            </Button>
            {me ? (
              <Button variant={mineOnly ? "primary" : "secondary"} onClick={() => setMineOnly((v) => !v)}>
                My work
              </Button>
            ) : null}

            <Button variant="ghost" onClick={() => { items.reload(); summary.reload(); }}>
              Refresh
            </Button>
          </div>

          {summary.data && !summary.data.automation.enabled ? (
            <p className="text-xs text-muted">
              Automated remediation is not available in this build — {summary.data.automation.reason}. Work here is
              assignment and tracking; execution stays with the owning team.
            </p>
          ) : null}

          {items.loading && !items.data ? <LoadingBlock label="Loading remediation work" /> : null}
          {items.error ? <ErrorState message={items.error.message} onRetry={items.reload} /> : null}

          {items.data && items.data.items.length === 0 ? (
            <EmptyState
              title="No remediation work matches these filters"
              description="Items appear here as soon as an assessment reports an actionable finding."
            />
          ) : null}

          {grouped && groups.data ? (
            groups.data.items.length === 0 ? (
              <EmptyState title="No open work to group" description="Units appear once findings are routed." />
            ) : (
              <TableWrap>
                <Table caption="Remediation units">
                  <thead>
                    <tr>
                      <Th>Upgrade</Th>
                      <Th>Findings</Th>
                      <Th>Worst severity</Th>
                      <Th>Team</Th>
                      <Th>Due</Th>
                      <Th>Ticket</Th>
                    </tr>
                  </thead>
                  <tbody>
                    {groups.data.items.map((g: RemediationGroup) => (
                      <Tr key={g.key}>
                        <Td>
                          <span className="font-medium">{g.product}</span>
                          {g.fixed_version ? (
                            <span className="mono block text-xs text-muted">→ {g.fixed_version}</span>
                          ) : (
                            <span className="block text-xs text-high">no fixed version published</span>
                          )}
                          <span className="mono block text-xs text-subtle">{g.asset}</span>
                        </Td>
                        <Td className="text-xs">
                          <span className="num font-medium">{g.items}</span>
                          <span className="block text-subtle">{g.advisories.slice(0, 3).join(", ")}{g.advisories.length > 3 ? "…" : ""}</span>
                        </Td>
                        <Td>
                          <Badge className={severityTone(g.severity)}>{g.severity}</Badge>
                          <span className="ml-1 text-xs text-subtle">{g.priority}</span>
                        </Td>
                        <Td className="text-xs">{g.team || <span className="text-high">unassigned</span>}</Td>
                        <Td className="text-xs">
                          {g.due_at ? formatDate(g.due_at) : <span className="text-subtle">—</span>}
                          {g.overdue > 0 ? <span className="block text-critical">{g.overdue} overdue</span> : null}
                        </Td>
                        <Td>
                          {g.fixed_version ? (
                            <Button size="sm" variant="ghost" onClick={() => fileGroupTicket(g)} disabled={ticketing === g.key}>
                              {ticketing === g.key ? "Filing…" : "File ticket"}
                            </Button>
                          ) : (
                            <span className="text-xs text-subtle">needs a fixed version</span>
                          )}
                        </Td>
                      </Tr>
                    ))}
                  </tbody>
                </Table>
              </TableWrap>
            )
          ) : null}

          {!grouped && items.data && items.data.items.length > 0 ? (
            <TableWrap>
              <Table caption="Remediation work items">
                <thead>
                  <tr>
                    <Th>Asset</Th>
                    <Th>Finding</Th>
                    <Th>Severity</Th>
                    <Th>Team</Th>
                    <Th>State</Th>
                    <Th>Due</Th>
                    <Th>Assign</Th>
                  </tr>
                </thead>
                <tbody>
                  {items.data.items.map((item) => (
                    <Tr key={item.id}>
                      <Td>
                        <span className="mono text-xs">{item.asset}</span>
                        <span className="block text-xs text-subtle">{item.ecosystem}</span>
                      </Td>
                      <Td>
                        <span className="mono text-xs">{item.vulnerability_id}</span>
                        <span className="block text-xs text-subtle">
                          {item.product} {item.installed_version}
                        </span>
                      </Td>
                      <Td>
                        <Badge className={severityTone(item.severity)}>{item.severity}</Badge>
                        <span className="ml-1 text-xs text-subtle">{item.priority}</span>
                      </Td>
                      <Td className="text-xs">
                        {item.team || <span className="text-high">unassigned</span>}
                        <span className="block text-subtle">
                          {item.owner || (item.team ? "no engineer" : "set an owner in Ownership")}
                        </span>
                      </Td>
                      <Td>
                        <Badge className={stateTone(item.state)}>{STATE_LABEL[item.state] ?? item.state}</Badge>
                        {item.accept_expires_at ? (
                          <span className="mt-1 block text-xs text-subtle">
                            by {item.accepted_by} · until {formatDate(item.accept_expires_at)}
                          </span>
                        ) : null}
                      </Td>
                      <Td className="text-xs">
                        {item.due_at ? (
                          <span className={item.overdue ? "text-critical" : "text-muted"}>
                            {formatDate(item.due_at)}
                            {item.overdue ? " · overdue" : ""}
                          </span>
                        ) : (
                          <span className="text-subtle">—</span>
                        )}
                        <span className="block text-subtle">seen {relativeTime(item.last_seen)}</span>
                      </Td>
                      <Td>
                        <div className="flex items-center gap-1">
                          <Select
                            value={item.team ?? ""}
                            onChange={(e) => assign(item, e.target.value)}
                            aria-label={`Assign ${item.vulnerability_id} on ${item.asset}`}
                          >
                            <option value="">Unassigned</option>
                            {teams.map((t) => (
                              <option key={t} value={t}>
                                {t}
                              </option>
                            ))}
                          </Select>
                          {me && item.owner !== me ? (
                            <Button size="sm" variant="ghost" onClick={() => claim(item)} title={`Assign ${item.id} to ${me}`}>
                              Claim
                            </Button>
                          ) : null}
                          {item.state !== "risk_accepted" ? (
                            <Button size="sm" variant="ghost" onClick={() => setAccepting(item)}>
                              Accept risk
                            </Button>
                          ) : null}
                        </div>
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          ) : null}
        </CardBody>
      </Card>

      <Modal
        open={accepting !== null}
        onOpenChange={(open) => {
          if (!open) setAccepting(null);
        }}
        title={accepting ? `Accept the risk for ${accepting.vulnerability_id}` : "Accept risk"}
        description="An accepted risk keeps the finding visible, records who decided and why, and reopens automatically when the review date passes."
      >
        <div className="space-y-3">
          <Field label="Reason" htmlFor="accept-reason" hint="What makes this acceptable, and what is covering it in the meantime?">
            <Input
              id="accept-reason"
              value={acceptReason}
              onChange={(e) => setAcceptReason(e.target.value)}
              placeholder="e.g. vendor patch lands in Q3; host is isolated by a network rule"
            />
          </Field>
          <Field label="Review in" htmlFor="accept-days">
            <Select id="accept-days" value={String(acceptDays)} onChange={(e) => setAcceptDays(Number(e.target.value))}>
              {[30, 60, 90, 180].map((d) => (
                <option key={d} value={d}>
                  {d} days
                </option>
              ))}
            </Select>
          </Field>
          <div className="flex items-center gap-2">
            <Button variant="primary" onClick={submitAcceptance} disabled={acceptReason.trim().length < 8}>
              Record acceptance
            </Button>
            <Button variant="ghost" onClick={() => setAccepting(null)}>
              Cancel
            </Button>
          </div>
        </div>
      </Modal>

      {summary.data ? (
        <p className="text-xs text-subtle">
          Counts computed {relativeTime(summary.data.generated)} · {s?.total ?? 0} items ·{" "}
          {s?.triage_assets ?? 0} assets waiting for an owner
        </p>
      ) : null}
    </div>
  );
}
