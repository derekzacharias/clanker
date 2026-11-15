import { useMemo, useState } from "react";
import { useAsync } from "../lib/useApi";
import { api, type RemediationItem, type RemediationState } from "../lib/api";
import { PageHeader } from "../components/PageHeader";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { EmptyState, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Select } from "../components/ui/Field";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { useToast } from "../components/ui/Toast";
import { formatDate, relativeTime } from "../lib/format";

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

export default function Remediation() {
  const [team, setTeam] = useState("");
  const [state, setState] = useState("");
  const [overdueOnly, setOverdueOnly] = useState(false);
  const { push } = useToast();

  const summary = useAsync(() => api.remediationSummary());
  const items = useAsync(
    () => api.remediation({ team: team || undefined, state: state || undefined, overdue: overdueOnly || undefined }),
    [team, state, overdueOnly],
  );

  const teams = useMemo(() => {
    const known = new Set<string>(ASSIGNABLE_TEAMS);
    (summary.data?.teams ?? []).forEach((t) => known.add(t));
    return [...known].sort();
  }, [summary.data]);

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

  const s = summary.data?.summary;

  return (
    <div className="space-y-4">
      <PageHeader
        title="Remediation"
        description="Who owns each finding, what it is waiting for, and when it is due. Findings themselves stay in Vulnerabilities."
      />

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

      <Card>
        <CardHeader
          title="Work queue"
          description="Routed from asset ownership, then the responsibility mapping. Unknown assets wait for a human instead of defaulting to a team."
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

          {items.data && items.data.items.length > 0 ? (
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
                      <Td className="text-xs">{item.team || <span className="text-high">unassigned</span>}</Td>
                      <Td>
                        <Badge className={stateTone(item.state)}>{STATE_LABEL[item.state] ?? item.state}</Badge>
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
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          ) : null}
        </CardBody>
      </Card>

      {summary.data ? (
        <p className="text-xs text-subtle">
          Counts computed {relativeTime(summary.data.generated)} · {s?.total ?? 0} items ·{" "}
          {s?.triage_assets ?? 0} assets waiting for an owner
        </p>
      ) : null}
    </div>
  );
}
