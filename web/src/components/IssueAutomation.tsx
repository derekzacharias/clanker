import { Loader2, Play, ShieldQuestion } from "lucide-react";
import { useEffect, useState } from "react";
import {
  api,
  ApiError,
  type AutomationAuditEntry,
  type AutomationConfig,
  type AutomationResult,
} from "../lib/api";
import { useAsync } from "../lib/useApi";
import { formatDate, relativeTime } from "../lib/format";
import { Badge } from "./ui/Badge";
import { Button } from "./ui/Button";
import { Card, CardBody, CardHeader } from "./ui/Card";
import { Banner, EmptyState, LoadingBlock } from "./ui/Feedback";
import { Field, Input, Select } from "./ui/Field";
import { Switch } from "./ui/Switch";
import { Table, TableWrap, Td, Th, Tr } from "./ui/Table";
import { useToast } from "./ui/Toast";

/**
 * Settings → Issue automation ("Create Issues for Me").
 *
 * The mode is the whole security story of this page, so it is explained in place rather
 * than in a tooltip: manual does nothing, assisted prepares issues for approval, auto
 * files them. Auto asks for confirmation on every run and holds anything the generator
 * flagged for review.
 */
export function IssueAutomation() {
  const toast = useToast();
  const state = useAsync(() => api.automation(), []);
  const [config, setConfig] = useState<AutomationConfig | null>(null);
  const [project, setProject] = useState(0);
  const [saving, setSaving] = useState(false);
  const [running, setRunning] = useState(false);
  const [results, setResults] = useState<AutomationResult[]>([]);
  const [previewId, setPreviewId] = useState("");
  const [preview, setPreview] = useState<AutomationResult | null>(null);
  const [audit, setAudit] = useState<AutomationAuditEntry[]>([]);

  useEffect(() => {
    if (!state.data) return;
    setConfig(state.data.config);
    setProject(state.data.gitlab_project);
  }, [state.data]);

  const loadAudit = async () => {
    try {
      const res = await api.automationAudit(50);
      setAudit(res.entries.slice().reverse());
    } catch {
      /* the trail is optional for rendering the form */
    }
  };

  useEffect(() => {
    void loadAudit();
  }, []);

  async function save(next?: Partial<AutomationConfig>) {
    if (!config) return;
    setSaving(true);
    try {
      const res = await api.saveAutomation({ ...config, ...next });
      setConfig(res.config);
      toast.push("Automation policy saved");
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "Could not save the policy", "error");
    } finally {
      setSaving(false);
    }
  }

  async function run() {
    if (!config) return;
    if (config.mode === "auto") {
      const ok = window.confirm(
        "Create issues in GitLab now?\n\nThis writes to the real project. Findings the generator flagged for review are held back.",
      );
      if (!ok) return;
    }
    setRunning(true);
    try {
      const res = await api.runAutomation(config.mode, true);
      setResults(res.results);
      toast.push(
        res.created > 0 ? `${res.created} issue(s) created` : `${res.results.length} finding(s) evaluated`,
      );
      void loadAudit();
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "The run failed", "error");
    } finally {
      setRunning(false);
    }
  }

  async function previewFinding() {
    if (!previewId.trim()) {
      toast.push("Paste a finding id first", "error");
      return;
    }
    try {
      const res = await api.previewIssue(previewId.trim());
      setPreview(res);
    } catch (err) {
      toast.push(err instanceof ApiError ? err.message : "Could not preview that finding", "error");
    }
  }

  if (state.loading) return <LoadingBlock label="Loading automation settings" />;
  if (state.error) {
    return (
      <Banner tone="danger" title="Automation settings are unavailable">
        {state.error.message}
      </Banner>
    );
  }
  if (!config) return null;

  return (
    <div className="grid gap-3">
      <Card>
        <CardHeader
          title="Create Issues for Me"
          description="Who decides that a finding becomes a GitLab issue."
          actions={
            <Badge
              className={
                config.mode === "auto"
                  ? "border-high/40 bg-high-soft text-high"
                  : config.mode === "assisted"
                    ? "border-accent/30 bg-accent-soft text-accent"
                    : "border-border-strong text-muted"
              }
            >
              {config.mode}
            </Badge>
          }
        />
        <CardBody className="grid gap-4">
          <fieldset className="grid gap-2">
            <legend className="mb-1 text-sm font-medium text-fg">Mode</legend>
            {(
              [
                ["manual", "Manual", "Nothing happens automatically. You file issues yourself."],
                ["assisted", "AI-assisted", "Issues are drafted for you to review. Nothing is sent to GitLab."],
                ["auto", "Create issues for me", "Qualifying findings become issues. Anything flagged for review is held back."],
              ] as const
            ).map(([value, label, description]) => (
              <label
                key={value}
                className={`flex cursor-pointer items-start gap-3 rounded-md border p-3 text-sm ${
                  config.mode === value ? "border-accent bg-accent-soft" : "border-border-strong"
                }`}
              >
                <input
                  type="radio"
                  name="automation-mode"
                  value={value}
                  checked={config.mode === value}
                  onChange={() => {
                    setConfig({ ...config, mode: value });
                    void save({ mode: value });
                  }}
                  className="mt-1"
                />
                <span>
                  <span className="font-medium">{label}</span>
                  <span className="block text-xs text-muted">{description}</span>
                </span>
              </label>
            ))}
          </fieldset>

          <div className="grid gap-3 sm:grid-cols-3">
            <Field label="Minimum severity" hint="Findings below this never become issues.">
              <Select
                value={config.min_severity}
                onChange={(e) => {
                  const next = { ...config, min_severity: e.target.value };
                  setConfig(next);
                  void save({ min_severity: e.target.value });
                }}
              >
                {["critical", "high", "medium", "low"].map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Maximum per run" hint="A hard budget for a single execution.">
              <Input
                type="number"
                min={1}
                max={200}
                value={config.max_per_run}
                onChange={(e) => setConfig({ ...config, max_per_run: Number(e.target.value) || 1 })}
                onBlur={() => void save({ max_per_run: config.max_per_run })}
              />
            </Field>
            <Field label="Destination project" hint={project ? `GitLab project #${project}` : "No GitLab project configured."}>
              <Input value={project ? `#${project}` : "—"} readOnly disabled />
            </Field>
          </div>

          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Labels" hint="Comma separated, added to every created issue.">
              <Input
                value={(config.labels ?? []).join(", ")}
                onChange={(e) =>
                  setConfig({ ...config, labels: e.target.value.split(",").map((l) => l.trim()).filter(Boolean) })
                }
                onBlur={() => void save({ labels: config.labels })}
              />
            </Field>
            <Field label="Assignee" hint="GitLab username. Leave empty for nobody.">
              <Input
                value={config.assignee ?? ""}
                onChange={(e) => setConfig({ ...config, assignee: e.target.value })}
                onBlur={() => void save({ assignee: config.assignee })}
              />
            </Field>
          </div>

          <div className="grid gap-2">
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>
                Let the AI write the issue
                <span className="block text-xs text-muted">
                  Off means issues are built from the scan record alone — same facts, no prose.
                </span>
              </span>
              <Switch
                checked={config.use_ai}
                onCheckedChange={(v) => {
                  setConfig({ ...config, use_ai: v });
                  void save({ use_ai: v });
                }}
              />
            </label>
            <label className="flex items-center justify-between gap-3 text-sm">
              <span>
                Reopen closed issues when a finding returns
                <span className="block text-xs text-muted">
                  Duplicate detection uses the finding marker, so a closed ticket is never filed twice.
                </span>
              </span>
              <Switch
                checked={config.reopen_closed}
                onCheckedChange={(v) => {
                  setConfig({ ...config, reopen_closed: v });
                  void save({ reopen_closed: v });
                }}
              />
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button onClick={() => void run()} disabled={running || config.mode === "manual"}>
              {running ? <Loader2 size={14} className="animate-spin" /> : <Play size={14} />} Run now
            </Button>
            <Button variant="secondary" onClick={() => void save()} disabled={saving}>
              Save policy
            </Button>
            <span className="text-xs text-muted">
              {config.mode === "auto"
                ? "Auto mode asks for confirmation on every run."
                : config.mode === "assisted"
                  ? "Assisted mode never writes to GitLab."
                  : "Manual mode does nothing."}
            </span>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title="Preview an issue"
          description="See exactly what would be filed, before enabling automation."
        />
        <CardBody className="grid gap-3">
          <div className="flex flex-wrap items-end gap-2">
            <div className="min-w-[16rem] flex-1">
              <Field label="Finding id" hint="From the Findings page, for example FINDING-0001.">
                <Input value={previewId} onChange={(e) => setPreviewId(e.target.value)} placeholder="FINDING-0001" />
              </Field>
            </div>
            <Button variant="secondary" onClick={() => void previewFinding()}>
              <ShieldQuestion size={14} /> Preview
            </Button>
          </div>
          {preview && (
            <div className="grid gap-2">
              {preview.draft?.requires_review && (
                <Banner tone="warn" title="This draft would be held for review">
                  {preview.draft.review_reasons?.join("; ")}
                </Banner>
              )}
              <div className="rounded-md border border-border-strong bg-surface-2 p-3">
                <p className="mb-2 text-sm font-medium">{preview.title}</p>
                <pre className="max-h-80 overflow-auto whitespace-pre-wrap text-xs text-muted">{preview.body}</pre>
              </div>
            </div>
          )}
        </CardBody>
      </Card>

      {results.length > 0 && (
        <Card>
          <CardHeader title="Last run" description={`${results.length} finding(s) evaluated.`} />
          <CardBody>
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th>Finding</Th>
                    <Th>Severity</Th>
                    <Th>Action</Th>
                    <Th>Detail</Th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r) => (
                    <Tr key={r.finding_key + r.action}>
                      <Td>
                        <span className="font-mono text-xs">{r.cve}</span>
                        <span className="block text-xs text-muted">{r.asset}</span>
                      </Td>
                      <Td>{r.severity}</Td>
                      <Td>
                        <Badge
                          className={
                            r.action === "created"
                              ? "border-low/40 bg-low-soft text-low"
                              : r.action === "needs_review" || r.action === "failed"
                                ? "border-high/40 bg-high-soft text-high"
                                : ""
                          }
                        >
                          {r.action}
                        </Badge>
                      </Td>
                      <Td className="text-xs text-muted">
                        {r.issue_url ? (
                          <a className="text-accent hover:underline" href={r.issue_url} target="_blank" rel="noreferrer">
                            {r.issue_url}
                          </a>
                        ) : (
                          r.reason || "—"
                        )}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          </CardBody>
        </Card>
      )}

      <Card>
        <CardHeader
          title="Activity"
          description="Every automated decision: what was created, why, and which model wrote it."
        />
        <CardBody>
          {audit.length === 0 ? (
            <EmptyState title="No activity yet" description="Run the workflow and the decisions will appear here." />
          ) : (
            <TableWrap>
              <Table>
                <thead>
                  <tr>
                    <Th>When</Th>
                    <Th>Action</Th>
                    <Th>Finding</Th>
                    <Th>Model</Th>
                    <Th>Issue</Th>
                  </tr>
                </thead>
                <tbody>
                  {audit.map((entry, i) => (
                    <Tr key={`${entry.at}-${i}`}>
                      <Td title={formatDate(entry.at)}>{relativeTime(entry.at)}</Td>
                      <Td>
                        <Badge>{entry.action}</Badge>
                      </Td>
                      <Td className="text-xs">
                        <span className="font-mono">{entry.cve}</span>
                        <span className="block text-muted">{entry.asset}</span>
                      </Td>
                      <Td className="text-xs text-muted">
                        {entry.generator === "ai" ? `${entry.provider}/${entry.model}` : entry.generator || "—"}
                      </Td>
                      <Td className="text-xs">
                        {entry.issue_url ? (
                          <a className="text-accent hover:underline" href={entry.issue_url} target="_blank" rel="noreferrer">
                            #{entry.issue_iid}
                          </a>
                        ) : (
                          <span className="text-muted">{entry.reason || "—"}</span>
                        )}
                      </Td>
                    </Tr>
                  ))}
                </tbody>
              </Table>
            </TableWrap>
          )}
        </CardBody>
      </Card>
    </div>
  );
}
