import { useRef, useState } from "react";
import { CheckCircle2, ExternalLink, Loader2, Plug, RefreshCw, XCircle } from "lucide-react";
import { api, type GitLabConfig, type GitLabProject, type GitLabTicket, type GitLabVerifyResult } from "../lib/api";
import { RemediationPreview } from "./RemediationPreview";
import { useAsync } from "../lib/useApi";
import { Banner } from "./ui/Feedback";
import { Button } from "./ui/Button";
import { Field, Input, Select } from "./ui/Field";
import { Switch } from "./ui/Switch";
import { relativeTime } from "../lib/format";

/**
 * GitLab ticketing panel for the finding detail.
 *
 * The finding is evidence and never changes, so the panel does not edit it: it renders the
 * issue body from the server (one source of truth for the text), lets the operator adjust
 * what will be sent, and records the resulting issue. Once a ticket exists, the create
 * action is replaced by the ticket, because "create another" is rarely what anyone wants.
 */
export function GitLabTicketPanel({
  findingId,
  initialTickets = [],
}: {
  findingId: string;
  /** Tickets already present on the finding detail, so an existing issue never flashes. */
  initialTickets?: GitLabTicket[];
}) {
  const config = useAsync(() => api.gitlabConfig());
  const [tickets, setTickets] = useState<GitLabTicket[] | null>(initialTickets.length > 0 ? initialTickets : null);
  const [composing, setComposing] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const known = tickets ?? [];
  // Tickets go stale as soon as someone else touches them in GitLab. On open, refresh once
  // per mount when the cached state is old, so the panel shows the current status instead of
  // yesterday's — without hammering the API on every render.
  const refreshed = useRef(false);
  const staleBefore = Date.now() - 10 * 60 * 1000;
  const cfg = config.data;
  const ready = Boolean(cfg?.ready);
  const configured = Boolean(cfg?.url);

  async function refresh(ticket: GitLabTicket) {
    setError(null);
    try {
      const res = await api.refreshGitLabTicket(ticket.id);
      setTickets((prev) => (prev ?? []).map((t) => (t.id === res.ticket.id ? res.ticket : t)));
      setMessage(`#${res.ticket.issue_iid} is ${res.ticket.state} in GitLab`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not refresh the ticket status");
    }
  }

  const stale = known.some((t) => !t.last_synced_at || new Date(t.last_synced_at).getTime() < staleBefore);
  if (!refreshed.current && configured && known.length > 0 && stale) {
    refreshed.current = true;
    const first = known[0];
    api
      .refreshGitLabTicket(first.id)
      .then((res) => setTickets((prev) => (prev ?? []).map((t) => (t.id === res.ticket.id ? res.ticket : t))))
      .catch(() => {
        // A failed background refresh is not worth an error banner: the Refresh status
        // button is still there, and it will say what went wrong.
      });
  }

  if (config.loading) return null;
  if (!configured) return null;

  if (known.length > 0) {
    return (
      <Section>
        <div className="space-y-2">
          {known.map((t) => (
            <div key={t.id} className="rounded-md border border-border bg-surface-2 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm font-medium">GitLab ticket #{t.issue_iid}</span>
                <span
                  className={`rounded border px-1.5 py-0.5 text-xs ${
                    t.state === "closed"
                      ? "border-border bg-surface text-muted"
                      : "border-low/30 bg-low-soft text-low"
                  }`}
                >
                  {t.state === "closed" ? "Closed" : "Open"}
                </span>
                {t.assignee ? <span className="text-xs text-muted">Assigned to {t.assignee}</span> : null}
                {t.remediation_status ? (
                  <span className="text-xs text-muted">remediation: {t.remediation_status.replace(/_/g, " ")}</span>
                ) : null}
                <span className="ml-auto text-xs text-subtle">
                  {t.last_synced_at ? `checked ${relativeTime(t.last_synced_at)}` : "not checked yet"}
                </span>
              </div>
              <p className="mt-1 text-xs text-muted">{t.title}</p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <a
                  href={t.issue_url}
                  target="_blank"
                  rel="noreferrer"
                  className="inline-flex items-center gap-1 text-xs text-accent underline underline-offset-2"
                >
                  View GitLab ticket #{t.issue_iid} <ExternalLink className="h-3 w-3" aria-hidden="true" />
                </a>
                <Button size="sm" variant="ghost" onClick={() => refresh(t)}>
                  <RefreshCw className="h-3.5 w-3.5" aria-hidden="true" />
                  Refresh status
                </Button>
              </div>
              <p className="mt-2 text-xs text-muted">
                A closed ticket is not proof of a fix: this finding is resolved only when a later scan stops
                reporting it.
              </p>
            </div>
          ))}
        </div>
        {message ? <p className="mt-2 text-xs text-muted">{message}</p> : null}
        {error ? <p className="mt-2 text-xs text-critical">{error}</p> : null}
      </Section>
    );
  }

  return (
    <Section>
      {!composing ? (
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary" size="sm" onClick={() => setComposing(true)} disabled={!ready}>
            <Plug className="h-4 w-4" aria-hidden="true" />
            Create GitLab Ticket
          </Button>
          <p className="text-xs text-muted">
            {ready
              ? "Previews the issue, then creates it in the configured project."
              : cfg?.blocked || "GitLab ticketing is not configured yet."}
          </p>
        </div>
      ) : (
        <TicketComposer
          findingId={findingId}
          config={cfg!}
          onCancel={() => setComposing(false)}
          onCreated={(ticket, serverMessage) => {
            setTickets([ticket]);
            setComposing(false);
            setMessage(serverMessage);
          }}
        />
      )}
      {error ? <p className="mt-2 text-xs text-critical">{error}</p> : null}
    </Section>
  );
}

function TicketComposer({
  findingId,
  config,
  onCancel,
  onCreated,
}: {
  findingId: string;
  config: GitLabConfig;
  onCancel: () => void;
  onCreated: (ticket: GitLabTicket, serverMessage: string) => void;
}) {
  const preview = useAsync(() => api.gitlabPreview(findingId), [findingId]);
  const projects = useAsync(() => api.gitlabProjects());
  const users = useAsync(() => api.gitlabUsers());
  const [title, setTitle] = useState<string | null>(null);
  const [description, setDescription] = useState<string | null>(null);
  const [projectID, setProjectID] = useState<number>(config.project_id);
  const [assigneeID, setAssigneeID] = useState<number>(0);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<{ ticket: GitLabTicket; message: string } | null>(null);

  const projectOptions: GitLabProject[] = projects.data?.items ?? [];
  const effectiveTitle = title ?? preview.data?.title ?? "";
  const effectiveDescription = description ?? preview.data?.description ?? "";

  async function submit() {
    setSaving(true);
    setError(null);
    try {
      const res = await api.createGitLabTicket({
        finding_id: findingId,
        project_id: projectID,
        title: effectiveTitle,
        description: effectiveDescription,
        assignee_id: assigneeID || undefined,
      });
      setResult({ ticket: res.ticket, message: res.message });
      onCreated(res.ticket, res.message);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create the ticket");
    } finally {
      setSaving(false);
    }
  }

  if (result) {
    return (
      <div className="space-y-2 rounded-md border border-low/30 bg-low-soft p-3">
        <p className="flex items-center gap-2 text-sm font-medium text-low">
          <CheckCircle2 className="h-4 w-4" aria-hidden="true" />
          {result.message}
        </p>
        <a
          href={result.ticket.issue_url}
          target="_blank"
          rel="noreferrer"
          className="inline-flex items-center gap-1 text-sm text-accent underline underline-offset-2"
        >
          View GitLab ticket #{result.ticket.issue_iid} <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
        </a>
      </div>
    );
  }

  return (
    <div className="space-y-3 rounded-md border border-border bg-surface-2 p-3">
      <div className="flex items-center justify-between gap-2">
        <h4 className="text-sm font-semibold">GitLab ticket preview</h4>
        <span className="text-xs text-subtle">{config.url}</span>
      </div>

      {preview.error ? <Banner tone="danger" title="Could not build the ticket">{preview.error.message}</Banner> : null}

      <Field label="Title" htmlFor="gl-title">
        <Input id="gl-title" value={effectiveTitle} onChange={(e) => setTitle(e.target.value)} />
      </Field>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Project" htmlFor="gl-project">
          <Select id="gl-project" value={String(projectID)} onChange={(e) => setProjectID(Number(e.target.value))}>
            {projectOptions.length === 0 ? <option value={String(projectID)}>{config.project_id}</option> : null}
            {projectOptions.map((p) => (
              <option key={p.id} value={p.id}>
                {p.path_with_namespace}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="Assignee (optional)" htmlFor="gl-assignee">
          <Select id="gl-assignee" value={String(assigneeID)} onChange={(e) => setAssigneeID(Number(e.target.value))}>
            <option value="0">Nobody</option>
            {(users.data?.items ?? []).map((u) => (
              <option key={u.id} value={u.id}>
                {u.name} (@{u.username})
              </option>
            ))}
          </Select>
        </Field>
      </div>

      {preview.data ? (
        <p className="text-xs text-muted">
          Labels: <span className="mono">{preview.data.label_field}</span>
        </p>
      ) : null}

      {preview.data?.plan ? <RemediationPreview plan={preview.data.plan} /> : null}

      <details className="rounded-md border border-border bg-surface p-2">
        <summary className="cursor-pointer text-xs font-medium text-muted">
          Advanced: edit the Markdown that will be posted
        </summary>
        <p className="mt-1 text-xs text-subtle">
          The preview above is rendered from the same plan. Editing here replaces the body exactly as typed.
        </p>
        <textarea
          id="gl-description"
          aria-label="Issue description markdown"
          value={effectiveDescription}
          onChange={(e) => setDescription(e.target.value)}
          rows={14}
          spellCheck={false}
          className="mono mt-2 w-full rounded-md border border-border bg-surface-2 px-2.5 py-2 text-xs leading-relaxed text-fg"
        />
      </details>

      {error ? (
        <Banner tone="danger" title="GitLab did not accept the ticket">
          {error}
        </Banner>
      ) : null}

      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" size="sm" onClick={submit} disabled={saving || !effectiveTitle.trim()}>
          {saving ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Plug className="h-4 w-4" aria-hidden="true" />}
          {saving ? "Creating…" : "Create Ticket"}
        </Button>
        <Button variant="ghost" size="sm" onClick={onCancel} disabled={saving}>
          Cancel
        </Button>
        <p className="text-xs text-muted">
          The finding is stored as evidence; the ticket is a link to it. Creating twice reuses the first issue.
        </p>
      </div>
    </div>
  );
}

/** Connection test summary: one line per check, no fake green tick. */
export function GitLabChecks({ result }: { result: GitLabVerifyResult }) {
  return (
    <div className="space-y-1.5">
      {result.checks.map((c) => (
        <p key={c.name} className="flex items-start gap-2 text-xs">
          {c.ok && !c.warning ? (
            <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-low" aria-hidden="true" />
          ) : c.ok ? (
            <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-high" aria-hidden="true" />
          ) : (
            <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-critical" aria-hidden="true" />
          )}
          <span>
            <span className="font-medium">{c.name}</span>
            {c.detail ? <span className="text-muted"> — {c.detail}</span> : null}
          </span>
        </p>
      ))}
    </div>
  );
}

function Section({ children }: { children: React.ReactNode }) {
  return (
    <section>
      <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Ticketing</h3>
      {children}
    </section>
  );
}

/** Kept for the settings panel: a labelled switch row. */
export function ToggleRow({
  id,
  label,
  description,
  checked,
  onChange,
}: {
  id: string;
  label: string;
  description: string;
  checked: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
        <p className="text-xs text-muted">{description}</p>
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} />
    </div>
  );
}
