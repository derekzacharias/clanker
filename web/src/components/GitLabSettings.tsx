import { useEffect, useState } from "react";
import { CheckCircle2, Loader2, Plug, RefreshCw, Save } from "lucide-react";
import { api, type GitLabProject, type GitLabVerifyResult } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { Banner } from "./ui/Feedback";
import { Button } from "./ui/Button";
import { Field, Input, Select } from "./ui/Field";
import { Switch } from "./ui/Switch";
import { GitLabChecks } from "./GitLabTicketPanel";
import { formatDate } from "../lib/format";

/**
 * Settings → Integrations → GitLab.
 *
 * The access token is write-only: it goes to the server once, is stored in a 0600 file (or
 * comes from the environment), and is never sent back. Leaving the field blank keeps the
 * stored token, because the browser cannot show it and re-typing it on every save is how
 * tokens end up in a sticky note.
 */
export function GitLabSettings() {
  const config = useAsync(() => api.gitlabConfig());
  const [enabled, setEnabled] = useState(false);
  const [url, setURL] = useState("");
  const [allowHTTP, setAllowHTTP] = useState(false);
  const [token, setToken] = useState("");
  const [projectID, setProjectID] = useState(0);
  const [labels, setLabels] = useState("");
  const [assignee, setAssignee] = useState("");
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<GitLabVerifyResult | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [projects, setProjects] = useState<GitLabProject[] | null>(null);
  const [loadingProjects, setLoadingProjects] = useState(false);

  // Load the stored configuration once.
  const stored = config.data;
  useEffect(() => {
    if (!stored) return;
    setEnabled(stored.enabled);
    setURL(stored.url ?? "");
    setAllowHTTP(stored.allow_insecure_http);
    setProjectID(stored.project_id ?? 0);
    setLabels((stored.labels ?? []).join(", "));
    setAssignee(stored.assignee ?? "");
  }, [stored]);

  async function save() {
    setSaving(true);
    setError(null);
    setMessage(null);
    try {
      const body: Parameters<typeof api.saveGitLab>[0] = {
        enabled,
        url: url.trim(),
        allow_insecure_http: allowHTTP,
        project_id: projectID,
        labels: labels
          .split(",")
          .map((l) => l.trim())
          .filter(Boolean),
        assignee: assignee.trim(),
      };
      if (token.trim() !== "") body.token = token.trim();
      const next = await api.saveGitLab(body);
      setToken("");
      setMessage(next.ready ? "Saved. Ticketing is ready." : `Saved, but not ready: ${next.blocked}`);
      config.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not save the GitLab configuration");
    } finally {
      setSaving(false);
    }
  }

  async function test() {
    setTesting(true);
    setError(null);
    setResult(null);
    try {
      const body: Parameters<typeof api.testGitLab>[0] = {
        allow_insecure_http: allowHTTP,
      };
      if (url.trim() !== "") body.url = url.trim();
      if (token.trim() !== "") body.token = token.trim();
      if (projectID > 0) body.project_id = projectID;
      const res = await api.testGitLab(body);
      setResult(res);
      // The server records when the test ran and whether it passed; reload so the summary
      // at the bottom of the panel is not stale.
      config.reload();
    } catch (err) {
      setError(err instanceof Error ? err.message : "The connection test could not run");
    } finally {
      setTesting(false);
    }
  }

  async function loadProjects() {
    setLoadingProjects(true);
    setError(null);
    try {
      const res = await api.gitlabProjects();
      setProjects(res.items);
      if (res.items.length === 0) setError("This token cannot see any projects.");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not list projects");
    } finally {
      setLoadingProjects(false);
    }
  }

  if (config.loading && !stored) return <p className="text-sm text-muted">Loading GitLab settings…</p>;
  if (config.error) return <Banner tone="danger" title="Could not read the GitLab settings">{config.error.message}</Banner>;

  return (
    <div className="space-y-4">
      <div className="rounded-md border border-border bg-surface-2 p-3">
        <div className="flex items-start justify-between gap-4">
          <div>
            <label htmlFor="gitlab-enabled" className="text-sm font-medium">
              Enable GitLab ticketing
            </label>
            <p className="text-xs text-muted">
              Adds “Create GitLab Ticket” to findings and creates issues through the GitLab API. Off by default: nothing
              is sent anywhere until it is switched on.
            </p>
          </div>
          <Switch id="gitlab-enabled" checked={enabled} onCheckedChange={setEnabled} />
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="GitLab server URL" htmlFor="gitlab-url" hint="For example https://gitlab.example.com">
          <Input
            id="gitlab-url"
            value={url}
            onChange={(e) => setURL(e.target.value)}
            placeholder="https://gitlab.example.com"
            spellCheck={false}
          />
        </Field>
        <Field
          label="Access token"
          htmlFor="gitlab-token"
          hint={
            stored?.token_set
              ? `A token is stored (${stored.token_source}). Leave blank to keep it.`
              : "Needs the api scope and at least the Reporter role on the project."
          }
        >
          <Input
            id="gitlab-token"
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            placeholder={stored?.token_set ? "•••••••• (stored)" : "glpat-…"}
            autoComplete="off"
            spellCheck={false}
          />
        </Field>
      </div>

      <div className="flex items-start justify-between gap-4 rounded-md border border-border p-3">
        <div>
          <label htmlFor="gitlab-http" className="text-sm font-medium">
            Allow plain HTTP for an internal instance
          </label>
          <p className="text-xs text-muted">
            Plain HTTP is refused unless this is on <em>and</em> the server resolves to a private address. Use HTTPS
            anywhere a token would cross an untrusted network.
          </p>
        </div>
        <Switch id="gitlab-http" checked={allowHTTP} onCheckedChange={setAllowHTTP} />
      </div>

      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Default project" htmlFor="gitlab-project" hint="Where issues are created unless the operator picks another.">
          <div className="flex gap-2">
            <Select
              id="gitlab-project"
              value={String(projectID)}
              onChange={(e) => setProjectID(Number(e.target.value))}
            >
              <option value="0">No project selected</option>
              {projectID > 0 && !(projects ?? []).some((p) => p.id === projectID) ? (
                <option value={String(projectID)}>{projectID}</option>
              ) : null}
              {(projects ?? []).map((p) => (
                <option key={p.id} value={p.id}>
                  {p.path_with_namespace}
                </option>
              ))}
            </Select>
            <Button size="sm" onClick={loadProjects} disabled={loadingProjects || !stored?.token_set}>
              {loadingProjects ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
              Load
            </Button>
          </div>
        </Field>
        <Field label="Default labels" htmlFor="gitlab-labels" hint="Comma separated. Severity and KEV labels are added automatically.">
          <Input
            id="gitlab-labels"
            value={labels}
            onChange={(e) => setLabels(e.target.value)}
            placeholder="security, team-infra"
          />
        </Field>
      </div>

      <Field label="Default assignee" htmlFor="gitlab-assignee" hint="Optional GitLab username; must be visible to the token.">
        <Input
          id="gitlab-assignee"
          value={assignee}
          onChange={(e) => setAssignee(e.target.value)}
          placeholder="e.g. dana"
          spellCheck={false}
        />
      </Field>

      <div className="flex flex-wrap items-center gap-2">
        <Button variant="primary" onClick={save} disabled={saving}>
          {saving ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Save className="h-4 w-4" aria-hidden="true" />}
          Save
        </Button>
        <Button onClick={test} disabled={testing}>
          {testing ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Plug className="h-4 w-4" aria-hidden="true" />}
          Test connection
        </Button>
        {stored?.token_set ? (
          <Button
            variant="ghost"
            onClick={async () => {
              try {
                await api.saveGitLab({ clear_token: true });
                config.reload();
                setMessage("Stored token removed.");
              } catch (err) {
                setError(err instanceof Error ? err.message : "Could not remove the token");
              }
            }}
          >
            Remove stored token
          </Button>
        ) : null}
      </div>

      {message ? (
        <p className="flex items-center gap-2 text-xs text-muted">
          <CheckCircle2 className="h-3.5 w-3.5 text-low" aria-hidden="true" />
          {message}
        </p>
      ) : null}
      {error ? <Banner tone="danger" title="GitLab">{error}</Banner> : null}

      {result ? (
        <div className={`rounded-md border p-3 ${result.ok ? "border-low/30 bg-low-soft" : "border-high/30 bg-high-soft"}`}>
          <p className="text-sm font-medium">{result.summary}</p>
          <div className="mt-2">
            <GitLabChecks result={result} />
          </div>
          <p className="mt-2 text-xs text-muted">
            This checks reachability, authentication, project access and permissions. It does not create an issue, so
            “ok” here means “the connection is ready”, not “a ticket was created”.
          </p>
        </div>
      ) : null}

      {stored ? (
        <dl className="grid gap-2 border-t border-border pt-3 text-xs text-muted sm:grid-cols-3">
          <div>
            <dt className="text-subtle">Credential source</dt>
            <dd>{stored.token_source === "environment" ? "environment variable" : "configuration file"}</dd>
          </div>
          <div>
            <dt className="text-subtle">Configuration file</dt>
            <dd className="mono break-all">{stored.config_file}</dd>
          </div>
          <div>
            <dt className="text-subtle">Last connection test</dt>
            <dd>
              {stored.verified_at
                ? `${formatDate(stored.verified_at)} — ${stored.verify_ok ? "passed" : "failed"}`
                : "never run"}
            </dd>
          </div>
        </dl>
      ) : null}
    </div>
  );
}
