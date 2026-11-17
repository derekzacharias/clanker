import * as Tabs from "@radix-ui/react-tabs";
import { Check, Loader2, RefreshCw } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { api, ApiError, getToken, setToken, type EnrolledAgent, type FeedResponse } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { useQueryParam } from "../lib/router";
import Improvement from "./Improvement";
import { GitLabSettings } from "../components/GitLabSettings";
import { AuditLog } from "../components/AuditLog";
import { formatDate, relativeTime } from "../lib/format";
import { PageHeader } from "../components/PageHeader";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { CopyButton } from "../components/ui/CopyButton";
import { Banner, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Field, Input, Select } from "../components/ui/Field";
import { Switch } from "../components/ui/Switch";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { useToast } from "../components/ui/Toast";

const TABS = ["general", "intelligence", "agents", "integrations", "improvement", "access", "audit"] as const;

export default function Settings() {
  const tabParam = useQueryParam("tab");
  // An unknown or stale tab value must fall back instead of rendering nothing.
  const initialTab = TABS.includes((tabParam ?? "") as (typeof TABS)[number]) ? (tabParam as string) : "general";
  return (
    <div>
      <PageHeader
        title="Settings"
        description="Scanner policy, vulnerability intelligence, endpoint agents, integrations and access."
      />
      <Tabs.Root defaultValue={initialTab}>
        <Tabs.List className="mb-3 flex flex-wrap gap-1 border-b border-border" aria-label="Settings sections">
          {[
            ["general", "General"],
            ["intelligence", "Intelligence"],
            ["agents", "Endpoint agents"],
            ["integrations", "Integrations"],
            ["improvement", "Continuous improvement"],
            ["access", "Access"],
            ["audit", "Audit log"],
          ].map(([value, label]) => (
            <Tabs.Trigger
              key={value}
              value={value}
              className="rounded-t-md border-b-2 border-transparent px-3 py-2 text-sm text-muted hover:text-fg data-[state=active]:border-accent data-[state=active]:font-medium data-[state=active]:text-accent"
            >
              {label}
            </Tabs.Trigger>
          ))}
        </Tabs.List>

        <Tabs.Content value="general">
          <GeneralTab />
          <GeneralOperations />
        </Tabs.Content>

        <Tabs.Content value="intelligence">
          <IntelligenceTab />
        </Tabs.Content>
        <Tabs.Content value="agents">
          <AgentsTab />
        </Tabs.Content>
        <Tabs.Content value="integrations">
          <Card>
            <CardHeader
              title="GitLab"
              description="Create remediation issues from findings. The access token is stored on the server and never returned to the browser."
            />
            <CardBody>
              <GitLabSettings />
            </CardBody>
          </Card>
        </Tabs.Content>

        <Tabs.Content value="audit">
          <Card>
            <CardHeader
              title="Audit log"
              description="Durable record of changes made through the dashboard. Survives log rotation."
            />
            <CardBody>
              <AuditLog />
            </CardBody>
          </Card>
        </Tabs.Content>

        <Tabs.Content value="improvement">
          <Improvement />
        </Tabs.Content>
        <Tabs.Content value="access">
          <AccessTab />
        </Tabs.Content>
      </Tabs.Root>
    </div>
  );
}

function GeneralTab() {
  const { data, error, loading, reload } = useAsync(() => api.settings());
  const { push } = useToast();
  const [failOn, setFailOn] = useState("");
  const [failOnKev, setFailOnKev] = useState(false);
  const [offlineDefault, setOfflineDefault] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!data) return;
    setFailOn(data.policy.fail_on ?? "");
    setFailOnKev(data.policy.fail_on_kev);
    setOfflineDefault(data.offline_default);
  }, [data]);

  if (loading && !data) return <LoadingBlock label="Loading settings" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return null;

  async function save() {
    setSaving(true);
    try {
      await api.saveSettings({
        policy: { fail_on: failOn, fail_on_kev: failOnKev },
        offline_default: offlineDefault,
      });
      push("Settings saved");
    } catch (err) {
      push(err instanceof ApiError ? err.message : String(err), "error");
    } finally {
      setSaving(false);
    }
  }

  return (
    <Card>
      <CardHeader title="Assessment policy" description="Applied to new scans and the CLI exit code. Detection is unchanged." />
      <CardBody className="max-w-2xl space-y-4">
        <Field
          label="Failure threshold"
          htmlFor="policy-fail-on"
          hint="Exit code 2 when an actionable finding is at or above this severity."
        >
          <Select id="policy-fail-on" value={failOn} onChange={(e) => setFailOn(e.target.value)}>
            <option value="">Never fail (report only)</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </Select>
        </Field>
        <ToggleRow
          id="policy-kev"
          checked={failOnKev}
          onChange={setFailOnKev}
          label="Fail when a known-exploited finding is actionable"
        />
        <ToggleRow
          id="offline-default"
          checked={offlineDefault}
          onChange={setOfflineDefault}
          label="Default new scans to offline (cached intelligence)"
          hint="Useful on air-gapped hosts; requires a populated cache."
        />
        <div className="flex items-center gap-2 pt-1">
          <Button variant="primary" onClick={save} disabled={saving}>
            {saving ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Check className="h-4 w-4" aria-hidden="true" />}
            Save changes
          </Button>
          <span className="text-xs text-muted">Stored locally in the assessment cache.</span>
        </div>
      </CardBody>
    </Card>
  );
}

function IntelligenceTab() {
  const { data, error, loading, reload } = useAsync(() => api.feeds());
  const { push } = useToast();
  const [updating, setUpdating] = useState(false);

  async function update() {
    setUpdating(true);
    try {
      await api.updateFeeds();
      push("Feed update started");
      window.setTimeout(() => {
        reload();
        setUpdating(false);
      }, 2500);
    } catch (err) {
      setUpdating(false);
      push(err instanceof ApiError ? err.message : String(err), "error");
    }
  }

  if (loading && !data) return <LoadingBlock label="Loading intelligence status" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return null;

  const stale = data.feeds.filter((f) => f.stale);
  return (
    <div className="space-y-3">
      <Card>
        <CardHeader
          title="Vulnerability intelligence"
          description="Advisories are cached locally; a failed sync is never treated as 'no vulnerabilities'."
          actions={
            <Button onClick={update} disabled={updating}>
              {updating ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
              Update intelligence
            </Button>
          }
        />
        <CardBody>
          {stale.length > 0 ? (
            <div className="mb-3">
              <Banner tone="warn" title="Some sources are stale">
                {stale.map((f) => `${f.source} (${relativeTime(f.last_sync)})`).join(", ")}. Findings may be incomplete.
              </Banner>
            </div>
          ) : null}
          {(data.feeds ?? []).length === 0 ? (
            <div className="space-y-2">
              <p className="text-sm text-muted">No intelligence has been downloaded yet.</p>
              <p className="text-sm text-muted">Run an update to fetch CISA KEV and FIRST EPSS.</p>
            </div>
          ) : (
            <FeedTable feeds={data.feeds ?? []} />
          )}
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Local cache" />
        <CardBody className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-3">
          <Count label="Advisories" value={data.counts.advisories} />
          <Count label="KEV records" value={data.counts.kev} />
          <Count label="EPSS scores" value={data.counts.epss} />
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Sources and their limits" />
        <CardBody>
          <ul className="space-y-2 text-sm text-muted">
            <li><span className="font-medium text-fg">OSV</span> — package and distribution advisories. Coverage and record shape differ per ecosystem.</li>
            <li><span className="font-medium text-fg">CISA KEV</span> — confirmed exploitation in the wild. A small catalog, so absence proves nothing.</li>
            <li><span className="font-medium text-fg">FIRST EPSS</span> — exploitation probability from a statistical model; not proof of exploitability.</li>
            <li className="text-xs">Feeds update over HTTPS from the official publishers. Nothing about your endpoints is uploaded.</li>
          </ul>
        </CardBody>
      </Card>
    </div>
  );
}

function AgentsTab() {
  const { data, error, loading, reload } = useAsync(() => api.agents());
  const { push } = useToast();
  // The enrollment token can be copied from here instead of re-running enroll.
  const enrollRef = useRef<HTMLElement | null>(null);
  // Default: install so the endpoint stays reachable. An installer that scans once
  // and exits leaves the endpoint offline the moment it returns.
  const [keepAvailable, setKeepAvailable] = useState(true);
  // A freshly minted single-use token: shown once with its commands and expiry.
  const [minted, setMinted] = useState<{ token: string; expires: string; commands: Record<string, string>; oneoff: Record<string, string> } | null>(null);
  const [minting, setMinting] = useState(false);
  const wantWatch = keepAvailable && Boolean(data?.install.keeps_available);
  // The template (with an <enroll-token> placeholder) is always available; minting a
  // token replaces the placeholder with a real one.
  const commands = minted ? (wantWatch ? minted.commands : minted.oneoff) : wantWatch ? data?.install.commands : data?.install.oneoff_commands ?? data?.install.commands;
  if (loading && !data) return <LoadingBlock label="Loading agent status" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return null;

  return (
    <div className="space-y-3">
      <Card>
        <CardHeader
          title="This endpoint"
          description="The server host's own agent-equivalent inventory path"
        />
        <CardBody className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
          <Row label="Hostname" value={data.local.host} />
          <Row label="Agent version" value={data.local.version} />
          <Row label="Platform" value={data.local.platform} />
          <Row label="Last scan" value={data.local.last_scan ? formatDate(data.local.last_scan) : "Never"} />
          <Row label="Cache" value={<span className="mono text-xs">{data.local.cache_path}</span>} />
          <Row label="Installation" value={<Badge className="border-low/30 bg-low-soft text-low">installed</Badge>} />
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title="Install the agent on other endpoints"
          description="The command enrolls the endpoint here, scans it once, reports the findings and installs a background service so it stays reachable. Installers verify a published SHA-256 first."
          actions={
            <Button
              variant="primary"
              size="sm"
              disabled={minting}
              onClick={async () => {
                setMinting(true);
                try {
                  const res = await api.mintEnrollToken();
                  setMinted({
                    token: res.enroll_token,
                    expires: res.expires_at,
                    commands: res.commands,
                    oneoff: res.oneoff_commands,
                  });
                  push("Enrollment token created — it works once and expires");
                } catch (err) {
                  push(err instanceof Error ? err.message : "Could not create an enrollment token");
                } finally {
                  setMinting(false);
                }
              }}
            >
              New enrollment token
            </Button>
          }
        />
        <CardBody className="space-y-3">
          {data.install.published ? (
            <>
              {data.install.keeps_available ? (
                <ToggleRow
                  id="keep-available"
                  checked={keepAvailable}
                  onChange={setKeepAvailable}
                  label="Keep this endpoint available"
                  hint={
                    keepAvailable
                      ? "The installer adds a background service, so the dashboard can scan this endpoint at any time."
                      : "Adds --no-service: enrolls and scans once, then exits. The endpoint shows offline until you start the service yourself."
                  }
                />
              ) : null}
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
                <InstallCommand title="Linux" command={commands?.linux ?? ""} />
                <InstallCommand title="macOS" command={commands?.macos ?? ""} />
                <InstallCommand title="Windows (PowerShell)" command={commands?.windows ?? ""} />
              </div>
              {minted ? null : (
                <p className="text-xs text-muted">
                  The command above shows <span className="mono">&lt;enroll-token&gt;</span> until you create a token:
                  enrollment tokens are single use and expire after 24 hours. Choose{" "}
                  <span className="font-medium">New enrollment token</span> and the placeholder is replaced with a
                  working token here.
                </p>
              )}
              <div className="flex flex-wrap items-center gap-2 text-xs text-muted">
            {minted ? (
              <>
                <span>Enrollment token (expires {new Date(minted.expires).toLocaleString()}):</span>
                <span ref={enrollRef} className="mono break-all text-fg">
                  {minted.token}
                </span>
                <CopyButton value={minted.token} label="Copy enrollment token" selectRef={enrollRef} />
                <span className="w-full text-subtle">
                  Single use: it is consumed by the next successful enrollment, and expired or used tokens are refused.
                  Create another one for each additional endpoint.
                </span>
              </>
            ) : (
              <span className="w-full text-subtle">
                No token is active. Tokens are created on demand, expire after 24 hours and work once.
              </span>
            )}
              </div>
              {wantWatch ? (
                <div className="rounded-md border border-border bg-surface-2 p-3 text-xs text-muted">
                  <p className="font-medium text-fg">Nothing else to do after the install</p>
                  <p className="mt-1">
                    The installer enrolls the endpoint, runs one assessment and installs a background service
                    (systemd user unit on Linux, LaunchAgent on macOS, logon task on Windows). The endpoint is online
                    from then on — no unit files to write, no commands to schedule.
                  </p>
                  <p className="mt-1">
                    Remove it at any time with <span className="mono">clanker-guard-agent uninstall --yes</span>, which
                    stops and deletes the service too.
                  </p>
                </div>
              ) : null}
            </>
          ) : (
            <>
              <Banner tone="warn" title="No agent artifacts have been published yet">
                Install commands are intentionally not shown: a copy-paste command pointing at a non-existent release
                would fail and would train administrators to ignore verification errors. Publish the artifacts once, then
                the real commands appear here.
              </Banner>
              <div>
                <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted">Build and publish</p>
                <ol className="list-decimal space-y-1 pl-5 text-sm">
                  {(data.install.build_steps ?? []).map((step) => (
                    <li key={step} className="mono text-xs">{step}</li>
                  ))}
                </ol>
              </div>
            </>
          )}
          <div className="rounded-md border border-border bg-surface-2 p-3 text-xs text-muted">
            <p className="font-medium text-fg">What the agent sends</p>
            <p className="mt-1">
              Package-manager metadata, OS release information and listening package metadata, plus the assessment it
              derives from them. It sends findings and its own status (what stage it is running) to{" "}
              <span className="mono">{data.fleet?.server_url || "this dashboard"}</span> and nowhere else; advisory
              lookups go to api.osv.dev. It never uploads files, credentials or documents, and the server cannot ask it to
              run anything. Uninstall with <span className="mono">clanker-guard-agent uninstall --yes</span>.
            </p>
          </div>
          <p className="text-xs text-muted">{data.managed_note}</p>
        </CardBody>
      </Card>

      <Card>
        <CardHeader
          title="Enrolled endpoints"
          description="Agents that hold a per-agent token for this server, and what they are doing."
        />
        {(data.fleet?.enrolled ?? []).length === 0 ? (
          <CardBody>
            <p className="text-sm text-muted">
              No endpoints enrolled yet. Paste an install command above on the endpoint you want to assess; it enrolls,
              scans and reports back on its own.
            </p>
          </CardBody>
        ) : (
          <TableWrap>
            <Table caption="Enrolled endpoints">
              <thead>
                <tr>
                  <Th>Host</Th>
                  <Th>Status</Th>
                  <Th>Activity</Th>
                  <Th>Last seen</Th>
                  <Th className="text-right">Findings</Th>
                  <Th>Version</Th>
                  <Th />
                </tr>
              </thead>
              <tbody>
                {(data.fleet?.enrolled ?? []).map((agent) => (
                  <tr key={agent.id}>
                    <Td>
                      <span className="mono text-xs">{agent.host}</span>
                      {agent.os ? <span className="block text-xs text-subtle">{agent.os}</span> : null}
                    </Td>
                    <Td>{agentStatus(agent)}</Td>
                    <Td>
                      <span className="text-xs text-muted">
                        {agent.revoked
                          ? "removed by operator"
                          : agent.state === "scanning" || agent.state === "reporting"
                            ? [agent.phase, `${agent.percent}%`].filter(Boolean).join(" · ")
                            : agent.watching
                              ? "watching for work"
                              : agent.message || agent.state}
                      </span>
                    </Td>
                    <Td>
                      <span className="text-xs text-muted">{agent.last_seen ? relativeSeconds(agent.seconds_since_seen) : "never"}</span>
                    </Td>
                    <Td className="text-right mono text-xs">{agent.findings}</Td>
                    <Td className="mono text-xs">{agent.version || "—"}</Td>
                    <Td className="text-right">
                      {agent.task?.status === "queued" ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={async () => {
                            try {
                              await api.cancelAgentScan(agent.id);
                              push(`Queued scan for ${agent.host} cancelled`);
                              reload();
                            } catch (err) {
                              push(err instanceof Error ? err.message : "Could not cancel the request");
                            }
                          }}
                        >
                          Cancel request
                        </Button>
                      ) : null}
                      {agent.revoked ? null : (
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={async () => {
                            try {
                              await api.revokeAgent(agent.id);
                              push(`${agent.host} revoked`);
                              reload();
                            } catch (err) {
                              push(err instanceof Error ? err.message : "Could not revoke the endpoint");
                            }
                          }}
                        >
                          Revoke
                        </Button>
                      )}
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </TableWrap>
        )}
        <CardBody className="pt-0">
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Endpoints reporting assessments" description="Hosts with a stored report in this cache" />
        {(data.endpoints ?? []).length === 0 ? (
          <CardBody>
            <p className="text-sm text-muted">No endpoint assessments yet.</p>
          </CardBody>
        ) : (
          <TableWrap>
            <Table caption="Known endpoints">
              <thead>
                <tr>
                  <Th>Host</Th>
                  <Th>Operating system</Th>
                  <Th>Agent version</Th>
                  <Th>Last scan</Th>
                  <Th className="text-right">Findings</Th>
                </tr>
              </thead>
              <tbody>
                {(data.endpoints ?? []).map((e) => (
                  <Tr key={e.host}>
                    <Td className="mono text-xs">{e.host}</Td>
                    <Td>{e.os} {e.os_version}</Td>
                    <Td className="mono text-xs">{e.agent_version}</Td>
                    <Td className="text-xs" title={formatDate(e.last_scan)}>{relativeTime(e.last_scan)}</Td>
                    <Td className="num text-right">{e.findings}</Td>
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

function AccessTab() {
  const { data, error, loading, reload } = useAsync(() => api.settings());
  const [token, setTokenValue] = useState(getToken());
  const { push } = useToast();
  if (loading && !data) return <LoadingBlock label="Loading access settings" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return null;

  return (
    <div className="space-y-3">
      <Card>
        <CardHeader title="API access" description="The interface and CLI share one local API." />
        <CardBody className="max-w-2xl space-y-3 text-sm">
          <Row label="Cache path" value={<span className="mono text-xs">{data.cache_path}</span>} />
          <Row label="Tool version" value={<span className="mono text-xs">{data.tool_version}</span>} />
          <Row
            label="Authentication"
            value={
              data.password_required && data.token_required ? (
                <span className="flex flex-wrap items-center gap-1.5">
                  <Badge className="border-low/30 bg-low-soft text-low">password sign-in</Badge>
                  <Badge className="border-border bg-surface-2 text-muted">+ API token</Badge>
                </span>
              ) : data.password_required ? (
                <Badge className="border-low/30 bg-low-soft text-low">password sign-in</Badge>
              ) : data.token_required ? (
                <Badge className="border-low/30 bg-low-soft text-low">token required</Badge>
              ) : (
                <Badge className="border-border bg-surface-2 text-muted">loopback only</Badge>
              )
            }
          />
          <p className="text-xs text-muted">
            The server binds to 127.0.0.1 by default. Binding to any other address requires a credential.
            {data.password_required && data.auth ? (
              <>
                {" "}
                Sign-in sessions last <span className="mono">{data.auth.session_ttl}</span> and are stored in the 0600 file{" "}
                <span className="mono">{data.auth.auth_file}</span>. Change the password on the host with{" "}
                <span className="mono">clanker vuln auth set-password</span>.
              </>
            ) : (
              <>
                {" "}
                Create a dashboard password with <span className="mono">clanker vuln auth set-password</span> to sign in
                from a browser instead of pasting <span className="mono">CLANKER_GUARD_TOKEN</span>.
              </>
            )}
          </p>
          <Field
            label="API token"
            htmlFor="api-token"
            hint="Only needed without a password sign-in: scripts and the endpoint agent send it as X-Guard-Token. Stored in this browser only."
          >
            <div className="flex gap-2">
              <Input
                id="api-token"
                type="password"
                value={token}
                onChange={(e) => setTokenValue(e.target.value)}
                autoComplete="off"
                placeholder="CLANKER_GUARD_TOKEN value"
              />
              <Button
                onClick={() => {
                  setToken(token);
                  push(token ? "Token saved for this browser" : "Token cleared");
                  reload();
                }}
              >
                Save
              </Button>
            </div>
          </Field>
        </CardBody>
      </Card>

      <Card>
        <CardHeader title="Capabilities in this build" description="What the interface will and will not do" />
        <CardBody>
          <ul className="grid grid-cols-1 gap-2 text-sm sm:grid-cols-2">
            {Object.entries(data.capabilities).map(([key, enabled]) => (
              <li key={key} className="flex items-center justify-between gap-3 rounded-md border border-border px-3 py-2">
                <span className="mono text-xs">{key}</span>
                {enabled ? (
                  <Badge className="border-low/30 bg-low-soft text-low">available</Badge>
                ) : (
                  <Badge className="border-border bg-surface-2 text-muted">not in this build</Badge>
                )}
              </li>
            ))}
          </ul>
        </CardBody>
      </Card>
    </div>
  );
}

function FeedTable({ feeds }: { feeds: FeedResponse["feeds"] }) {
  return (
    <TableWrap>
      <Table caption="Intelligence feed status">
        <thead>
          <tr>
            <Th>Source</Th>
            <Th>Last sync</Th>
            <Th className="text-right">Records</Th>
            <Th>State</Th>
          </tr>
        </thead>
        <tbody>
          {feeds.map((f) => (
            <Tr key={f.source}>
              <Td className="font-medium">{f.source}</Td>
              <Td className="text-xs" title={formatDate(f.last_sync)}>{relativeTime(f.last_sync)}</Td>
              <Td className="num text-right">{f.records.toLocaleString()}</Td>
              <Td>
                {f.stale ? (
                  <Badge className="border-high/30 bg-high-soft text-high">stale</Badge>
                ) : (
                  <Badge className="border-low/30 bg-low-soft text-low">fresh</Badge>
                )}
              </Td>
            </Tr>
          ))}
        </tbody>
      </Table>
    </TableWrap>
  );
}

function InstallCommand({ title, command }: { title: string; command: string }) {
  // "manual" means every clipboard path failed; the text is selected instead so
  // the operator finishes with Ctrl+C instead of wondering why nothing happened.
  const [outcome, setOutcome] = useState<"copied" | "manual" | null>(null);
  const codeRef = useRef<HTMLElement | null>(null);

  return (
    <div className="rounded-md border border-border">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-semibold">{title}</span>
        <CopyButton
          value={command}
          label={`Copy ${title} install command`}
          selectRef={codeRef}
          onOutcome={setOutcome}
        />
      </div>
      {/* The global `pre` rule supplies the gray panel; flush inside the card so
          there is one border, not two. */}
      <pre className="scroll-x m-0 rounded-none border-0 border-t border-border p-3 text-[0.6875rem] leading-relaxed">
        <code ref={codeRef}>{command}</code>
      </pre>
      <p role="status" aria-live="polite" className="px-3 pb-2 text-xs text-muted">
        {outcome === "copied" ? "Copied to the clipboard." : null}
        {outcome === "manual"
          ? "This browser blocks clipboard access over plain HTTP. The command is selected — press Ctrl+C (⌘C)."
          : null}
      </p>
    </div>
  );
}

function ToggleRow({
  id,
  checked,
  onChange,
  label,
  hint,
}: {
  id: string;
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
  hint?: string;
}) {
  return (
    <div className="flex items-start justify-between gap-4">
      <div>
        <label htmlFor={id} className="text-sm font-medium">
          {label}
        </label>
        {hint ? <p id={`${id}-hint`} className="text-xs text-muted">{hint}</p> : null}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} aria-describedby={hint ? `${id}-hint` : undefined} />
    </div>
  );
}

function Row({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/60 pb-1.5">
      <span className="text-muted">{label}</span>
      <span className="text-right font-medium">{value}</span>
    </div>
  );
}

function Count({ label, value }: { label: string; value: number }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-muted">{label}</p>
      <p className="num mt-0.5 text-lg font-semibold">{value.toLocaleString()}</p>
    </div>
  );
}


/**
 * agentStatus is the one thing an operator scans for: is this endpoint reporting,
 * and if not, why. Revoked and stalled agents are visually distinct from healthy
 * ones rather than all rendering the same grey badge.
 */
function agentStatus(agent: EnrolledAgent) {
  if (agent.revoked) return <Badge className="border-critical/30 bg-critical-soft text-critical">revoked</Badge>;
  if (agent.state === "error")
    return <Badge className="border-critical/30 bg-critical-soft text-critical">error</Badge>;
  if (agent.state === "scanning" || agent.state === "reporting")
    return <Badge className="border-accent/40 bg-accent-soft text-accent">{agent.state}</Badge>;
  // "Online" means reachable: the agent is holding a request and can be asked to
  // scan right now. An endpoint with no watcher is unreachable and says so.
  if (agent.online) return <Badge className="border-low/30 bg-low-soft text-low">online</Badge>;
  return <Badge className="border-border bg-surface-2 text-muted">offline</Badge>;
}

/** relativeSeconds renders the server's seconds_since_seen without clock math in the browser. */
function relativeSeconds(seconds?: number): string {
  if (seconds === undefined || Number.isNaN(seconds)) return "unknown";
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/**
 * Operational settings: the jobs that keep the data current and the exits that keep it
 * recoverable. Deliberately small — three numbers and two buttons, all of which do
 * something the server would otherwise only do when a human remembered.
 */
function GeneralOperations() {
  const settings = useAsync(() => api.settings());
  const { push } = useToast();
  const [webhook, setWebhook] = useState("");
  const [secret, setSecret] = useState("");
  const [digestHours, setDigestHours] = useState(24);
  const [refreshHours, setRefreshHours] = useState(24);
  const [saving, setSaving] = useState(false);
  const [busy, setBusy] = useState<string | null>(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const vals = settings.data as unknown as Record<string, unknown> | undefined;
    if (!vals || loaded) return;
    const ops = (vals.operations ?? {}) as Record<string, string>;
    setWebhook(ops["notify.webhook_url"] ?? "");
    setDigestHours(Number(ops["notify.digest_hours"] ?? "24") || 24);
    setRefreshHours(Number(ops["feeds.refresh_hours"] ?? "24") || 24);
    setLoaded(true);
  }, [settings.data, loaded]);

  async function save() {
    setSaving(true);
    try {
      await api.saveSettings({
        operations: {
          "notify.webhook_url": webhook.trim(),
          "notify.webhook_secret": secret.trim(),
          "notify.digest_hours": String(digestHours),
          "feeds.refresh_hours": String(refreshHours),
        },
      });
      push("Operational settings saved");
      settings.reload();
    } catch (err) {
      push(err instanceof Error ? err.message : "Could not save");
    } finally {
      setSaving(false);
    }
  }

  async function runSweep() {
    setBusy("sweep");
    try {
      await api.runMaintenance();
      push("Expired acceptances re-checked, history pruned, digest evaluated");
    } catch (err) {
      push(err instanceof Error ? err.message : "Sweep failed");
    } finally {
      setBusy(null);
    }
  }

  async function backupNow() {
    setBusy("backup");
    try {
      const res = await api.backup();
      push(`Snapshot written: ${res.name}`);
    } catch (err) {
      push(err instanceof Error ? err.message : "Backup failed");
    } finally {
      setBusy(null);
    }
  }

  return (
    <Card className="mt-3">
      <CardHeader
        title="Operations"
        description="Scheduled freshness, the one channel that tells a human work is late, and a tested way to take a copy."
      />
      <CardBody className="space-y-3">
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Notification webhook" htmlFor="ops-webhook" hint="Receives a JSON digest when work is overdue. One message per interval, signed when a secret is set.">
            <Input id="ops-webhook" value={webhook} onChange={(e) => setWebhook(e.target.value)} placeholder="https://hooks.example.com/clanker" />
          </Field>
          <Field label="Webhook signing secret" htmlFor="ops-secret" hint="Optional. Sent as X-Guard-Signature (HMAC-SHA256 of the body).">
            <Input id="ops-secret" type="password" value={secret} onChange={(e) => setSecret(e.target.value)} autoComplete="off" />
          </Field>
          <Field label="Digest interval (hours)" htmlFor="ops-digest">
            <Input id="ops-digest" type="number" min={1} max={168} value={digestHours} onChange={(e) => setDigestHours(Number(e.target.value))} />
          </Field>
          <Field label="Intelligence refresh (hours)" htmlFor="ops-feeds" hint="KEV and EPSS. Priority and SLAs depend on them staying current.">
            <Input id="ops-feeds" type="number" min={1} max={168} value={refreshHours} onChange={(e) => setRefreshHours(Number(e.target.value))} />
          </Field>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Button variant="primary" onClick={save} disabled={saving}>
            {saving ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Check className="h-4 w-4" aria-hidden="true" />}
            Save
          </Button>
          <Button onClick={runSweep} disabled={busy !== null}>
            {busy === "sweep" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <RefreshCw className="h-4 w-4" aria-hidden="true" />}
            Run maintenance now
          </Button>
          <Button onClick={backupNow} disabled={busy !== null}>
            {busy === "backup" ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Check className="h-4 w-4" aria-hidden="true" />}
            Back up database
          </Button>
        </div>
        <p className="text-xs text-muted">
          The backup button needs a backup directory on the server (<span className="mono">--backup-dir</span>). History older
          than the retention window is pruned automatically; work items keep their evidence.
        </p>
      </CardBody>
    </Card>
  );
}
