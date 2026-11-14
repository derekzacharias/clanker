import * as Tabs from "@radix-ui/react-tabs";
import { Check, ClipboardCopy, Loader2, RefreshCw } from "lucide-react";
import { useEffect, useState } from "react";
import { api, ApiError, getToken, setToken, type FeedResponse } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { useQueryParam } from "../lib/router";
import Improvement from "./Improvement";
import { formatDate, relativeTime } from "../lib/format";
import { PageHeader } from "../components/PageHeader";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Banner, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Field, Input, Select } from "../components/ui/Field";
import { Switch } from "../components/ui/Switch";
import { Table, TableWrap, Td, Th, Tr } from "../components/ui/Table";
import { useToast } from "../components/ui/Toast";

export default function Settings() {
  const tabParam = useQueryParam("tab");
  return (
    <div>
      <PageHeader title="Settings" description="Scanner policy, vulnerability intelligence, endpoint agents and access." />
      <Tabs.Root defaultValue={tabParam ?? "general"}>
        <Tabs.List className="mb-3 flex flex-wrap gap-1 border-b border-border" aria-label="Settings sections">
          {[
            ["general", "General"],
            ["intelligence", "Intelligence"],
            ["agents", "Endpoint agents"],
            ["improvement", "Continuous improvement"],
            ["access", "Access"],
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
        </Tabs.Content>
        <Tabs.Content value="intelligence">
          <IntelligenceTab />
        </Tabs.Content>
        <Tabs.Content value="agents">
          <AgentsTab />
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
        <Field label="Failure threshold" hint="Exit code 2 when an actionable finding is at or above this severity.">
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
        <CardBody className="grid gap-2 text-sm sm:grid-cols-3">
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
        <CardBody className="grid gap-2 text-sm sm:grid-cols-2">
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
          description="Copy-and-paste installers verify a published SHA-256 before installing. No service or scheduled task is created."
        />
        <CardBody className="space-y-3">
          {data.install.published ? (
            <div className="grid gap-3 sm:grid-cols-3">
              <InstallCommand title="Linux" command={data.install.commands?.linux ?? ""} />
              <InstallCommand title="macOS" command={data.install.commands?.macos ?? ""} />
              <InstallCommand title="Windows (PowerShell)" command={data.install.commands?.windows ?? ""} />
            </div>
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
            <p className="font-medium text-fg">What the agent collects</p>
            <p className="mt-1">
              Package-manager metadata, OS release information and listening package metadata. No files, credentials or
              documents. Advisory lookups go to api.osv.dev only. Uninstall with{" "}
              <span className="mono">clanker-guard-agent uninstall --yes</span>.
            </p>
          </div>
          <p className="text-xs text-muted">{data.managed_note}</p>
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
              data.token_required ? (
                <Badge className="border-low/30 bg-low-soft text-low">token required</Badge>
              ) : (
                <Badge className="border-border bg-surface-2 text-muted">loopback only</Badge>
              )
            }
          />
          <p className="text-xs text-muted">
            The server binds to 127.0.0.1 by default. Binding to any other address requires
            <span className="mono"> CLANKER_GUARD_TOKEN</span>, which this interface sends as the
            <span className="mono"> X-Guard-Token</span> header.
          </p>
          <Field label="API token" hint="Stored in this browser only. Leave empty for a loopback server.">
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
          <ul className="grid gap-2 text-sm sm:grid-cols-2">
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
  const [copied, setCopied] = useState(false);
  return (
    <div className="rounded-md border border-border">
      <div className="flex items-center justify-between border-b border-border px-3 py-2">
        <span className="text-xs font-semibold">{title}</span>
        <Button
          size="sm"
          variant="ghost"
          onClick={async () => {
            try {
              await navigator.clipboard.writeText(command);
              setCopied(true);
              window.setTimeout(() => setCopied(false), 1500);
            } catch {
              /* clipboard blocked */
            }
          }}
          aria-label={`Copy ${title} install command`}
        >
          {copied ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : <ClipboardCopy className="h-3.5 w-3.5" aria-hidden="true" />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <pre className="scroll-x p-3 text-[0.6875rem] leading-relaxed">
        <code>{command}</code>
      </pre>
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

