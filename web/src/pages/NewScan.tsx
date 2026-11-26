import { AlertTriangle, CheckCircle2, Laptop, Loader2, MonitorSmartphone, Network, Package, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, ApiError, downloadReportExport, type EnrolledAgent, type Job } from "../lib/api";
import { navigate } from "../lib/router";
import { formatDate } from "../lib/format";
import { PageHeader } from "../components/PageHeader";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Banner, ErrorState } from "../components/ui/Feedback";
import { Field, Input, Select } from "../components/ui/Field";
import { CopyButton } from "../components/ui/CopyButton";
import { Switch } from "../components/ui/Switch";
import { cn } from "../lib/cn";

type Kind = "local" | "network" | "sbom" | "agents";
type SbomSource = "document" | "image";

const SCOPE_TEMPLATE = `name: my-scope
authorized_by: your name
authorized_at: ${new Date().toISOString()}
expires_at: ${new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString()}
targets:
  - 127.0.0.1
ports: [22, 80, 443]
max_hosts: 8
allow_public_addresses: false`;
type Stage = { name: string; percent: number };

const STAGES: Stage[] = [
  { name: "discovery", percent: 10 },
  { name: "inventory", percent: 30 },
  { name: "intelligence", percent: 60 },
  { name: "matching", percent: 75 },
  { name: "enrichment", percent: 85 },
  { name: "report", percent: 92 },
  { name: "done", percent: 100 },
];

export default function NewScan() {
  const [step, setStep] = useState(1);
  const [kind, setKind] = useState<Kind>("local");
  const [offline, setOffline] = useState(false);
  const [includeNotAffected, setIncludeNotAffected] = useState(false);
  const [failOn, setFailOn] = useState("high");
  const [failOnKev, setFailOnKev] = useState(false);
  const [scopeYaml, setScopeYaml] = useState(SCOPE_TEMPLATE);
  const [targets, setTargets] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [sbomSource, setSbomSource] = useState<SbomSource>("document");
  const [sbomPath, setSbomPath] = useState("");
  const [imageRef, setImageRef] = useState("");
  const [job, setJob] = useState<Job | null>(null);
  // Endpoint Scan: the agents already installed elsewhere. Work is queued here and
  // pulled by the agent, so this page never opens a connection to an endpoint.
  const [agents, setAgents] = useState<EnrolledAgent[] | null>(null);
  const [agentError, setAgentError] = useState<string | null>(null);
  const [selectedAgents, setSelectedAgents] = useState<string[]>([]);
  const [queued, setQueued] = useState<string[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);

  // Poll the job while it runs. No fake percentages: values come from the server.
  useEffect(() => {
    if (!job || job.status === "completed" || job.status === "failed" || job.status === "canceled") return;
    const timer = window.setInterval(async () => {
      try {
        const detail = await api.scan(job.id);
        if (detail.job) setJob(detail.job);
      } catch {
        /* transient poll failure: keep trying */
      }
    }, 900);
    return () => window.clearInterval(timer);
  }, [job]);

  useEffect(() => {
    if (kind !== "agents" || agents !== null) return;
    let cancelled = false;
    api
      .agents()
      .then((res) => {
        if (!cancelled) setAgents(res.fleet?.enrolled ?? []);
      })
      .catch((err: unknown) => {
        if (!cancelled) setAgentError(err instanceof Error ? err.message : "Could not load the enrolled endpoints.");
      });
    return () => {
      cancelled = true;
    };
  }, [kind, agents]);

  const canStart = useMemo(() => {
    if (starting) return false;
    if (kind === "local") return true;
    if (kind === "network") return authorized && scopeYaml.trim().length > 0;
    if (kind === "agents") return selectedAgents.length > 0;
    return sbomSource === "document" ? sbomPath.trim().length > 0 : imageRef.trim().length > 0;
  }, [kind, starting, authorized, scopeYaml, sbomSource, sbomPath, imageRef, selectedAgents]);

  async function start() {
    setStarting(true);
    setError(null);
    if (kind === "agents") {
      try {
        const accepted: string[] = [];
        for (const id of selectedAgents) {
          await api.queueAgentScan(id);
          accepted.push(id);
        }
        setQueued(accepted);
      } catch (err) {
        setError(err instanceof ApiError ? err.message : String(err));
      } finally {
        setStarting(false);
      }
      return;
    }
    try {
      const body: Parameters<typeof api.startScan>[0] = {
        kind,
        offline,
        include_not_affected: includeNotAffected,
        fail_on: failOn,
        fail_on_kev: failOnKev,
      };
      if (kind === "network") {
        body.authorized = authorized;
        body.scope_yaml = scopeYaml;
        body.targets = targets
          .split(",")
          .map((t) => t.trim())
          .filter(Boolean);
      }
      if (kind === "sbom") {
        if (sbomSource === "document") body.sbom_path = sbomPath.trim();
        else body.image = imageRef.trim();
      }
      const created = await api.startScan(body);
      setJob(created);
    } catch (err) {
      const msg = err instanceof ApiError ? err.message : String(err);
      setError(msg);
    } finally {
      setStarting(false);
    }
  }

  async function cancel() {
    if (!job) return;
    try {
      await api.cancelScan(job.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  if (queued) {
    return <QueuedScans ids={queued} onNew={() => { setQueued(null); setSelectedAgents([]); setStep(1); }} />;
  }

  if (job) {
    return <ScanProgress job={job} onCancel={cancel} error={error} />;
  }

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader
        title="New scan"
        description="Three steps: choose what to assess, configure it, review. Nothing runs until you confirm."
      />

      <ol className="mb-4 flex flex-wrap items-center gap-2 text-sm" aria-label="Scan setup steps">
        {["Choose scan type", "Configure", "Review"].map((label, i) => {
          const n = i + 1;
          return (
            <li key={label} className="flex items-center gap-2">
              <span
                aria-current={step === n ? "step" : undefined}
                className={cn(
                  "flex items-center gap-2 rounded-full border px-3 py-1",
                  step === n ? "border-accent bg-accent-soft font-medium text-accent" : "border-border text-muted",
                )}
              >
                <span className="num" aria-hidden="true">{n}</span>
                {label}
              </span>
              {n < 3 ? <span className="text-subtle" aria-hidden="true">→</span> : null}
            </li>
          );
        })}
      </ol>

      {step === 1 ? (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4" role="group" aria-label="Scan type">
          <TypeCard
            selected={kind === "local"}
            onSelect={() => setKind("local")}
            icon={<Laptop className="h-5 w-5" />}
            title="Local System"
            description="Inventory installed software and the operating system on this machine."
            badge="No privileges needed"
          />
          <TypeCard
            selected={kind === "network"}
            onSelect={() => setKind("network")}
            icon={<Network className="h-5 w-5" />}
            title="Network Assessment"
            description="Assess services on explicitly authorised network assets."
            badge="Requires a scope"
          />
          <TypeCard
            selected={kind === "sbom"}
            onSelect={() => setKind("sbom")}
            icon={<Package className="h-5 w-5" />}
            title="Software / Container"
            description="Assess dependency manifests, SBOMs or supported container images."
            badge="CycloneDX · SPDX · manifests"
          />
          <TypeCard
            selected={kind === "agents"}
            onSelect={() => setKind("agents")}
            icon={<MonitorSmartphone className="h-5 w-5" />}
            title="Endpoint Scan"
            description="Ask enrolled agents on other machines to assess themselves."
            badge="Agent pull · no inbound connection"
          />
        </div>
      ) : null}

      {step === 2 && kind === "network" ? (
        <Card>
          <CardHeader
            title="Authorise a network assessment"
            description="Discovery uses TCP connect, fingerprinting uses one benign request per service, and nothing is exploited."
          />
          <CardBody className="space-y-4">
            <Banner tone="warn" title="Only scan what you are authorised to scan">
              The scope below records who approved this assessment, which targets are in scope, and when the approval
              expires. Targets outside it are refused by the scanner, not by this form.
            </Banner>
            <Field
              label="Scope document (YAML)"
              htmlFor="scope-yaml"
              hint="name, authorized_by, authorized_at, expires_at, targets, ports, max_hosts"
            >
              <textarea
                id="scope-yaml"
                value={scopeYaml}
                onChange={(e) => setScopeYaml(e.target.value)}
                rows={12}
                spellCheck={false}
                className="mono w-full rounded-md border border-border-strong bg-surface px-2.5 py-2 text-xs"
              />
            </Field>
            <Field
              label="Targets (optional)"
              htmlFor="targets"
              hint="Comma-separated addresses or hostnames, must already be inside the scope. Leave empty to use the scope list."
            >
              <Input id="targets" value={targets} onChange={(e) => setTargets(e.target.value)} placeholder="192.168.20.10" />
            </Field>
            <div className="flex items-start gap-2">
              <input
                id="authorized"
                type="checkbox"
                checked={authorized}
                onChange={(e) => setAuthorized(e.target.checked)}
                className="mt-1 h-4 w-4"
              />
              <label htmlFor="authorized" className="text-sm">
                I confirm I am authorised to assess these targets. Scans are read-only and non-destructive, but they do
                contact the services.
              </label>
            </div>
          </CardBody>
        </Card>
      ) : null}

      {step === 2 && kind === "sbom" ? (
        <Card>
          <CardHeader
            title="Assess software or a container image"
            description="Documents are parsed, never executed. Images are read with docker save; the image is never run."
          />
          <CardBody className="space-y-4">
            <div className="flex flex-wrap gap-2" role="radiogroup" aria-label="Software source">
              {[
                ["document", "SBOM or manifest"],
                ["image", "Container image"],
              ].map(([value, label]) => (
                <button
                  key={value}
                  type="button"
                  role="radio"
                  aria-checked={sbomSource === value}
                  onClick={() => setSbomSource(value as SbomSource)}
                  className={
                    sbomSource === value
                      ? "rounded-md border border-accent bg-accent-soft px-3 py-1.5 text-sm font-medium text-accent"
                      : "rounded-md border border-border px-3 py-1.5 text-sm text-muted hover:bg-surface-2"
                  }
                >
                  {label}
                </button>
              ))}
            </div>

            {sbomSource === "document" ? (
              <Field
                label="Document path on the server"
                htmlFor="sbom-path"
                hint="CycloneDX, SPDX or Syft JSON, package-lock.json, requirements.txt, go.sum, Cargo.lock, composer.lock or Gemfile.lock."
              >
                <Input
                  id="sbom-path"
                  value={sbomPath}
                  onChange={(e) => setSbomPath(e.target.value)}
                  placeholder="/home/you/project/sbom.json"
                />
              </Field>
            ) : (
              <Field
                label="Container image"
                htmlFor="image-ref"
                hint="The image must exist on the server's Docker daemon. Layers are read with docker save."
              >
                <Input
                  id="image-ref"
                  value={imageRef}
                  onChange={(e) => setImageRef(e.target.value)}
                  placeholder="ghcr.io/acme/api:1.4.0"
                />
              </Field>
            )}

            <Banner tone="info" title="What this checks">
              Components are correlated against public advisory data using their package URLs. Versions that are not
              declared in the document cannot be assessed, and the report lists them as gaps.
            </Banner>

          </CardBody>
        </Card>
      ) : null}

      {step === 2 && kind === "local" ? (
        <Card>
          <CardHeader title="Configure local assessment" description="Defaults are safe: read-only, unprivileged, no uploads." />
          <CardBody className="space-y-4">
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
              <Field
                label="Failure threshold"
                htmlFor="fail-on"
                hint="Sets the report policy and scan exit code. Does not change detection."
              >
                <Select id="fail-on" value={failOn} onChange={(e) => setFailOn(e.target.value)}>
                  <option value="">Never fail (report only)</option>
                  <option value="critical">Fail on critical</option>
                  <option value="high">Fail on high or worse</option>
                  <option value="medium">Fail on medium or worse</option>
                  <option value="low">Fail on any severity</option>
                </Select>
              </Field>
              <div className="space-y-3">
                <SwitchRow
                  id="fail-kev"
                  checked={failOnKev}
                  onChange={setFailOnKev}
                  label="Fail when a known-exploited (KEV) finding is actionable"
                />
                <SwitchRow
                  id="include-na"
                  checked={includeNotAffected}
                  onChange={setIncludeNotAffected}
                  label="Include checked-and-not-affected records"
                  hint="Useful for false-positive review; makes reports larger."
                />
              </div>
            </div>

            <SwitchRow
              id="offline"
              checked={offline}
              onChange={setOffline}
              label="Use cached intelligence only (offline)"
              hint="No network calls. Requires a populated cache (Settings → Intelligence)."
            />

            <Banner tone="info" title="What this collects">
              Package-manager metadata only: dpkg/rpm/apk, Python dist-info, npm globals and Ruby gems, plus OS release
              information. No files, credentials, documents or environment variables. No data leaves the host except
              advisory lookups to <span className="mono">api.osv.dev</span>.
            </Banner>
          </CardBody>
        </Card>
      ) : null}

      {step === 2 && kind === "agents" ? (
        <Card>
          <CardHeader
            title="Choose endpoints to scan"
            description="Enrolled agents. Each pulls the request at its next check-in, so no inbound connection is opened to the endpoint."
          />
          <CardBody className="space-y-3">
            {agentError ? <ErrorState message={agentError} /> : null}
            {agents === null && !agentError ? (
              <p role="status" className="text-sm text-muted">
                Loading enrolled endpoints…
              </p>
            ) : null}
            {agents && agents.length === 0 ? (
              <Banner tone="warn" title="No endpoints are enrolled yet">
                Install the agent on an endpoint first — Settings → Agents has a copy-and-paste command that enrolls it and
                reports back. Until then there is nothing to scan from here.
              </Banner>
            ) : null}
            {agents && agents.length > 0 ? (
              <ul className="space-y-2">
                {agents.map((agent) => {
                  const checked = selectedAgents.includes(agent.id);
                  return (
                    <li
                      key={agent.id}
                      className={cn(
                        "rounded-md border p-3",
                        agent.revoked ? "border-border opacity-60" : "border-border-strong",
                      )}
                    >
                      <label className="flex items-start gap-2.5">
                        <input
                          type="checkbox"
                          className="mt-1"
                          checked={checked}
                          disabled={agent.revoked}
                          onChange={(e) =>
                            setSelectedAgents((cur) =>
                              e.target.checked ? [...cur, agent.id] : cur.filter((x) => x !== agent.id),
                            )
                          }
                          aria-describedby={`agent-${agent.id}-state`}
                        />
                        <span>
                          <span className="mono text-sm">{agent.host}</span>
                          {agent.os ? <span className="ml-2 text-xs text-muted">{agent.os}</span> : null}
                          <span id={`agent-${agent.id}-state`} className="mt-0.5 block text-xs text-muted">
                            {agent.revoked
                              ? "revoked — cannot be asked to scan"
                              : agent.online
                                ? `online — the scan starts immediately${agent.findings ? ` · ${agent.findings} findings` : ""}`
                                : "offline (unreachable) — the scan is queued until it reconnects"}
                          </span>
                        </span>
                      </label>
                    </li>
                  );
                })}
              </ul>
            ) : null}
            <Banner tone="info" title="How this works">
              An endpoint that is <span className="font-medium">online</span> is holding a claim request
              (<span className="mono">clanker-guard-agent watch</span>), so the scan starts the moment you confirm it. One
              that is <span className="font-medium">offline</span> is unreachable; the request waits and runs as soon as it
              reconnects. The server never connects to the endpoint itself.
            </Banner>
          </CardBody>
        </Card>
      ) : null}

      {step === 3 ? (
        <Card>
          <CardHeader title="Review" description="Confirm what will run." />
          <CardBody className="space-y-3 text-sm">
            <Row
              label="Scan type"
              value={
                kind === "local"
                  ? "Local system"
                  : kind === "network"
                    ? "Network assessment"
                    : kind === "sbom"
                      ? "Software / container"
                      : "Endpoint scan"
              }
            />
            {kind === "agents" ? (
              <Row
                label="Endpoints"
                value={
                  (agents ?? [])
                    .filter((a) => selectedAgents.includes(a.id))
                    .map((a) => a.host)
                    .join(", ") || "none selected"
                }
              />
            ) : null}
            {kind === "network" ? (
              <>
                <Row label="Authorised by" value={scopeYaml.match(/authorized_by:\s*(.+)/)?.[1]?.trim() || "not set"} />
                <Row label="Scope name" value={scopeYaml.match(/^name:\s*(.+)$/m)?.[1]?.trim() || "not set"} />
                <Row label="Targets" value={targets.trim() || scopeYaml.match(/targets:\s*\n\s*-\s*(.+)/)?.[1]?.trim() || "not set"} />
                <Row label="Authorisation acknowledged" value={authorized ? "yes" : "NO — required"} />
              </>
            ) : null}
            {kind === "sbom" ? (
              <Row
                label={sbomSource === "document" ? "Document" : "Container image"}
                value={sbomSource === "document" ? sbomPath.trim() || "not set" : imageRef.trim() || "not set"}
              />
            ) : null}
            <Row label="Intelligence" value={offline ? "Cached only (offline)" : "OSV online + cached KEV/EPSS"} />
            <Row label="Failure threshold" value={failOn ? `Fail on ${failOn}` : "Never fail (report only)"} />
            <Row label="KEV policy" value={failOnKev ? "Fail on known exploited" : "Report only"} />
            <Row label="Not-affected records" value={includeNotAffected ? "Included" : "Hidden"} />
            {error ? <ErrorState message={error} /> : null}
            {!canStart ? (
              <p className="text-xs text-high">
                {kind === "network"
                  ? "Confirm the authorisation checkbox to start."
                  : kind === "sbom"
                    ? "Enter a document path or an image reference to start."
                    : ""}
              </p>
            ) : null}
            <div className="flex justify-end gap-2 pt-2">
              <Button onClick={() => setStep(2)}>Back</Button>
              <Button variant="primary" onClick={start} disabled={!canStart}>
                {starting ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : null}
                Start Scan
              </Button>
            </div>
          </CardBody>
        </Card>
      ) : null}

      {step < 3 ? (
        <div className="mt-4 flex justify-between">
          <Button variant="ghost" onClick={() => (step === 1 ? navigate("/") : setStep(step - 1))}>
            {step === 1 ? "Cancel" : "Back"}
          </Button>
          <Button variant="primary" onClick={() => setStep(step + 1)} disabled={starting}>
            Continue
          </Button>
        </div>
      ) : null}
    </div>
  );
}

function TypeCard({
  selected,
  onSelect,
  icon,
  title,
  description,
  badge,
  disabled,
}: {
  selected: boolean;
  onSelect: () => void;
  icon: React.ReactNode;
  title: string;
  description: string;
  badge?: string;
  disabled?: boolean;
}) {
  return (
    <button
      type="button"
      onClick={onSelect}
      disabled={disabled}
      aria-pressed={selected}
      className={cn(
        "card p-4 text-left transition-colors",
        selected && "border-accent ring-1 ring-accent/40",
        disabled ? "cursor-not-allowed opacity-70" : "hover:border-accent/60",
      )}
    >
      <div className="flex items-center justify-between">
        <span className="text-accent" aria-hidden="true">
          {icon}
        </span>
        {badge ? (
          <Badge className={disabled ? "border-border bg-surface-2 text-muted" : "border-low/30 bg-low-soft text-low"}>
            {badge}
          </Badge>
        ) : null}
      </div>
      <p className="mt-3 text-sm font-semibold">{title}</p>
      <p className="mt-1 text-xs text-muted">{description}</p>
    </button>
  );
}

function SwitchRow({
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
        {hint ? <p className="text-xs text-muted">{hint}</p> : null}
      </div>
      <Switch id={id} checked={checked} onCheckedChange={onChange} aria-describedby={hint ? `${id}-hint` : undefined} />
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3 border-b border-border/60 pb-2">
      <span className="text-muted">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}

function ScanProgress({ job, onCancel, error }: { job: Job; onCancel: () => void; error: string | null }) {
  const running = job.status === "running" || job.status === "queued";
  const currentIndex = Math.max(
    0,
    STAGES.findIndex((s) => s.name === job.stage),
  );

  return (
    <div className="mx-auto max-w-3xl space-y-4">
      <PageHeader
        title={running ? "Assessment running" : job.status === "completed" ? "Assessment complete" : "Assessment stopped"}
        description={
          <>
            Job <span className="mono">{job.id}</span> · started {formatDate(job.started_at)}
          </>
        }
        actions={
          running ? (
            <Button variant="danger" onClick={onCancel}>
              <XCircle className="h-4 w-4" aria-hidden="true" /> Cancel scan
            </Button>
          ) : null
        }
      />

      <Card>
        <CardBody className="space-y-4">
          <div>
            <div className="mb-1 flex items-center justify-between text-sm">
              <span className="font-medium">
                {running ? "Working…" : job.status === "completed" ? "Finished" : job.status}
                {job.stage_detail ? <span className="ml-2 font-normal text-muted">{job.stage_detail}</span> : null}
              </span>
              <span className="num text-muted">{job.percent}%</span>
            </div>
            <div
              className="h-2 w-full overflow-hidden rounded-full bg-surface-3"
              role="progressbar"
              aria-valuenow={job.percent}
              aria-valuemin={0}
              aria-valuemax={100}
              aria-label="Scan progress"
            >
              <div className="h-full bg-accent transition-[width] duration-500" style={{ width: `${job.percent}%` }} />
            </div>
            <p className="mt-1 text-xs text-muted">
              Percentages are stage-based, not time estimates: advisory lookups dominate the runtime and cannot be
              predicted reliably.
            </p>
          </div>

          <ol className="space-y-1.5 text-sm">
            {STAGES.filter((s) => s.name !== "done").map((s, i) => {
              const done = job.status === "completed" || i < currentIndex;
              const active = i === currentIndex && running;
              return (
                <li key={s.name} className="flex items-center gap-2">
                  {done ? (
                    <CheckCircle2 className="h-4 w-4 text-low" aria-hidden="true" />
                  ) : active ? (
                    <Loader2 className="h-4 w-4 animate-spin text-accent" aria-hidden="true" />
                  ) : (
                    <span className="h-4 w-4 rounded-full border border-border" aria-hidden="true" />
                  )}
                  <span className={done ? "text-fg" : active ? "font-medium" : "text-muted"}>
                    {stageLabel(s.name)}
                  </span>
                </li>
              );
            })}
          </ol>

          {job.status === "failed" ? (
            <Banner tone="danger" title="The assessment failed">
              <p>{job.error || "No error detail was recorded."}</p>
              <p className="mt-1">
                Partial work may have completed. Fix the cause and retry; findings from this run are not included in
                reports.
              </p>
              <div className="mt-2 flex gap-2">
                <Button size="sm" onClick={() => navigate("/scans/new")}>Retry</Button>
                <Button size="sm" variant="ghost" onClick={() => navigate("/scans")}>Scan history</Button>
              </div>
            </Banner>
          ) : null}

          {job.status === "canceled" ? (
            <Banner tone="warn" title="Scan canceled">
              The assessment stopped before producing a report. Nothing was recorded as a finding.
              <div className="mt-2">
                <Button size="sm" onClick={() => navigate("/scans/new")}>Start another scan</Button>
              </div>
            </Banner>
          ) : null}

          {job.status === "completed" && job.report_id ? (
            <Banner tone="success" title="Report ready">
              <div className="mt-1 flex flex-wrap gap-2">
                <Button size="sm" onClick={() => navigate(`/reports/${encodeURIComponent(job.report_id!)}`)}>
                  View report
                </Button>
                <Button size="sm" variant="ghost" onClick={() => navigate("/vulnerabilities")}>
                  Review findings
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => void downloadReportExport(job.report_id!, "markdown")}
                >
                  Download Markdown
                </Button>
              </div>
            </Banner>
          ) : null}

          {error ? <ErrorState message={error} /> : null}

          {running ? (
            <p className="flex items-center gap-2 text-xs text-muted">
              <AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" />
              You can leave this page; the scan continues on the server and appears under Scans.
            </p>
          ) : null}
        </CardBody>
      </Card>
    </div>
  );
}

function stageLabel(name: string): string {
  switch (name) {
    case "discovery":
      return "Discovering asset and operating system";
    case "inventory":
      return "Collecting installed software";
    case "intelligence":
      return "Querying vulnerability intelligence";
    case "matching":
      return "Matching advisories and deciding applicability";
    case "enrichment":
      return "Checking which vulnerabilities are known to be exploited, and scoring risk";
    case "report":
      return "Preparing report";
    default:
      return name;
  }
}

/**
 * QueuedScans shows what the server was asked for and whether each endpoint has
 * picked it up. Work is pull-based, so "queued" can last as long as the agent is
 * offline; the panel says that instead of showing a progress bar that never moves.
 */
function QueuedScans({ ids, onNew }: { ids: string[]; onNew: () => void }) {
  const [agents, setAgents] = useState<EnrolledAgent[] | null>(null);
  const [cancelling, setCancelling] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const res = await api.agents();
        if (!cancelled) setAgents(res.fleet?.enrolled ?? []);
      } catch {
        /* keep showing the last known state */
      }
    };
    void load();
    const timer = window.setInterval(load, 4000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const rows = ids
    .map((id) => (agents ?? []).find((a) => a.id === id))
    .filter((a): a is EnrolledAgent => Boolean(a));
  const pending = rows.some((a) => !a.task || a.task.status === "queued" || a.task.status === "running");

  return (
    <div className="mx-auto max-w-2xl space-y-4">
      <PageHeader
        title="Endpoint scan queued"
        description="Scans start as soon as the request reaches a reachable endpoint; it uploads the report itself."
      />
      <Card>
        <CardBody className="space-y-3">
          {rows.length === 0 ? (
            <p className="text-sm text-muted">Waiting for the endpoint state…</p>
          ) : (
            <ul className="space-y-2 text-sm">
              {rows.map((agent) => {
                const status = agent.task?.status ?? "queued";
                const tone =
                  status === "done"
                    ? "border-low/30 bg-low-soft text-low"
                    : status === "failed"
                      ? "border-critical/30 bg-critical-soft text-critical"
                      : "border-accent/40 bg-accent-soft text-accent";
                return (
                  <li key={agent.id} className="flex flex-wrap items-center justify-between gap-2 rounded-md border border-border px-3 py-2">
                    <span>
                      <span className="mono text-sm">{agent.host}</span>
                      <span className="ml-2 text-xs text-muted">
                        {status === "queued" && !agent.online
                          ? "endpoint unreachable — queued until it reconnects"
                          : status === "queued"
                            ? "dispatched — starting now"
                            : status === "running"
                              ? `scanning${agent.phase ? ` · ${agent.phase}` : ""}`
                              : status === "done"
                                ? `report ${agent.task?.report_id ?? "received"}`
                                : agent.task?.note || "scan failed"}
                      </span>
                    </span>
                    <span className="flex items-center gap-2">
                      {status === "queued" && !agent.watching ? (
                        <CopyButton value="clanker-guard-agent watch" label="Copy the command that makes this endpoint reachable" />
                      ) : null}
                      {status === "queued" ? (
                        <Button
                          size="sm"
                          variant="ghost"
                          disabled={cancelling === agent.id}
                          onClick={async () => {
                            setCancelling(agent.id);
                            try {
                              await api.cancelAgentScan(agent.id);
                            } catch {
                              /* nothing queued any more: the list refresh shows it */
                            } finally {
                              setCancelling(null);
                            }
                          }}
                        >
                          Cancel request
                        </Button>
                      ) : null}
                      <Badge className={tone}>{status}</Badge>
                    </span>
                  </li>
                );
              })}
            </ul>
          )}
          <p className="text-xs text-muted">
            {pending
              ? "A reachable endpoint starts the scan immediately. An unreachable one has no agent listening for work: run `clanker-guard-agent watch` on it (copy the command above) and the request starts the moment it connects."
              : "Finished. The reports are in Reports and the findings are in Vulnerabilities."}
          </p>
          <div className="flex justify-end gap-2">
            <Button onClick={() => navigate("/settings?tab=agents")}>Agent status</Button>
            <Button variant="primary" onClick={onNew}>
              New scan
            </Button>
          </div>
        </CardBody>
      </Card>
    </div>
  );
}
