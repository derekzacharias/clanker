import { AlertTriangle, CheckCircle2, Laptop, Loader2, Network, Package, XCircle } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { api, ApiError, downloadReportExport, type Job } from "../lib/api";
import { navigate } from "../lib/router";
import { formatDate } from "../lib/format";
import { PageHeader } from "../components/PageHeader";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { Badge } from "../components/ui/Badge";
import { Button } from "../components/ui/Button";
import { Banner, ErrorState } from "../components/ui/Feedback";
import { Field, Input, Select } from "../components/ui/Field";
import { Switch } from "../components/ui/Switch";
import { cn } from "../lib/cn";

type Kind = "local" | "network" | "sbom";
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
  const [scopeFile, setScopeFile] = useState("");
  const [targets, setTargets] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
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

  const canStart = useMemo(() => {
    if (starting) return false;
    if (kind === "local") return true;
    return false; // network/sbom are not implemented in this build
  }, [kind, starting]);

  async function start() {
    setStarting(true);
    setError(null);
    try {
      const created = await api.startScan({
        kind,
        offline,
        include_not_affected: includeNotAffected,
        fail_on: failOn,
        fail_on_kev: failOnKev,
      });
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
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3" role="group" aria-label="Scan type">
          <TypeCard
            selected={kind === "local"}
            onSelect={() => setKind("local")}
            icon={<Laptop className="h-5 w-5" />}
            title="Local Endpoint"
            description="Inventory installed software and the operating system on this machine."
            badge="Available"
          />
          <TypeCard
            selected={kind === "network"}
            onSelect={() => setKind("network")}
            icon={<Network className="h-5 w-5" />}
            title="Network Assessment"
            description="Assess services on explicitly authorised network assets."
            badge="Not in this build"
          />
          <TypeCard
            selected={kind === "sbom"}
            onSelect={() => setKind("sbom")}
            icon={<Package className="h-5 w-5" />}
            title="Software / Container"
            description="Assess dependency manifests, SBOMs or supported container images."
            badge="Not in this build"
          />
        </div>
      ) : null}

      {step === 1 && kind !== "local" ? (
        <div className="mt-3">
          <Banner tone="warn" title={`${kind === "network" ? "Network" : "SBOM"} assessment is not implemented in this build`}>
            {kind === "network" ? (
              <>
                The authorisation gate exists and is enforced: a scope file naming who approved the scan, the exact
                targets, and an expiry is required before any network work. Service discovery and safe validation ship in
                Phase 3. Scanning without an authorised scope would be unsafe, so the option is disabled rather than
                faked.
              </>
            ) : (
              <>
                Inventory already carries package URLs, but the SBOM reader/exporter is on the roadmap. Use{" "}
                <span className="mono">clanker vuln scan --sbom</span> once available.
              </>
            )}
          </Banner>
        </div>
      ) : null}

      {step === 2 && kind !== "local" ? (
        <Card>
          <CardHeader
            title={kind === "network" ? "Configure network assessment" : "Configure SBOM assessment"}
            description="This form documents the real requirements; submission is blocked because the feature is not implemented yet."
          />
          <CardBody className="space-y-4">
            <Banner tone="warn" title="Not available in this build">
              {kind === "network"
                ? "Service discovery, fingerprinting and safe validation ship in Phase 3. The authorisation gate below already exists in the CLI and API."
                : "The SBOM reader is on the roadmap; inventory already produces package URLs, so this is an adapter, not a redesign."}
            </Banner>
            <fieldset disabled className="space-y-3">
              <Field
                label="Authorisation scope file"
                htmlFor="scope-file"
                hint="Names who approved the scan, the exact targets, and the host cap."
              >
                <Input
                  id="scope-file"
                  value={scopeFile}
                  onChange={(e) => setScopeFile(e.target.value)}
                  placeholder="scope.yaml"
                />
              </Field>
              <Field label="Targets" htmlFor="targets" hint="Comma-separated addresses or CIDRs. Must be inside the approved scope.">
                <Input
                  id="targets"
                  value={targets}
                  onChange={(e) => setTargets(e.target.value)}
                  placeholder="192.168.20.10, 192.168.20.0/28"
                />
              </Field>
              <div className="flex items-start gap-2">
                <input
                  id="authorized"
                  type="checkbox"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                  className="mt-1"
                />
                <label htmlFor="authorized" className="text-sm">
                  I am authorised to assess these targets. Scans are read-only and non-destructive, but still require
                  explicit approval.
                </label>
              </div>
            </fieldset>
            <div className="flex justify-end gap-2">
              <Button onClick={() => setStep(1)}>Back</Button>
              <Button variant="primary" disabled>
                Start Scan
              </Button>
            </div>
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

      {step === 3 ? (
        <Card>
          <CardHeader title="Review" description="Confirm what will run." />
          <CardBody className="space-y-3 text-sm">
            <Row label="Scan type" value="Local endpoint" />
            <Row label="Intelligence" value={offline ? "Cached only (offline)" : "OSV online + cached KEV/EPSS"} />
            <Row label="Failure threshold" value={failOn ? `Fail on ${failOn}` : "Never fail (report only)"} />
            <Row label="KEV policy" value={failOnKev ? "Fail on known exploited" : "Report only"} />
            <Row label="Not-affected records" value={includeNotAffected ? "Included" : "Hidden"} />
            {error ? <ErrorState message={error} /> : null}
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
          <Button variant="primary" onClick={() => setStep(step + 1)} disabled={kind !== "local"}>
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
      return "Enriching with KEV / EPSS and scoring risk";
    case "report":
      return "Preparing report";
    default:
      return name;
  }
}
