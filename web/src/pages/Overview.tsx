import { ArrowRight, Radar, ShieldAlert, Server, Sparkles, TriangleAlert } from "lucide-react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { Link, navigate } from "../lib/router";
import { formatDate, pluralize, relativeTime, riskTone } from "../lib/format";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { StatCard } from "../components/StatCard";
import { SeverityBar } from "../components/SeverityBar";
import { SeverityBadge, KevBadge, ApplicabilityBadge } from "../components/badges";
import { Banner, EmptyState, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Button } from "../components/ui/Button";
import { PageHeader } from "../components/PageHeader";

export default function Overview() {
  const { data, error, loading, reload } = useAsync(() => api.overview());

  if (loading && !data) return <LoadingBlock label="Loading security overview" />;
  if (error) return <ErrorState message={error.message} onRetry={reload} />;
  if (!data) return null;

  if (!data.has_data) {
    return (
      <div className="mx-auto max-w-3xl">
        <Card className="mt-6">
          <EmptyState
            icon={<ShieldAlert className="h-5 w-5" />}
            title="Run your first scan"
            description={
              <>
                Clanker Guard will inventory the software installed on this endpoint, correlate it against public
                vulnerability intelligence, and show you what actually applies — with the evidence behind every
                finding.
                <br />
                <br />
                Nothing is measured until you scan, so there are no metrics to show yet.
              </>
            }
            action={
              <Button variant="primary" onClick={() => navigate("/scans/new")}>
                <Radar className="h-4 w-4" aria-hidden="true" /> Run your first scan
              </Button>
            }
          />
        </Card>
      </div>
    );
  }

  const staleFeeds = data.feeds.filter((f) => f.stale);
  return (
    <div className="space-y-4">
      <PageHeader
        title="Security overview"
        description={
          <>
            {pluralize(data.metrics.assets, "asset")} assessed · last scan{" "}
            {relativeTime(data.coverage.last_scan_at)} · {formatDate(data.coverage.last_scan_at)}
          </>
        }
        actions={
          <>
            <Button onClick={() => navigate("/vulnerabilities")}>
              Review findings <ArrowRight className="h-4 w-4" aria-hidden="true" />
            </Button>
            <Button variant="primary" onClick={() => navigate("/scans/new")}>
              <Radar className="h-4 w-4" aria-hidden="true" /> New Scan
            </Button>
          </>
        }
      />

      {staleFeeds.length > 0 ? (
        <Banner tone="warn" title="Vulnerability intelligence is stale">
          {staleFeeds.map((f) => `${f.source} last synced ${relativeTime(f.last_sync)}`).join(" · ")}. Findings may be
          incomplete until the feeds are refreshed.{" "}
          <Link to="/settings?tab=intelligence" className="text-accent underline-offset-2 hover:underline">
            Update intelligence
          </Link>
        </Banner>
      ) : null}

      {data.metrics.needs_investigation > 0 ? (
        <Banner tone="info" title={`${data.metrics.needs_investigation} finding(s) need investigation`}>
          These matched an advisory but the evidence is incomplete or conflicting (often a vendor backport or a
          third-party build). They are excluded from the actionable count until confirmed.
        </Banner>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Assets" value={data.metrics.assets} hint={`${data.coverage.assessed} with a completed scan`} icon={<Server className="h-4 w-4" />} />
        <StatCard label="Critical" value={data.metrics.critical} tone="critical" hint="Confirmed or probable" icon={<ShieldAlert className="h-4 w-4" />} />
        <StatCard label="High" value={data.metrics.high} tone="high" hint="Confirmed or probable" icon={<TriangleAlert className="h-4 w-4" />} />
        <StatCard label="Known exploited" value={data.metrics.kev} tone={data.metrics.kev > 0 ? "critical" : "default"} hint="CISA KEV membership" icon={<Sparkles className="h-4 w-4" />} />
      </div>

      <div className="grid gap-3 xl:grid-cols-3">
        <Card className="xl:col-span-2">
          <CardHeader
            title="Priority findings"
            description="Ranked by the backend risk model: KEV, EPSS, severity, exposure, confidence and fix availability."
            actions={
              <Link to="/vulnerabilities" className="text-xs text-accent hover:underline">
                View all
              </Link>
            }
          />
          <CardBody className="p-0">
            {data.priority.length === 0 ? (
              <p className="p-4 text-sm text-muted">
                No actionable findings in the assessed scope. This is not proof the environment is secure — review
                coverage below.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {data.priority.map((f) => (
                  <li key={f.id}>
                    <Link
                      to={`/vulnerabilities?q=${encodeURIComponent(f.cve)}`}
                      className="flex flex-wrap items-center gap-x-3 gap-y-1.5 px-4 py-3 hover:bg-surface-2"
                    >
                      <span className="mono text-xs text-muted">{f.asset}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-medium">
                          {f.product} <span className="mono text-xs text-muted">{f.installed_version}</span>
                        </span>
                        <span className="mono text-xs text-muted">{f.cve}</span>
                      </span>
                      <SeverityBadge severity={f.severity} />
                      {f.kev ? <KevBadge ransomware={f.kev_ransomware} /> : null}
                      <ApplicabilityBadge value={f.affected} />
                      <span className={`num text-sm font-semibold ${riskTone(f.risk_score)}`}>{f.risk_score.toFixed(1)}</span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        <div className="space-y-3">
          <Card>
            <CardHeader title="Severity distribution" />
            <CardBody>
              <SeverityBar rows={data.severity} />
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Scan coverage" />
            <CardBody className="space-y-2 text-sm">
              <Row label="Assets assessed" value={String(data.coverage.assessed)} />
              <Row label={`Not scanned in ${data.coverage.stale_after_days} days`} value={String(data.coverage.stale)} />
              <Row label="Failed assessments (24 h)" value={String(data.coverage.failed_recent)} />
              <Row label="Latest completed" value={formatDate(data.coverage.last_scan_at)} />
            </CardBody>
          </Card>

          <Card>
            <CardHeader title="Recent activity" />
            <CardBody className="p-0">
              {data.activity.length === 0 ? (
                <p className="p-4 text-sm text-muted">No scans recorded yet.</p>
              ) : (
                <ul className="divide-y divide-border">
                  {data.activity.slice(0, 6).map((a) => (
                    <li key={a.id + a.finished_at} className="flex items-center justify-between gap-3 px-4 py-2.5 text-sm">
                      <span className="min-w-0">
                        <span className="block truncate">{a.host || a.kind}</span>
                        <span className="text-xs text-muted">
                          {a.status}
                          {a.findings !== undefined ? ` · ${a.findings} findings` : ""}
                        </span>
                      </span>
                      <span className="shrink-0 text-xs text-muted">{relativeTime(a.finished_at)}</span>
                    </li>
                  ))}
                </ul>
              )}
            </CardBody>
          </Card>
        </div>
      </div>

      <Card>
        <CardHeader
          title="Coverage limitations"
          description="What this assessment did not check. Findings lists are only meaningful next to these limits."
        />
        <CardBody>
          <ul className="list-disc space-y-1 pl-5 text-sm text-muted">
            {(data.limitations.length ? data.limitations : ["No limitations reported."]).map((l) => (
              <li key={l}>{l}</li>
            ))}
          </ul>
          {data.errors.length > 0 ? (
            <div className="mt-3">
              <h3 className="text-xs font-semibold uppercase tracking-wide text-muted">Degraded coverage</h3>
              <ul className="mt-1 space-y-1 text-sm text-high">
                {data.errors.map((e) => (
                  <li key={e}>{e}</li>
                ))}
              </ul>
            </div>
          ) : null}
        </CardBody>
      </Card>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-baseline justify-between gap-3">
      <span className="text-muted">{label}</span>
      <span className="num font-medium">{value}</span>
    </div>
  );
}
