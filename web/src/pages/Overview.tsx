import { ArrowRight, Radar, ShieldAlert, Timer, TriangleAlert, Users } from "lucide-react";
import { api } from "../lib/api";
import { useAsync } from "../lib/useApi";
import { Link, navigate } from "../lib/router";
import { formatDate, pluralize, relativeTime, riskTone } from "../lib/format";
import { Card, CardBody, CardHeader } from "../components/ui/Card";
import { SeverityBadge, KevBadge, ApplicabilityBadge } from "../components/badges";
import { Banner, EmptyState, ErrorState, LoadingBlock } from "../components/ui/Feedback";
import { Button } from "../components/ui/Button";
import { PageHeader } from "../components/PageHeader";
import { ProcessStrip, type ProcessStep } from "../components/ProcessStrip";
import { MetricCard } from "../components/MetricCard";
import { SeverityDonut } from "../components/charts/SeverityDonut";
import { AgingBars } from "../components/charts/AgingBars";
import { Collapsible } from "../components/ui/Collapsible";
import { InfoTooltip } from "../components/ui/InfoTooltip";

/**
 * The landing screen answers four questions in order, and nothing else:
 *
 *   1. What is my posture?        one sentence, with the numbers behind it
 *   2. What needs attention?      a short list of things that are wrong *now*
 *   3. What do I do next?         one primary action, derived from the data
 *   4. Is it getting better?      ageing and time-to-fix, not a wall of statistics
 *
 * Everything that does not support one of those decisions moved into the "Technical detail"
 * disclosure at the bottom (severity split, coverage, limitations) or onto its own screen.
 */
export default function Overview() {

  const overview = useAsync(() => api.overview());
  const remediation = useAsync(() => api.remediationSummary());
  const metrics = useAsync(() => api.metrics());
  const groups = useAsync(() => api.remediationGroups());

  const loading = (overview.loading && !overview.data) || (remediation.loading && !remediation.data);
  if (loading) return <LoadingBlock label="Loading security overview" />;
  if (overview.error) return <ErrorState message={overview.error.message} onRetry={overview.reload} />;
  if (!overview.data) return null;

  const data = overview.data;
  if (!data.has_data) {
    return (
      <div className="mx-auto max-w-3xl">
        <Card className="mt-6">
          <EmptyState
            icon={<ShieldAlert className="h-5 w-5" />}
            title="Run your first scan"
            description={
              <>
                Clanker Guard inventories the software on an endpoint, correlates it against public vulnerability
                intelligence, and shows what actually applies — with the evidence behind every finding.
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

  const errors = data.errors ?? [];
  const limitations = data.limitations ?? [];
  const priority = data.priority ?? [];
  const feeds = data.feeds ?? [];
  const severity = data.severity ?? [];
  const staleFeeds = feeds.filter((f) => f.stale);
  const sum = remediation.data?.summary;
  const m = metrics.data;

  const open = sum?.open ?? 0;
  const overdue = sum?.overdue ?? 0;
  const triage = sum?.triage_assets ?? 0;
  const units = groups.data?.total ?? 0;
  const staleAssets = data.coverage.stale;

  // The next action is derived, not decorative: the first thing that is actually blocking
  // the workflow, in workflow order.
  const nextAction = (() => {
    if (staleFeeds.length > 0) {
      return {
        title: "Refresh vulnerability intelligence",
        why: `${staleFeeds.length} feed${staleFeeds.length === 1 ? " is" : "s are"} stale, so priorities and KEV flags may be wrong.`,
        label: "Update intelligence",
        to: "/settings?tab=intelligence",
      };
    }
    if (triage > 0) {
      return {
        title: `Route ${pluralize(triage, "unowned asset")}`,
        why: "Routing never guesses: work on these assets waits until somebody owns them.",
        label: "Set ownership",
        to: "/remediation?tab=ownership",
      };
    }
    if (overdue > 0) {
      return {
        title: `Work ${pluralize(overdue, "overdue item")}`,
        why: "Past the agreed deadline. Overdue work is the number an auditor asks for.",
        label: "Open overdue work",
        to: "/remediation?tab=queue&overdue=1",
      };
    }
    if ((sum?.by_state?.pending_verification ?? 0) > 0) {
      return {
        title: `Verify ${pluralize(sum?.by_state?.pending_verification ?? 0, "fix")}`,
        why: "A rescan is the only thing that proves a finding is gone.",
        label: "Review verification queue",
        to: "/remediation?tab=queue&state=pending_verification",
      };
    }
    if (staleAssets > 0) {
      return {
        title: `Assess ${pluralize(staleAssets, "stale asset")}`,
        why: "Their findings are from an old scan, so the current picture is unknown.",
        label: "Open scans",
        to: "/scans",
      };
    }
    if (open === 0) {
      return {
        title: "No open remediation work",
        why: "The last assessment found nothing actionable in scope. Scan again after changes to keep it true.",
        label: "Run a scan",
        to: "/scans/new",
      };
    }
    return {
      title: "Work the remediation queue",
      why: `${pluralize(open, "open item")} across ${pluralize(units, "upgrade")} — nothing is late.`,
      label: "Open remediation",
      to: "/remediation",
    };
  })();

  const steps: ProcessStep[] = [
    {
      key: "discover", label: "Discover", to: "/assets",
      count: data.metrics.assets, tone: data.metrics.assets > 0 ? "done" : "action",
      hint: data.metrics.assets > 0 ? "endpoints enrolled" : "enroll an endpoint",
    },
    {
      key: "scan", label: "Scan", to: "/scans",
      count: data.coverage.assessed, tone: staleAssets > 0 ? "action" : "done",
      hint: staleAssets > 0 ? `${staleAssets} stale` : "all current",
    },
    {
      key: "review", label: "Review", to: "/vulnerabilities",
      count: data.metrics.actionable ?? open, tone: "info",
      hint: "actionable findings",
    },
    {
      key: "assign", label: "Assign", to: "/remediation?tab=ownership",
      count: triage, tone: triage > 0 ? "action" : "done",
      hint: triage > 0 ? "waiting for an owner" : "every asset owned",
    },
    {
      key: "fix", label: "Fix", to: "/remediation?tab=upgrades",
      count: units, tone: "info",
      hint: "upgrades in flight",
    },
    {
      key: "verify", label: "Verify", to: "/remediation?tab=queue&state=pending_verification",
      count: sum?.by_state?.pending_verification ?? 0, tone: "info",
      hint: "waiting for a rescan",
    },
  ];

  return (
    <div className="space-y-4">
      <PageHeader
        title="Overview"
        description={
          <>
            {pluralize(data.metrics.assets, "asset")} · last scan {relativeTime(data.coverage.last_scan_at)} ·{" "}
            {formatDate(data.coverage.last_scan_at)}
          </>
        }
        help={`This page answers four questions: how exposed you are right now, what needs attention, what to do next, and whether things are improving. The numbers come from the most recent completed assessment of each system, so a system scanned a week ago still counts with its old results until it is scanned again.`}
        actions={
          <Button className="hidden sm:inline-flex" variant="primary" onClick={() => navigate("/scans/new")}>
            <Radar className="h-4 w-4" aria-hidden="true" /> New scan
          </Button>
        }
      />

      {/* 1 + 2: posture and what needs attention, in one block. */}
      <div className="grid gap-3 lg:grid-cols-3">
        <Card className="p-4 lg:col-span-2">
          <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            Current posture
            <InfoTooltip label="About current posture">
              Open findings are the ones still reported by each system&apos;s latest scan. A finding
              closed here means a later scan no longer sees it — not that a ticket was closed. One
              upgrade can close many findings, so the number of findings is always larger than the
              number of changes someone has to make.
            </InfoTooltip>
          </p>
          <p className="mt-1 text-lg leading-snug">
            {open === 0 ? (
              <>No actionable findings in scope.</>
            ) : (
              <>
                <span className="num font-semibold">{open}</span> open {open === 1 ? "finding" : "findings"} over{" "}
                <span className="num font-semibold">{units}</span> {units === 1 ? "upgrade" : "upgrades"},{" "}
                {overdue > 0 ? (
                  <span className="font-semibold text-critical">
                    {overdue} past deadline
                  </span>
                ) : (
                  <span className="text-muted">none past deadline</span>
                )}
                {triage > 0 ? (
                  <>
                    , and <span className="font-semibold text-high">{pluralize(triage, "asset")} with no owner</span>
                  </>
                ) : null}
                .
              </>
            )}
          </p>
        </Card>

        {/* 3: the next action, derived from the data rather than guessed. */}
        <Card className="border-accent/40 p-4">
          <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-accent">
            <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" /> Do this next
          </p>
          <p className="mt-1 text-sm font-semibold">{nextAction.title}</p>
          <p className="mt-1 text-xs text-muted">{nextAction.why}</p>
          <Button variant="primary" size="sm" className="mt-3" onClick={() => navigate(nextAction.to)}>
            {nextAction.label} <ArrowRight className="h-3.5 w-3.5" aria-hidden="true" />
          </Button>
        </Card>
      </div>

      <div className="stagger grid grid-cols-2 gap-3 lg:grid-cols-4">
        <MetricCard
          label="Open findings"
          value={open}
          hint={`${units} ${units === 1 ? "upgrade" : "upgrades"} to apply`}
          icon={ShieldAlert}
          to="/vulnerabilities"
          help={<>Every finding still reported by the latest completed scan of each system. One upgrade often closes many findings, so this number is always larger than the number of changes to make.</>}
        />
        <MetricCard
          label="Critical findings"
          value={data.metrics.critical}
          hint="severity from the advisory"
          icon={TriangleAlert}
          to="/vulnerabilities?severity=critical"
          tone={data.metrics.critical > 0 ? "critical" : "neutral"}
          help={<>Findings whose advisory rates them critical. Severity describes the vulnerability, not how urgent it is here — priority adds known exploitation, internet exposure and what the system is worth.</>}
        />
        <MetricCard
          label="Systems needing an owner"
          value={triage}
          hint="routing waits for these"
          icon={Users}
          to="/remediation?tab=ownership"
          tone={triage > 0 ? "high" : "positive"}
          help={<>Assets whose findings could not be routed, because no team owns the asset and its packages could not be classified. Clanker never guesses a team: someone records the owner once, and the work routes from then on.</>}
        />
        <MetricCard
          label="Past deadline"
          value={overdue}
          hint={overdue > 0 ? "behind the agreed SLA" : "nothing is late"}
          icon={Timer}
          to="/remediation?tab=queue&overdue=1"
          tone={overdue > 0 ? "critical" : "positive"}
          help={<>Open findings older than the deadline set for their severity (7 days for critical through 90 for low, unless the policy was changed). A finding past its deadline is still open work, not an escalation — nothing notifies anyone automatically.</>}
        />
      </div>

      <ProcessStrip steps={steps} />

      {staleFeeds.length > 0 ? (
        <Banner tone="warn" title="Vulnerability intelligence is stale">
          {staleFeeds.map((f) => `${f.source} last synced ${relativeTime(f.last_sync)}`).join(" · ")}. Findings may be
          incomplete until the feeds are refreshed.{" "}
          <Link to="/settings?tab=intelligence" className="text-accent underline underline-offset-2 hover:text-accent-hover">
            Update intelligence
          </Link>
        </Banner>
      ) : null}

      {data.apps && data.apps.nvd_missing > 0 ? (
        <Banner tone="warn" title="Installed applications are not being assessed">
          {data.apps.nvd_missing === 1
            ? "One asset has installed applications that were inventoried but not evaluated"
            : `${data.apps.nvd_missing} assets have installed applications that were inventoried but not evaluated`}{" "}
          because the NVD dataset has never been synchronized. Zero application findings means &ldquo;not
          assessed&rdquo;, not &ldquo;patched&rdquo;. Run <span className="mono">clanker-guard-agent feeds update --with-nvd</span>{" "}
          on the server to close this gap.
        </Banner>
      ) : null}

      {data.metrics.needs_investigation > 0 ? (
        <Banner
          tone="info"
          title={`${pluralize(data.metrics.needs_investigation, "finding")} ${data.metrics.needs_investigation === 1 ? "needs" : "need"} investigation`}
        >
          These matched an advisory but the evidence is incomplete or conflicting (often a vendor backport). They are
          excluded from the actionable count until confirmed.
        </Banner>
      ) : null}

      {/* Priority findings: the short list, not the pile. */}
      <div className="grid gap-3 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardHeader
            title="Most urgent findings"
            description="Ranked by the backend risk model: KEV, EPSS, severity, exposure and confidence."
            actions={
              <Link to="/vulnerabilities" className="text-xs text-accent underline underline-offset-2">
                View all
              </Link>
            }
          />
          <CardBody className="p-0">
            {priority.length === 0 ? (
              <p className="p-4 text-sm text-muted">
                No actionable findings in the assessed scope. That is not proof the environment is secure — see coverage
                below.
              </p>
            ) : (
              <ul className="divide-y divide-border">
                {priority.slice(0, 5).map((f) => (
                  <li key={f.id}>
                    <Link
                      to={`/vulnerabilities?q=${encodeURIComponent(f.cve)}`}
                      className="flex flex-col gap-1 px-4 py-2.5 hover:bg-surface-2 sm:flex-row sm:flex-wrap sm:items-center sm:gap-x-3"
                    >
                      <span className="mono text-xs text-muted">{f.asset}</span>
                      <span className="min-w-0 flex-1">
                        <span className="block truncate text-sm font-medium">
                          {f.product} <span className="mono text-xs text-muted">{f.installed_version}</span>
                        </span>
                        <span className="mono text-xs text-muted">{f.cve}</span>
                      </span>
                      <span className="flex flex-wrap items-center gap-1.5">
                        <SeverityBadge severity={f.severity} />
                        {f.kev ? <KevBadge ransomware={f.kev_ransomware} /> : null}
                        <ApplicabilityBadge value={f.affected} />
                        <span className={`num text-sm font-semibold ${riskTone(f.risk_score)}`}>{f.risk_score.toFixed(1)}</span>
                      </span>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </CardBody>
        </Card>

        {/* 4: progress, from stored evidence. */}
        <Card className="p-4">
          <p className="flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            Is it getting better?
            <InfoTooltip label="About process metrics">
              Time to fix is measured from the first scan that reported a finding to the scan that
              proved it gone. It only appears for findings that have been verified, so a new
              installation shows a dash rather than an invented number. Ageing counts open findings
              by how long ago they were first seen.
            </InfoTooltip>
          </p>
          {m ? (
            <>
              <dl className="mt-2 space-y-1.5 text-sm">
                <div className="flex items-baseline justify-between gap-2">
                  <dt className="text-muted">Median time to fix</dt>
                  <dd className="num font-medium">
                    {m.time_to_fix?.length ? `${m.time_to_fix[0].median_days} d` : "—"}
                  </dd>
                </div>
                <div className="flex items-baseline justify-between gap-2">
                  <dt className="text-muted">Verified closed</dt>
                  <dd className="num font-medium">{m.verified ?? 0}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-2">
                  <dt className="text-muted">Reopened</dt>
                  <dd className="num font-medium">{m.reopened ?? 0}</dd>
                </div>
                <div className="flex items-baseline justify-between gap-2">
                  <dt className="text-muted">Exceptions expiring</dt>
                  <dd className="num font-medium">{m.acceptances_due ?? 0}</dd>
                </div>
              </dl>
              <p className="mt-3 text-xs text-subtle">
                Time to fix appears once findings are closed by a later scan. Nothing here is estimated.
              </p>
            </>
          ) : (
            <p className="mt-2 text-sm text-muted">Process metrics are unavailable on this server.</p>
          )}
        </Card>
      </div>

      {data.improvements_available > 0 ? (
        <Banner tone="success" title={`${pluralize(data.improvements_available, "detection improvement")} available for review`}>
          Generated from verified analyst reviews, tested against fixtures. Nothing is deployed without approval.{" "}
          <Link to="/settings?tab=improvement" className="text-accent underline underline-offset-2 hover:text-accent-hover">
            Review proposals
          </Link>
        </Banner>
      ) : null}

      {/* Everything below supports analysis, not the next action: collapsed by default. */}
      <div className="grid items-start gap-3 lg:grid-cols-2">
        <Card className="p-4">
          <p className="mb-3 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            Severity mix
            <InfoTooltip label="About severity mix">
              What the open findings look like by advisory severity, across every assessed system.
              Select a band to jump to those findings. Severity is the advisory&apos;s rating; priority
              on the Remediation page is when this organisation should act.
            </InfoTooltip>
          </p>
          <SeverityDonut rows={severity.map((r) => ({ key: r.key, count: r.count }))} onSelect={(sev) => navigate(`/vulnerabilities?severity=${encodeURIComponent(sev)}`)} />
          <Link to="/vulnerabilities" className="mt-3 inline-block text-xs text-accent underline underline-offset-2">
            Open the findings list
          </Link>
        </Card>
        <Card className="p-4">
          <p className="mb-3 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            Age of open findings
            <InfoTooltip label="About finding age">
              How long open findings have been known, measured from the first scan that reported them.
              A shape that piles up on the right means fixes are not keeping up with discovery, even
              if the total stays flat.
            </InfoTooltip>
          </p>
          <AgingBars buckets={metrics.data?.age_buckets ?? []} />
        </Card>

        <Card className="p-4">
          <Collapsible
            title="Coverage and limitations"
            summary={`${data.coverage.assessed} assessed · ${data.coverage.stale} stale · ${limitations.length} limits`}
          >            <dl className="space-y-1.5 text-sm">
              <Row label="Assets assessed" value={String(data.coverage.assessed)} />
              <Row label={`Not scanned in ${data.coverage.stale_after_days} days`} value={String(data.coverage.stale)} />
              <Row label="Failed assessments (24 h)" value={String(data.coverage.failed_recent)} />
              <Row label="Latest completed" value={formatDate(data.coverage.last_scan_at)} />
            </dl>
            <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-muted">
              {(limitations.length ? limitations : ["No limitations reported."]).map((l) => (
                <li key={l}>{l}</li>
              ))}
            </ul>
            {errors.length > 0 ? (
              <div className="mt-3">
                <h4 className="text-xs font-semibold uppercase tracking-wide text-muted">Degraded coverage</h4>
                <ul className="mt-1 space-y-1 text-sm text-high">
                  {errors.map((e) => (
                    <li key={e}>{e}</li>
                  ))}
                </ul>
              </div>
            ) : null}
            <p className="mt-2 text-xs text-muted">
              A completed scan is not proof the environment is secure: it covers only the packages and sources listed
              here.
            </p>
          </Collapsible>
        </Card>
      </div>

      {data.apps ? (
        <Card className="p-4">
          <p className="mb-3 flex items-center gap-1.5 text-xs font-semibold uppercase tracking-wide text-muted">
            Application assessment
            <InfoTooltip label="About application assessment">
              Installed desktop applications (browsers, Office, runtimes, third-party software) are
              correlated against the local NVD CVE dataset. Coverage is the proportion of discovered
              applications that were successfully evaluated: an application without a vulnerability
              mapping stays visible as a gap — it is never counted as secure.
            </InfoTooltip>
          </p>
          <dl className="space-y-1.5 text-sm">
            <Row label="Applications discovered" value={String(data.apps.apps_discovered)} />
            <Row label="Applications evaluated" value={String(data.apps.apps_evaluated)} />
            <Row label="Applications without a mapping" value={String(data.apps.apps_unmapped)} />
            <Row label="Applications with vulnerabilities" value={String(data.apps.apps_with_findings)} />
            <Row label="Application findings" value={`${data.metrics.app_findings} (${data.metrics.os_findings} OS)`} />
            <Row label="Application findings in KEV" value={String(data.metrics.app_kev)} />
          </dl>
          <p className="mt-3 text-xs text-subtle">
            Operating-system findings (distribution advisories and Windows servicing) are counted
            separately so a patched OS never hides vulnerable applications.{" "}
            <Link to="/vulnerabilities?category=application" className="text-accent underline underline-offset-2">
              Open application findings
            </Link>
          </p>
        </Card>
      ) : null}
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
