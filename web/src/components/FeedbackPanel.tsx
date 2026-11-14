import { CheckCircle2, CircleHelp, ShieldCheck, ShieldX, Wrench, X } from "lucide-react";
import { useState } from "react";
import {
  api,
  ApiError,
  type Feedback,
  type ReasonCode,
  type FeedbackResponse,
  type Verification,
  type Verdict,
  type Vulnerability,
} from "../lib/api";
import { Button } from "./ui/Button";
import { Badge } from "./ui/Badge";
import { Banner } from "./ui/Feedback";
import { cn } from "../lib/cn";
import { formatDate } from "../lib/format";

const ACTIONS: { verdict: Verdict; label: string; icon: typeof CheckCircle2; tone: string }[] = [
  { verdict: "confirmed", label: "Confirm finding", icon: ShieldCheck, tone: "border-low/40 text-low" },
  { verdict: "false_positive", label: "Mark false positive", icon: ShieldX, tone: "border-high/40 text-high" },
  { verdict: "needs_investigation", label: "Needs investigation", icon: CircleHelp, tone: "border-medium/40 text-medium" },
  { verdict: "remediated", label: "Remediated", icon: Wrench, tone: "border-border text-muted" },
  { verdict: "request_verification", label: "Request verification", icon: CheckCircle2, tone: "border-border text-muted" },
];

const REASONS: { code: ReasonCode; label: string; hint: string }[] = [
  { code: "vendor_patch_installed", label: "Vendor patch already installed", hint: "Checked against the distribution's advisory data." },
  { code: "incorrect_identification", label: "Incorrect software identification", hint: "e.g. a snap stub or third-party rebuild." },
  { code: "feature_not_enabled", label: "Vulnerable feature not enabled", hint: "Cannot be verified automatically yet." },
  { code: "advisory_not_applicable", label: "Advisory does not apply", hint: "Cannot be verified automatically yet." },
  { code: "other", label: "Other", hint: "Recorded without an automated check." },
];

const VERIFICATION_TONE: Record<string, string> = {
  supported: "border-low/40 bg-low-soft text-low",
  contradicted: "border-critical/40 bg-critical-soft text-critical",
  inconclusive: "border-high/40 bg-high-soft text-high",
};

function verificationLabel(v: Verification): "supported" | "contradicted" | "inconclusive" {
  if (v.supported) return "supported";
  return v.confidence === "high" ? "contradicted" : "inconclusive";
}

/**
 * Analyst feedback for one finding. The scanner verdict is never overwritten:
 * a correction only appears when advisory evidence supports it.
 */
export function FeedbackPanel({
  finding,
  onUpdated,
}: {
  finding: Vulnerability;
  onUpdated: () => void;
}) {
  const [verdict, setVerdict] = useState<Verdict | null>(null);
  const [reason, setReason] = useState<ReasonCode | null>(null);
  const [note, setNote] = useState("");
  const [analyst, setAnalyst] = useState(() => localStorage.getItem("clanker-guard.analyst") ?? "");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<FeedbackResponse | null>(null);
  const [history, setHistory] = useState<Feedback[] | null>(null);
  const [showHistory, setShowHistory] = useState(false);

  const submitDisabled = !verdict || busy || (verdict === "false_positive" && !reason);

  async function submit() {
    if (!verdict) return;
    setBusy(true);
    setError(null);
    try {
      if (analyst) localStorage.setItem("clanker-guard.analyst", analyst);
      const res = await api.feedback(finding.id, {
        verdict,
        reason_code: reason ?? undefined,
        reason_text: note || undefined,
        analyst: analyst || "web-ui",
      });
      setResult(res);
      setVerdict(null);
      setReason(null);
      setNote("");
      onUpdated();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  async function loadHistory() {
    setShowHistory((v) => !v);
    if (history) return;
    try {
      const res = await api.feedbackHistory(finding.id);
      setHistory(res.feedback);
    } catch {
      setHistory([]);
    }
  }

  return (
    <section aria-labelledby="feedback-heading" className="rounded-lg border border-border bg-surface-2 p-3">
      <div className="flex items-center justify-between gap-2">
        <h3 id="feedback-heading" className="text-xs font-semibold uppercase tracking-wide text-muted">
          Analyst review
        </h3>
        <button
          type="button"
          onClick={loadHistory}
          className="text-xs text-accent hover:underline"
          aria-expanded={showHistory}
        >
          {showHistory ? "Hide history" : "Review history"}
        </button>
      </div>

      {finding.analyst ? (
        <div className="mt-2 rounded-md border border-border bg-surface p-2.5">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <Badge className="border-low/30 bg-low-soft text-low">verified by analyst</Badge>
            <span className="font-medium">
              {finding.analyst.verdict.replace(/_/g, " ")} → {finding.analyst.applicability.replace(/_/g, " ")}
            </span>
            <span className="text-muted">{formatDate(finding.analyst.verified_at)}</span>
          </div>
          <p className="mt-1 text-sm">{finding.analyst.explanation}</p>
          <p className="mt-1 text-xs text-muted">
            Scanner verdict remains <span className="mono">{finding.affected.replace(/_/g, " ")}</span>. Both are shown so
            the correction can be audited.
          </p>
        </div>
      ) : null}

      {result ? (
        <div className={cn("mt-2 rounded-md border p-2.5", VERIFICATION_TONE[verificationLabel(result.verification)])}>
          <p className="text-xs font-semibold">
            Feedback recorded — verification {verificationLabel(result.verification)}
          </p>
          <p className="mt-1 text-sm text-fg">{result.verification.explanation}</p>
          {result.verification.changed ? (
            <p className="mt-1 text-xs">
              Classification updated: <span className="mono">{result.verification.original_applicability}</span> →{" "}
              <span className="mono">{result.verification.reassessed_applicability}</span>
            </p>
          ) : (
            <p className="mt-1 text-xs">The scanner classification was not changed.</p>
          )}
          {(result.verification.evidence ?? []).length > 0 ? (
            <ul className="mt-2 space-y-1 text-xs">
              {(result.verification.evidence ?? []).slice(0, 3).map((e, i) => (
                <li key={i} className="text-fg/90">
                  <span className="mono">{e.kind}</span> — {e.detail}
                </li>
              ))}
            </ul>
          ) : null}
          {(result.improvement_ids ?? []).length > 0 ? (
            <p className="mt-2 text-xs">
              Improvement proposal{(result.improvement_ids ?? []).length > 1 ? "s" : ""}:{" "}
              {(result.improvement_ids ?? []).map((id) => (
                <a key={id} href="/settings?tab=improvement" className="mono text-accent hover:underline">
                  {id}{" "}
                </a>
              ))}
            </p>
          ) : null}
        </div>
      ) : null}

      <div className="mt-2 flex flex-wrap gap-1.5">
        {ACTIONS.map((a) => {
          const Icon = a.icon;
          const active = verdict === a.verdict;
          return (
            <button
              key={a.verdict}
              type="button"
              aria-pressed={active}
              onClick={() => {
                setVerdict(a.verdict);
                setReason(null);
                setResult(null);
              }}
              className={cn(
                "inline-flex items-center gap-1.5 rounded-md border px-2.5 py-1.5 text-xs",
                active ? cn("border-accent bg-accent-soft font-medium text-accent") : cn(a.tone, "hover:bg-surface"),
              )}
            >
              <Icon className="h-3.5 w-3.5" aria-hidden="true" />
              {a.label}
            </button>
          );
        })}
      </div>

      {verdict === "false_positive" ? (
        <fieldset className="mt-3">
          <legend className="text-xs font-medium text-muted">Why is this not applicable?</legend>
          <div className="mt-1.5 space-y-1.5">
            {REASONS.map((r) => (
              <label
                key={r.code}
                className={cn(
                  "flex cursor-pointer items-start gap-2 rounded-md border p-2 text-sm",
                  reason === r.code ? "border-accent bg-accent-soft" : "border-border bg-surface hover:bg-surface-2",
                )}
              >
                <input
                  type="radio"
                  name="feedback-reason"
                  value={r.code}
                  checked={reason === r.code}
                  onChange={() => setReason(r.code)}
                  className="mt-1"
                />
                <span>
                  <span className="block font-medium">{r.label}</span>
                  <span className="block text-xs text-muted">{r.hint}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
      ) : null}

      {verdict ? (
        <div className="mt-3 space-y-2">
          <label htmlFor="feedback-note" className="block text-xs font-medium text-muted">
            Note (optional, stored as data)
          </label>
          <textarea
            id="feedback-note"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            rows={2}
            className="w-full rounded-md border border-border-strong bg-surface px-2.5 py-1.5 text-sm"
            placeholder="Reference to a vendor advisory, internal ticket, or build detail…"
          />
          <div className="flex flex-wrap items-end gap-2">
            <div className="flex-1">
              <label htmlFor="feedback-analyst" className="block text-xs font-medium text-muted">
                Your name (recorded in the audit trail)
              </label>
              <input
                id="feedback-analyst"
                value={analyst}
                onChange={(e) => setAnalyst(e.target.value)}
                className="h-9 w-full rounded-md border border-border-strong bg-surface px-2.5 text-sm"
                placeholder="analyst"
              />
            </div>
            <Button variant="primary" onClick={submit} disabled={submitDisabled}>
              Submit feedback
            </Button>
            <Button variant="ghost" onClick={() => setVerdict(null)}>
              <X className="h-4 w-4" aria-hidden="true" /> Cancel
            </Button>
          </div>
        </div>
      ) : null}

      {error ? (
        <div className="mt-2">
          <Banner tone="danger" title="Feedback rejected">
            {error}
          </Banner>
        </div>
      ) : null}

      {showHistory ? (
        <div className="mt-3">
          {history === null ? (
            <p className="text-xs text-muted">Loading history…</p>
          ) : history.length === 0 ? (
            <p className="text-xs text-muted">No reviews recorded for this finding yet.</p>
          ) : (
            <ul className="space-y-1.5">
              {history.map((fb) => (
                <li key={fb.id} className="rounded border border-border bg-surface p-2 text-xs">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="font-medium">{fb.verdict.replace(/_/g, " ")}</span>
                    {fb.reason_code ? <span className="mono text-muted">{fb.reason_code}</span> : null}
                    <span className="text-muted">{fb.analyst}</span>
                    <span className="text-muted">{formatDate(fb.created_at)}</span>
                  </div>
                  {fb.reason_text ? <p className="mt-0.5 text-fg">{fb.reason_text}</p> : null}
                  {fb.verification ? (
                    <p className="mt-0.5 text-muted">
                      verified: {fb.verification.supported ? "supported" : "not supported"} ·{" "}
                      {fb.verification.explanation}
                    </p>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
        </div>
      ) : null}

      <p className="mt-2 text-[0.6875rem] text-subtle">
        Feedback is verified against advisory evidence. It never changes a classification on its own.
      </p>
    </section>
  );
}
