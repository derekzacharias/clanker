import { Loader2, Send, Sparkles } from "lucide-react";
import { useState } from "react";
import { api, type AskResponse } from "../lib/api";
import { Link } from "../lib/router";
import { Button } from "./ui/Button";
import { Drawer } from "./ui/Dialog";
import { Banner, ErrorState } from "./ui/Feedback";
import { severityLabel } from "../lib/format";

const SUGGESTIONS = [
  "What should I patch first?",
  "Which systems have known exploited vulnerabilities?",
  "Which findings have fixes available?",
  "Which findings are likely false positives?",
  "What changed since the last scan?",
];

/**
 * Ask Guard answers from stored scan evidence only. It is deliberately a
 * supporting panel, not a chat-first interface, and it says so in the UI.
 */
export function AskGuard({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<AskResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function ask(q: string) {
    if (!q.trim()) return;
    setBusy(true);
    setError(null);
    try {
      setAnswer(await api.ask(q));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setAnswer(null);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Drawer
      open={open}
      onOpenChange={onOpenChange}
      title={
        <span className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-accent" aria-hidden="true" /> Ask Guard
        </span>
      }
      description="Answers are computed from your stored findings and advisory data. No model is consulted."
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void ask(question);
        }}
        className="space-y-2"
      >
        <label htmlFor="ask-input" className="text-xs font-medium text-muted">
          Question
        </label>
        <div className="flex gap-2">
          <input
            id="ask-input"
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="What should I patch first?"
            className="h-9 flex-1 rounded-md border border-border-strong bg-surface px-2.5 text-sm placeholder:text-subtle"
          />
          <Button type="submit" variant="primary" disabled={busy || !question.trim()}>
            {busy ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <Send className="h-4 w-4" aria-hidden="true" />}
            Ask
          </Button>
        </div>
      </form>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {SUGGESTIONS.map((s) => (
          <button
            key={s}
            type="button"
            onClick={() => {
              setQuestion(s);
              void ask(s);
            }}
            className="rounded-full border border-border px-2.5 py-1 text-xs text-muted hover:bg-surface-2 hover:text-fg"
          >
            {s}
          </button>
        ))}
      </div>

      {error ? <ErrorState title="Could not answer" message={error} /> : null}

      {answer ? (
        <div className="mt-5 space-y-4">
          <Banner tone="info" title="Grounded in stored evidence">
            {answer.grounding.note} Report <span className="mono">{answer.grounding.report_id}</span> on{" "}
            {answer.grounding.host}.
          </Banner>
          <pre className="whitespace-pre-wrap break-words font-sans text-sm leading-relaxed">{answer.answer}</pre>
          {answer.citations.length > 0 ? (
            <div>
              <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted">Cited findings</h3>
              <ul className="space-y-1.5">
                {answer.citations.map((c) => (
                  <li key={c.id} className="flex flex-wrap items-center gap-2 text-sm">
                    <Link
                      to={`/vulnerabilities?q=${encodeURIComponent(c.cve)}`}
                      className="mono text-accent hover:underline"
                    >
                      {c.cve}
                    </Link>
                    <span className="text-muted">
                      {c.product} · {severityLabel[(c.severity as keyof typeof severityLabel) ?? "unknown"] ?? c.severity}
                    </span>
                    {c.advisory_url ? (
                      <a
                        href={c.advisory_url}
                        target="_blank"
                        rel="noreferrer"
                        className="text-xs text-accent hover:underline"
                      >
                        advisory ↗
                      </a>
                    ) : null}
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </div>
      ) : null}

      {!answer && !busy && !error ? (
        <p className="mt-6 text-sm text-muted">
          Ask about remediation priorities, known-exploited findings, or why a specific CVE was reported.
        </p>
      ) : null}
    </Drawer>
  );
}
