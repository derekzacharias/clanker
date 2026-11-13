import type { Applicability, Severity } from "./api";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "unknown"];

export const severityLabel: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  unknown: "Unknown",
  none: "None",
};

/**
 * Severity is never communicated by colour alone: every caller renders the
 * label too. These classes only provide the supporting visual weight.
 */
export const severityClass: Record<Severity, string> = {
  critical: "bg-critical-soft text-critical border-critical/30",
  high: "bg-high-soft text-high border-high/30",
  medium: "bg-medium-soft text-medium border-medium/30",
  low: "bg-low-soft text-low border-low/30",
  unknown: "bg-unknown-soft text-unknown border-unknown/30",
  none: "bg-unknown-soft text-unknown border-unknown/30",
};

export const applicabilityLabel: Record<Applicability, string> = {
  confirmed_applicability: "Confirmed",
  validated_behavior: "Validated",
  probable: "Probable",
  potential: "Potential",
  needs_investigation: "Needs investigation",
  not_affected: "Not affected",
};

export const applicabilityHint: Record<Applicability, string> = {
  confirmed_applicability: "Authoritative advisory data says this exact build is affected.",
  validated_behavior: "A safe, vulnerability-specific check observed the condition.",
  probable: "Strong evidence, but at least one prerequisite could not be verified (often a vendor backport).",
  potential: "Only a version or fingerprint match; the advisory does not confirm this build.",
  needs_investigation: "Evidence is missing or conflicting. Confirm manually before treating it as exploitable.",
  not_affected: "Authoritative evidence shows the vulnerable condition does not apply.",
};

export const confidenceLabel: Record<string, string> = {
  high: "High confidence",
  medium: "Medium confidence",
  low: "Low confidence",
};

export function riskTone(score: number): string {
  if (score >= 70) return "text-critical";
  if (score >= 45) return "text-high";
  if (score >= 25) return "text-medium";
  return "text-muted";
}

export function pct(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return `${(value * 100).toFixed(1)}%`;
}

export function num(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return value.toFixed(1);
}

export function formatDate(iso?: string): string {
  if (!iso) return "Never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "Unknown";
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function relativeTime(iso?: string, now: Date = new Date()): string {
  if (!iso) return "never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return "unknown";
  const diff = now.getTime() - d.getTime();
  const mins = Math.round(diff / 60000);
  if (mins < 1) return "just now";
  if (mins < 60) return `${mins} min ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours} h ago`;
  const days = Math.round(hours / 24);
  if (days === 1) return "yesterday";
  if (days < 30) return `${days} days ago`;
  const months = Math.round(days / 30);
  return `${months} mo ago`;
}

/** True when a scan is older than the documented staleness window. */
export function isStale(iso: string | undefined, days = 7): boolean {
  if (!iso) return true;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return true;
  return Date.now() - t > days * 24 * 3600 * 1000;
}

export function pluralize(n: number, one: string, many = `${one}s`): string {
  return `${n} ${n === 1 ? one : many}`;
}
