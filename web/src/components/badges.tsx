import { ShieldAlert, ShieldCheck, ShieldQuestion, Sparkles } from "lucide-react";
import { Badge } from "./ui/Badge";
import { Tooltip } from "./ui/Tooltip";
import type { Applicability, Severity } from "../lib/api";
import { applicabilityHint, applicabilityLabel, severityClass, severityLabel } from "../lib/format";
import { cn } from "../lib/cn";

/**
 * Severity is always rendered as icon + label + colour, never colour alone.
 */
export function SeverityBadge({ severity }: { severity: Severity }) {
  const Icon = severity === "critical" || severity === "high" ? ShieldAlert : ShieldCheck;
  return (
    <Badge className={cn("gap-1", severityClass[severity])}>
      <Icon className="h-3 w-3" aria-hidden="true" />
      <span>{severityLabel[severity]}</span>
    </Badge>
  );
}

export function ApplicabilityBadge({ value }: { value: Applicability }) {
  const tone =
    value === "confirmed_applicability" || value === "validated_behavior"
      ? "border-low/40 bg-low-soft text-low"
      : value === "probable"
        ? "border-medium/40 bg-medium-soft text-medium"
        : value === "potential"
          ? "border-unknown/40 bg-unknown-soft text-unknown"
          : value === "needs_investigation"
            ? "border-high/40 bg-high-soft text-high"
            : "border-border bg-surface-2 text-muted";
  return (
    <Tooltip label={applicabilityHint[value]}>
      <Badge className={cn("cursor-help gap-1", tone)}>
        {value === "needs_investigation" ? (
          <ShieldQuestion className="h-3 w-3" aria-hidden="true" />
        ) : (
          <ShieldCheck className="h-3 w-3" aria-hidden="true" />
        )}
        <span>{applicabilityLabel[value]}</span>
      </Badge>
    </Tooltip>
  );
}

export function KevBadge({ ransomware }: { ransomware?: string }) {
  return (
    <Tooltip
      label={
        ransomware
          ? `CISA KEV — known ransomware use: ${ransomware}`
          : "Listed in CISA's Known Exploited Vulnerabilities catalog"
      }
    >
      <Badge className="cursor-help gap-1 border-critical/40 bg-critical-soft text-critical">
        <Sparkles className="h-3 w-3" aria-hidden="true" />
        KEV
      </Badge>
    </Tooltip>
  );
}

export function ConfidenceBadge({ value }: { value: string }) {
  const tone =
    value === "high"
      ? "border-low/30 bg-low-soft text-low"
      : value === "medium"
        ? "border-medium/30 bg-medium-soft text-medium"
        : "border-border bg-surface-2 text-muted";
  return <Badge className={tone}>{value} confidence</Badge>;
}

export function FixBadge({ version }: { version?: string }) {
  if (!version) {
    return <span className="text-xs text-muted">No fixed version published</span>;
  }
  return (
    <Badge className="border-accent/30 bg-accent-soft text-accent" title={`Fixed in ${version}`}>
      <span className="mono">→ {version}</span>
    </Badge>
  );
}
