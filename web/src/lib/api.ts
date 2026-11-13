/**
 * Typed client for the Clanker Guard HTTP API.
 *
 * The backend is authoritative for scan results, applicability, confidence and
 * risk. Nothing here recomputes any of that.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "unknown" | "none";
export type Applicability =
  | "confirmed_applicability"
  | "validated_behavior"
  | "probable"
  | "potential"
  | "needs_investigation"
  | "not_affected";

export interface Meta {
  tool: string;
  version: string;
  cache: string;
  web_dir: string;
  capabilities: {
    local_scan: boolean;
    network_scan: boolean;
    sbom_scan: boolean;
    llm: boolean;
    agent_push: boolean;
  };
  release: { published: boolean; base_url: string };
}

export interface Overview {
  has_data: boolean;
  metrics: {
    assets: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    kev: number;
    actionable: number;
    needs_investigation: number;
    total: number;
  };
  severity: CountRow[];
  priority: Vulnerability[];
  coverage: {
    assessed: number;
    stale: number;
    failed_recent: number;
    stale_after_days: number;
    last_scan_at?: string;
  };
  activity: ActivityRow[];
  feeds: FeedStatus[];
  limitations: string[];
  errors: string[];
}

export interface CountRow {
  key: string;
  count: number;
}

export interface ActivityRow {
  id: string;
  kind: string;
  host?: string;
  status: string;
  stage?: string;
  percent: number;
  finished_at?: string;
  findings?: number;
  actionable?: number;
  kev?: number;
  error?: string;
}

export interface FeedStatus {
  source: string;
  last_sync?: string;
  records: number;
  stale: boolean;
}

export interface Evidence {
  kind: string;
  detail: string;
  url?: string;
  source?: string;
}

export interface RiskFactor {
  name: string;
  weight: number;
  detail?: string;
}

export interface Link {
  label: string;
  url: string;
}

export interface Vulnerability {
  id: string;
  finding_id: string;
  report_id: string;
  cve: string;
  aliases?: string[];
  asset: string;
  product: string;
  installed_version: string;
  ecosystem: string;
  severity: Severity;
  affected: Applicability;
  confidence: "high" | "medium" | "low";
  validation_status: string;
  kev: boolean;
  kev_date_added?: string;
  kev_ransomware?: string;
  epss: number | null;
  epss_percentile: number | null;
  cvss: number | null;
  cvss_vector?: string;
  fixed_version?: string;
  remediation: string;
  source: string;
  advisory_id: string;
  vendor?: string;
  risk_score: number;
  first_seen: string;
  last_seen: string;
  explanation?: string;
  evidence?: Evidence[];
  confidence_increase?: string[];
  confidence_reduction?: string[];
  risk_factors?: RiskFactor[];
  references?: Link[];
}

export interface VulnList {
  total: number;
  items: Vulnerability[];
  facets: {
    severity: CountRow[];
    applicability: CountRow[];
    assets: CountRow[];
    kev: number;
    fix_available: number;
  };
  applied: Record<string, unknown>;
}

export interface Asset {
  host: string;
  os: string;
  os_version: string;
  arch?: string;
  packages: number;
  findings: number;
  actionable: number;
  critical: number;
  high: number;
  kev: number;
  last_scan: string;
  stale: boolean;
  agent_version?: string;
  mode?: string;
  report_id?: string;
  is_container?: boolean;
}

export interface PackageRow {
  name: string;
  version: string;
  ecosystem: string;
  source: string;
  arch?: string;
  purl?: string;
  patch_status?: string;
}

export interface AssetDetail {
  host: string;
  asset: {
    hostname: string;
    os: string;
    os_version: string;
    os_codename?: string;
    kernel?: string;
    arch?: string;
    distro_id?: string;
    is_container?: boolean;
  };
  report_id: string;
  last_scan: string;
  mode: string;
  offline: boolean;
  agent: { version: string; last_scan: string };
  packages: PackageRow[];
  package_count: number;
  packages_truncated: boolean;
  findings: Vulnerability[];
  coverage: Coverage;
  skipped: { check: string; reason: string }[];
  errors: string[];
  policy: { fail_on?: string; fail_on_kev: boolean };
  history: RunSummary[];
}

export interface Coverage {
  packages_inspected: number;
  packages_matched: number;
  advisories_checked: number;
  sources_used: string[];
  not_covered?: string[];
  limitations?: string[];
}

export interface RunSummary {
  id: string;
  host: string;
  started_at: string;
  finished_at: string;
  findings: number;
  actionable: number;
  kev_count: number;
  report_id: string;
}

export interface Job {
  id: string;
  kind: string;
  status: "queued" | "running" | "completed" | "failed" | "canceled";
  host?: string;
  started_at: string;
  finished_at?: string;
  stage?: string;
  stage_detail?: string;
  percent: number;
  error?: string;
  report_id?: string;
}

export interface ScanDetail {
  job: Job | null;
  report_available: boolean;
  report_id?: string;
  report?: ReportDoc;
}

export interface ReportDoc {
  schema_version: string;
  report_id: string;
  metadata: {
    tool_version: string;
    started_at: string;
    finished_at?: string;
    mode: string;
    host: string;
    offline: boolean;
    errors?: string[];
    skipped_checks?: { check: string; reason: string }[];
    coverage: Coverage;
    policy?: { fail_on_severity?: string; fail_on_kev?: boolean };
  };
  inventory: { asset: Record<string, unknown>; packages: PackageRow[] };
  findings: unknown[];
  summary: {
    total: number;
    by_severity: Record<string, number>;
    by_affected: Record<string, number>;
    kev_count: number;
    actionable: number;
    not_affected: number;
  };
}

export interface FeedResponse {
  feeds: FeedStatus[];
  counts: { advisories: number; kev: number; epss: number };
}

export interface AgentsResponse {
  local: { host: string; version: string; cache_path: string; platform: string; installed: boolean; last_scan?: string };
  endpoints: {
    host: string;
    agent_version: string;
    last_scan: string;
    os: string;
    os_version: string;
    findings: number;
    mode: string;
  }[];
  install: {
    published: boolean;
    version: string;
    base_url: string;
    commands?: Record<string, string>;
    build_steps?: string[];
  };
  managed_mode: boolean;
  managed_note: string;
}

export interface Settings {
  policy: { fail_on: string; fail_on_kev: boolean };
  offline_default: boolean;
  release_base: string;
  cache_path: string;
  tool_version: string;
  token_required: boolean;
  capabilities: Record<string, boolean>;
}

export interface AskResponse {
  answer: string;
  citations: { id: string; cve: string; product: string; severity: string; affected: string; advisory_url: string }[];
  grounding: { report_id: string; host: string; generated_by: string; llm_used: boolean; note: string };
}

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const TOKEN_KEY = "clanker-guard.token";

export function getToken(): string {
  try {
    return localStorage.getItem(TOKEN_KEY) ?? "";
  } catch {
    return "";
  }
}

export function setToken(token: string): void {
  try {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {
    /* storage disabled: token stays in memory for this session only */
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const headers = new Headers(init?.headers);
  headers.set("Accept", "application/json");
  if (init?.body) headers.set("Content-Type", "application/json");
  const token = getToken();
  if (token) headers.set("X-Guard-Token", token);

  let res: Response;
  try {
    res = await fetch(path, { ...init, headers });
  } catch (err) {
    throw new ApiError(0, "network_error", "Cannot reach the Clanker Guard API. Is `clanker vuln serve` running?");
  }
  if (!res.ok) {
    let code = "http_error";
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { error?: string; code?: string };
      if (body.error) message = body.error;
      if (body.code) code = body.code;
    } catch {
      /* non-JSON error body */
    }
    throw new ApiError(res.status, code, message);
  }
  if (res.status === 204) return undefined as T;
  return (await res.json()) as T;
}

function qs(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === "" || v === false) continue;
    search.set(k, String(v));
  }
  const s = search.toString();
  return s ? `?${s}` : "";
}

export const api = {
  meta: () => request<Meta>("/api/meta"),
  health: () => request<{ status: string }>("/api/health"),
  overview: () => request<Overview>("/api/overview"),
  assets: () => request<{ items: Asset[]; total: number }>("/api/assets"),
  asset: (host: string) => request<AssetDetail>(`/api/assets/${encodeURIComponent(host)}`),
  vulnerabilities: (params: {
    q?: string;
    severity?: string;
    applicability?: string;
    kev?: boolean;
    fix?: string;
    asset?: string;
    sort?: string;
    order?: string;
    limit?: number;
    offset?: number;
  }) => request<VulnList>(`/api/vulnerabilities${qs(params)}`),
  vulnerability: (id: string) => request<Vulnerability>(`/api/vulnerabilities/${encodeURIComponent(id)}`),
  scans: () => request<{ jobs: Job[]; runs: RunSummary[]; active: number }>("/api/scans"),
  scan: (id: string) => request<ScanDetail>(`/api/scans/${encodeURIComponent(id)}`),
  startScan: (body: {
    kind: "local" | "network" | "sbom";
    offline?: boolean;
    include_not_affected?: boolean;
    fail_on?: string;
    fail_on_kev?: boolean;
  }) => request<Job>("/api/scans", { method: "POST", body: JSON.stringify(body) }),
  cancelScan: (id: string) => request<{ id: string; status: string }>(`/api/scans/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
  reports: () => request<{ items: RunSummary[]; total: number }>("/api/reports"),
  report: (id: string) => request<ReportDoc>(`/api/reports/${encodeURIComponent(id)}`),
  exportUrl: (id: string, format: "json" | "markdown" | "sarif" | "html") =>
    `/api/reports/${encodeURIComponent(id)}/export?format=${format}`,
  feeds: () => request<FeedResponse>("/api/feeds"),
  updateFeeds: () => request<Job>("/api/feeds/update", { method: "POST" }),
  agents: () => request<AgentsResponse>("/api/agents"),
  settings: () => request<Settings>("/api/settings"),
  saveSettings: (body: {
    policy?: { fail_on: string; fail_on_kev: boolean };
    offline_default?: boolean;
    release_base?: string;
  }) => request<Settings>("/api/settings", { method: "PUT", body: JSON.stringify(body) }),
  ask: (question: string, host?: string) =>
    request<AskResponse>("/api/ask", { method: "POST", body: JSON.stringify({ question, host }) }),
};
