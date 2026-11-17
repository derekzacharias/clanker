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
  improvements_available: number;
  reviewed_findings: number;
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
  /** Work item derived from this finding, when one exists. Present on the detail only. */
  /** Issues tracked for this finding (normally zero or one). */
  gitlab_tickets?: GitLabTicket[];
  remediation_item?: {
    id: string;
    asset: string;
    team?: string;
    owner?: string;
    state: RemediationState;
    priority: string;
    severity: string;
    category?: string;
    due_at?: string;
    overdue: boolean;
  } | null;
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
  analyst?: AnalystState;
  effective_affected?: Applicability;
}

export type Verdict =
  | "confirmed"
  | "false_positive"
  | "needs_investigation"
  | "remediated"
  | "request_verification";

export type ReasonCode =
  | "vendor_patch_installed"
  | "incorrect_identification"
  | "feature_not_enabled"
  | "advisory_not_applicable"
  | "other";

export interface Verification {
  supported: boolean;
  confidence: "high" | "medium" | "low";
  explanation: string;
  evidence: Evidence[];
  original_applicability: string;
  reassessed_applicability?: string;
  changed: boolean;
  category?: string;
}

export interface AnalystState {
  verdict: Verdict;
  applicability: Applicability;
  confidence: string;
  explanation: string;
  evidence?: Evidence[];
  verified_at: string;
}

export interface Feedback {
  id: string;
  finding: {
    id: string;
    cve: string;
    product: string;
    version: string;
    ecosystem: string;
    applicability: string;
  };
  verdict: Verdict;
  reason_code?: ReasonCode;
  reason_text?: string;
  analyst: string;
  created_at: string;
  verification?: Verification;
}

export interface FeedbackResponse {
  feedback: Feedback;
  verification: Verification;
  state: {
    finding_id: string;
    verdict: Verdict;
    applicability: string;
    confidence: string;
    explanation: string;
    verified_at: string;
  } | null;
  improvement_ids: string[];
  note: string;
}

export type ImprovementStatus =
  | "discovered"
  | "researching"
  | "proposed"
  | "testing"
  | "awaiting_approval"
  | "approved"
  | "deployed"
  | "monitoring"
  | "rolled_back"
  | "rejected";

export interface Metrics {
  available: boolean;
  cases: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  accuracy: number;
}

export interface CaseResult {
  fixture: string;
  label: string;
  expected: string;
  baseline: string;
  candidate: string;
  pass: boolean;
  note?: string;
}

export interface Evaluation {
  passed: boolean;
  baseline: Metrics;
  candidate: Metrics;
  cases: CaseResult[];
  regressions?: string[];
  fixed_cases?: string[];
  notes?: string[];
  evaluated_at: string;
}

export interface Improvement {
  id: string;
  category: string;
  status: ImprovementStatus;
  title: string;
  problem: string;
  proposed_change: string;
  expected_benefit: string;
  risk_level: "low" | "medium" | "high";
  signature: string;
  affected_findings: string[];
  evidence: Evidence[];
  policy?: Record<string, unknown>;
  policy_notes?: string[];
  evaluation?: Evaluation;
  created_at: string;
  updated_at: string;
  approved_by?: string;
  approved_at?: string;
  deployed_at?: string;
  rolled_back_at?: string;
  rule_id?: string;
  rejected_reason?: string;
}

export interface ImprovementEvent {
  id: number;
  improvement_id: string;
  from: string;
  to: string;
  actor: string;
  note?: string;
  created_at: string;
}

export interface QualityMetrics {
  reviewed: number;
  confirmed: number;
  false_positives: number;
  needs_investigation: number;
  remediated: number;
  verification_supported: number;
  verification_contradicted: number;
  verification_inconclusive: number;
  false_positive_rate: number | null;
  reviewed_rate: number | null;
  findings_considered: number;
  actionable: number;
  needs_investigation_findings: number;
  open_improvements: number;
  deployed_improvements: number;
  rejected_improvements: number;
  notes?: string[];
}

export interface QualityResponse {
  metrics: QualityMetrics;
  improvement_counts: Record<string, number>;
  recent_feedback?: {
    finding_id: string;
    cve: string;
    product: string;
    verdict: Verdict;
    reason?: ReasonCode;
    analyst: string;
    created_at: string;
    supported?: boolean;
    explanation?: string;
  }[];
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

export interface AgentTask {
  id: string;
  agent_id: string;
  kind: string;
  status: "queued" | "running" | "done" | "failed";
  requested_at: string;
  started_at?: string;
  finished_at?: string;
  note?: string;
  report_id?: string;
}

export interface EnrolledAgent {
  id: string;
  host: string;
  os: string;
  version: string;
  state: "enrolled" | "idle" | "scanning" | "reporting" | "error";
  phase: string;
  percent: number;
  message: string;
  findings: number;
  last_report_id: string;
  enrolled_at: string;
  last_seen?: string;
  seconds_since_seen?: number;
  online: boolean;
  /** True while the agent holds a claim request, i.e. it can accept work now. */
  watching: boolean;
  revoked: boolean;
  task?: AgentTask;
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
    oneoff_commands?: Record<string, string>;
    keeps_available?: boolean;
    build_steps?: string[];
  };
  fleet: {
    server_url: string;
    enroll_token: string;
    reachable_window: string;
    count: number;
    enrolled: EnrolledAgent[];
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
  password_required?: boolean;
  auth?: { required: boolean; session_ttl: string; auth_file: string };
  capabilities: Record<string, boolean>;
}

/**
 * Result of GET /api/auth/session. `required` is false for a loopback server
 * with no credential configured, which is the one case the UI renders without
 * asking for anything.
 */
export interface AuthSession {
  authenticated: boolean;
  required: boolean;
  username?: string;
  /** Current role, read from the server on each probe. */
  role?: "viewer" | "operator" | "admin" | "";
  expires_at?: string;
  session_ttl?: string;
  methods: { password: boolean; token: boolean };
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
    // same-origin: the session cookie is scoped to this origin and must travel
    // with the request. Credentials are never attached to another origin.
    res = await fetch(path, { ...init, headers, credentials: "same-origin" });
  } catch (err) {
    throw new ApiError(0, "network_error", "Cannot reach the Clanker Guard API. Is `clanker vuln serve` running?");
  }
  // 401 on the auth endpoints is an ordinary answer (no session yet, wrong
  // password), not "your credential was rejected": dispatching the recovery
  // event for those would re-enter the probe that produced them.
  // /api/health is unauthenticated by design: a 401 from it is not an authentication
  // event, and firing the recovery flow from a liveness probe would sign the operator
  // out over a meaningless response.
  if (res.status === 401 && !path.startsWith("/api/auth/") && path !== "/api/health") {
    window.dispatchEvent(new CustomEvent("guard:unauthorized"));
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

/**
 * Fetch a file with the API token and save it.
 *
 * Export endpoints are authenticated, so a plain <a href> would navigate to a
 * 401 JSON body instead of downloading (the browser does not attach custom
 * headers to link navigations). Everything therefore goes through fetch + Blob.
 */
export async function downloadFile(path: string, fallbackName: string): Promise<string> {
  const headers = new Headers();
  const token = getToken();
  if (token) headers.set("X-Guard-Token", token);
  let res: Response;
  try {
    res = await fetch(path, { headers, credentials: "same-origin" });
  } catch {
    throw new ApiError(0, "network_error", "Cannot reach the Clanker Guard API.");
  }
  if (!res.ok) {
    let message = `${res.status} ${res.statusText}`;
    try {
      const body = (await res.json()) as { error?: string };
      if (body.error) message = body.error;
    } catch {
      /* not JSON */
    }
    throw new ApiError(res.status, "download_failed", message);
  }
  const disposition = res.headers.get("Content-Disposition") ?? "";
  const match = /filename="?([^";]+)"?/.exec(disposition);
  const filename = match?.[1] ?? fallbackName;
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  anchor.rel = "noopener";
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  // Revoke on the next tick so Safari has time to start the download.
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  return filename;
}

export type ReportExportFormat = "json" | "markdown" | "sarif" | "html" | "csv" | "cyclonedx";

export async function downloadReportExport(id: string, format: ReportExportFormat): Promise<string> {
  const ext = format === "markdown" ? "md" : format;
  // The inventory exports carry their own names: a CSV of installed software is
  // not "the report".
  const fallback =
    format === "csv"
      ? `clanker-guard-${id}-software.csv`
      : format === "cyclonedx"
        ? `clanker-guard-${id}.cdx.json`
        : `clanker-guard-${id}.${ext}`;
  return downloadFile(`/api/reports/${encodeURIComponent(id)}/export?format=${format}`, fallback);
}

/**
 * Environment-wide software asset list: every host with a stored assessment, one
 * row per installed package. CSV for asset registers/CMDB imports, CycloneDX for
 * SBOM tooling (one host at a time).
 */
export async function downloadSoftwareInventory(options: { format: "csv" | "cyclonedx"; host?: string }): Promise<string> {
  const params = new URLSearchParams({ format: options.format });
  if (options.host) params.set("host", options.host);
  const fallback =
    options.format === "cyclonedx"
      ? `clanker-guard-software-${options.host ?? "inventory"}.cdx.json`
      : "clanker-guard-software-inventory.csv";
  return downloadFile(`/api/software/export?${params.toString()}`, fallback);
}

export async function downloadFeedbackExport(): Promise<string> {
  return downloadFile("/api/feedback/export", "clanker-guard-feedback.json");
}

export const api = {
  meta: () => request<Meta>("/api/meta"),
  health: () => request<{ status: string; version?: string; uptime?: string }>("/api/health"),
  // Auth: the session probe is deliberately unauthenticated so the login screen
  // can tell "needs sign-in" from "unreachable" before it has credentials.
  session: () => request<AuthSession>("/api/auth/session"),
  login: (username: string, password: string) =>
    request<AuthSession>("/api/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password }),
    }),
  logout: () => request<{ authenticated: boolean }>("/api/auth/logout", { method: "POST" }),
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
    // network
    scope_yaml?: string;
    scope_file?: string;
    targets?: string[];
    authorized?: boolean;
    // software / container
    sbom_path?: string;
    image?: string;
  }) => request<Job>("/api/scans", { method: "POST", body: JSON.stringify(body) }),
  cancelScan: (id: string) => request<{ id: string; status: string }>(`/api/scans/${encodeURIComponent(id)}/cancel`, { method: "POST" }),
  reports: () => request<{ items: RunSummary[]; total: number }>("/api/reports"),
  report: (id: string) => request<ReportDoc>(`/api/reports/${encodeURIComponent(id)}`),
  exportUrl: (id: string, format: "json" | "markdown" | "sarif" | "html") =>
    `/api/reports/${encodeURIComponent(id)}/export?format=${format}`,
  feeds: () => request<FeedResponse>("/api/feeds"),
  updateFeeds: () => request<Job>("/api/feeds/update", { method: "POST" }),
  agents: () => request<AgentsResponse>("/api/agents"),
  // Remediation orchestration
  remediationSummary: () => request<RemediationSummary>("/api/remediation/summary"),
  remediation: (params: { team?: string; state?: string; owner?: string; asset?: string; overdue?: boolean } = {}) =>
    request<{ items: RemediationItem[]; total: number }>(`/api/remediation${qs(params)}`),
  ownership: (asset: string) => request<Ownership>(`/api/ownership/${encodeURIComponent(asset)}`),
  acceptRisk: (id: string, body: { reason: string; days?: number; until?: string }) =>
    request<{ item: RemediationItem }>(`/api/remediation/${encodeURIComponent(id)}/accept`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  remediationGroups: () =>
    request<{ items: RemediationGroup[]; total: number; findings: number }>("/api/remediation/groups"),
  metrics: () => request<ProcessMetrics>("/api/metrics"),
  runMaintenance: () => request<{ ok: boolean }>("/api/maintenance/run", { method: "POST" }),
  backup: () => request<{ path: string; name: string }>("/api/maintenance/backup", { method: "POST" }),
  accessMe: () => request<AccessMe>("/api/access/me"),
  users: () => request<{ items: Account[]; total: number; note?: string }>("/api/users"),
  createUser: (body: { username: string; password: string; role: string }) =>
    request<{ user: Account }>("/api/users", { method: "POST", body: JSON.stringify(body) }),
  updateUser: (username: string, body: { role?: string; disabled?: boolean; password?: string }) =>
    request<{ user: Account }>(`/api/users/${encodeURIComponent(username)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  deleteUser: (username: string) =>
    request<{ deleted: string }>(`/api/users/${encodeURIComponent(username)}`, { method: "DELETE" }),
  audit: (opts: { limit?: number; action?: string; actor?: string } = {}) =>
    request<{ items: AuditEntry[]; total: number; actions: string[] }>(
      `/api/audit${qs({ limit: opts.limit, action: opts.action, actor: opts.actor })}`,
    ),
  gitlabConfig: () => request<GitLabConfig>("/api/integrations/gitlab"),
  saveGitLab: (body: {
    enabled?: boolean;
    url?: string;
    token?: string;
    clear_token?: boolean;
    project_id?: number;
    labels?: string[];
    assignee?: string;
    timeout_seconds?: number;
    allow_insecure_http?: boolean;
  }) => request<GitLabConfig>("/api/integrations/gitlab", { method: "PUT", body: JSON.stringify(body) }),
  testGitLab: (body: { url?: string; token?: string; project_id?: number; allow_insecure_http?: boolean } = {}) =>
    request<GitLabVerifyResult>("/api/integrations/gitlab/test", { method: "POST", body: JSON.stringify(body) }),
  gitlabProjects: (search?: string) =>
    request<{ items: GitLabProject[]; total: number }>(
      `/api/integrations/gitlab/projects${qs({ search })}`,
    ),
  gitlabUsers: (search?: string) =>
    request<{ items: { id: number; username: string; name: string }[]; total: number }>(
      `/api/integrations/gitlab/users${qs({ search })}`,
    ),
  gitlabPreview: (findingId: string) =>
    request<{
      title: string;
      description: string;
      plan: RemediationPlan;
      labels: string[];
      label_field: string;
      project_id: number;
      finding_key: string;
    }>(
      "/api/integrations/gitlab/preview",
      { method: "POST", body: JSON.stringify({ finding_id: findingId }) },
    ),
  createGitLabTicket: (body: {
    finding_id: string;
    project_id?: number;
    title?: string;
    description?: string;
    labels?: string[];
    assignee_id?: number;
  }) =>
    request<{ ticket: GitLabTicket; created: boolean; reused: boolean; message: string }>(
      "/api/integrations/gitlab/tickets",
      { method: "POST", body: JSON.stringify(body) },
    ),
  refreshGitLabTicket: (id: string) =>
    request<{ ticket: GitLabTicket }>(`/api/integrations/gitlab/tickets/${encodeURIComponent(id)}/refresh`, {
      method: "POST",
    }),
  ownershipOverview: (opts: { triage?: boolean } = {}) =>
    request<{ items: AssetOwnershipRow[]; total: number }>(`/api/ownership${qs({ triage: opts.triage })}`),
  bulkOwnership: (body: {
    assets: string[];
    team: string;
    owner?: string;
    exposure?: string;
    environment?: string;
    criticality?: string;
    contact?: string;
  }) =>
    request<{ updated: string[]; failed: Record<string, string>; total: number }>("/api/ownership/bulk", {
      method: "POST",
      body: JSON.stringify(body),
    }),
  saveOwnership: (asset: string, body: Partial<Ownership>) =>
    request<Ownership>(`/api/ownership/${encodeURIComponent(asset)}`, { method: "PUT", body: JSON.stringify(body) }),
  updateRemediation: (id: string, body: { team?: string; owner?: string; state?: RemediationState; notes?: string }) =>
    request<{ item: RemediationItem }>(`/api/remediation/${encodeURIComponent(id)}`, {
      method: "PATCH",
      body: JSON.stringify(body),
    }),
  agentEvents: (id: string) =>
    request<{ agent: EnrolledAgent; events: { at: string; state: string; phase: string; percent: number; message: string }[] }>(
      `/api/agents/${encodeURIComponent(id)}/events`,
    ),
  queueAgentScan: (id: string) =>
    request<{ task: AgentTask; created: boolean }>(`/api/agents/${encodeURIComponent(id)}/scan`, { method: "POST" }),
  cancelAgentScan: (id: string) =>
    request<{ cancelled: number }>(`/api/agents/${encodeURIComponent(id)}/scan/cancel`, { method: "POST" }),
  revokeAgent: (id: string) =>
    request<{ revoked: string }>(`/api/agents/${encodeURIComponent(id)}/revoke`, { method: "POST" }),
  // Enrollment tokens are single-use and expire, so they are minted on demand.
  mintEnrollToken: (label?: string) =>
    request<{
      enroll_token: string;
      expires_at: string;
      single_use: boolean;
      commands: Record<string, string>;
      oneoff_commands: Record<string, string>;
    }>("/api/agents/enroll-token", { method: "POST", body: JSON.stringify({ label: label ?? "" }) }),
  rotateEnrollToken: () =>
    request<{ enroll_token: string }>("/api/agents/enroll-token/rotate", { method: "POST" }),
  settings: () => request<Settings>("/api/settings"),
  saveSettings: (body: {
    policy?: { fail_on: string; fail_on_kev: boolean };
    offline_default?: boolean;
    release_base?: string;
    operations?: Record<string, string>;
  }) => request<Settings>("/api/settings", { method: "PUT", body: JSON.stringify(body) }),
  feedback: (id: string, body: { verdict: Verdict; reason_code?: ReasonCode; reason_text?: string; analyst?: string }) =>
    request<FeedbackResponse>(`/api/vulnerabilities/${encodeURIComponent(id)}/feedback`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  feedbackHistory: (id: string) =>
    request<{ feedback: Feedback[]; state?: { applicability: string; verdict: Verdict; explanation: string } }>(
      `/api/vulnerabilities/${encodeURIComponent(id)}/history`,
    ),
  deleteFeedback: (id: string) =>
    request<{ deleted: string }>(`/api/vulnerabilities/${encodeURIComponent(id)}/feedback`, { method: "DELETE" }),
  improvements: (status?: string) =>
    request<{ items: Improvement[]; counts: Record<string, number>; total: number }>(
      `/api/improvements${status ? `?status=${encodeURIComponent(status)}` : ""}`,
    ),
  improvement: (id: string) =>
    request<{ improvement: Improvement; events: ImprovementEvent[]; rules: unknown[]; active: { rule_id: string; notes: string[] } }>(
      `/api/improvements/${encodeURIComponent(id)}`,
    ),
  transitionImprovement: (id: string, body: { to: ImprovementStatus; actor?: string; note?: string }) =>
    request<{ improvement: Improvement }>(`/api/improvements/${encodeURIComponent(id)}/transition`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  evaluateImprovement: (id: string) =>
    request<{ improvement: Improvement }>(`/api/improvements/${encodeURIComponent(id)}/evaluate`, { method: "POST" }),
  quality: () => request<QualityResponse>("/api/quality"),
  feedbackExportUrl: () => "/api/feedback/export",
  ask: (question: string, host?: string) =>
    request<AskResponse>("/api/ask", { method: "POST", body: JSON.stringify({ question, host }) }),
};

// --- remediation orchestration (ownership → routing → work items) -----------

export type RemediationState =
  | "detected"
  | "validated"
  | "awaiting_ownership"
  | "assigned"
  | "awaiting_approval"
  | "scheduled"
  | "in_progress"
  | "remediation_applied"
  | "pending_verification"
  | "resolved"
  | "failed"
  | "risk_accepted"
  | "false_positive";

export interface Ownership {
  asset: string;
  team?: string;
  owner?: string;
  service?: string;
  environment?: string;
  criticality?: string;
  exposure?: string;
  contact?: string;
  mechanism?: string;
  maintenance_window?: string;
  /** Connection details for a person, not credentials: user, host override, jump host. */
  ssh_user?: string;
  ssh_port?: number;
  ssh_host?: string;
  ssh_jump?: string;
  runbook_url?: string;
  source?: string;
  status: "owned" | "triage";
  updated_at: string;
}

/** One line of the ownership inventory: an asset, its record (if any), and its work. */
/** GitLab ticket tracked by Clanker Guard. GitLab remains the source of truth for state. */
/** One durable record of who did what. */
/** One dashboard account. Password hashes never leave the server. */
export interface Account {
  username: string;
  role: "viewer" | "operator" | "admin";
  disabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface AccessMe {
  authenticated: boolean;
  username: string;
  role: "" | "viewer" | "operator" | "admin";
  permissions: { read: boolean; write: boolean; admin: boolean };
  accounts: number;
}

export interface AuditEntry {
  seq: number;
  at: string;
  actor: string;
  action: string;
  target?: string;
  detail?: string;
  remote?: string;
}

/** Structured remediation plan: the same content the ticket body is rendered from. */
export interface RemediationCommand {
  lang: string;
  lines: string[];
}

export interface RemediationStep {
  title: string;
  detail?: string;
  commands?: RemediationCommand[];
  disruptive?: boolean;
}

export interface RemediationPlan {
  status: "verified" | "requires_review" | "no_fix" | "unsupported" | "needs_investigation";
  confidence: string;
  reason?: string;
  system: {
    hostname: string;
    asset_id: string;
    ip?: string;
    os?: string;
    os_version?: string;
    distro?: string;
    arch?: string;
    ssh_managed: boolean;
  };
  access: { host?: string; ssh_user?: string; ssh_host?: string; ssh_jump?: string; runbook?: string };
  cve: string;
  severity: string;
  package?: string;
  installed_version?: string;
  fixed_version?: string;
  advisory?: string;
  manager?: string;
  steps: RemediationStep[];
  verify?: RemediationCommand[];
  verify_note?: string;
  rollback?: RemediationCommand[];
  rollback_note?: string;
  prerequisites?: string[];
  warnings?: string[];
  disruptive: boolean;
}

export interface GitLabTicket {
  id: string;
  finding_key: string;
  asset: string;
  vulnerability_id: string;
  project_id: number;
  project_path?: string;
  issue_iid: number;
  issue_url: string;
  title: string;
  labels?: string;
  /** "opened" | "closed" as last read from GitLab. */
  state: string;
  assignee?: string;
  created_by?: string;
  /** Plan verdict when the issue was filed (verified, requires_review, no_fix, ...). */
  remediation_status?: string;
  created_at: string;
  last_synced_at?: string;
  pending: boolean;
  note?: string;
}

export interface GitLabProject {
  id: number;
  name: string;
  path_with_namespace: string;
  web_url: string;
  issues_enabled: boolean;
}

export interface GitLabCheck {
  name: string;
  ok: boolean;
  detail?: string;
  warning?: boolean;
}

export interface GitLabVerifyResult {
  ok: boolean;
  checks: GitLabCheck[];
  version?: string;
  user?: string;
  project?: GitLabProject;
  can_create_issues: boolean;
  summary: string;
}

export interface GitLabConfig {
  enabled: boolean;
  url: string;
  project_id: number;
  labels: string[] | null;
  assignee: string;
  timeout_seconds: number;
  allow_insecure_http: boolean;
  /** The token itself is never sent to the browser: only whether one is stored. */
  token_set: boolean;
  token_source: "file" | "environment";
  ready: boolean;
  blocked: string;
  verified_at?: string | null;
  verify_ok: boolean;
  verify_note: string;
  config_file: string;
}

export interface AssetOwnershipRow {
  asset: string;
  team?: string;
  owner?: string;
  service?: string;
  environment?: string;
  criticality?: string;
  exposure?: string;
  contact?: string;
  mechanism?: string;
  maintenance_window?: string;
  /** Connection details for a person, not credentials: user, host override, jump host. */
  ssh_user?: string;
  ssh_port?: number;
  ssh_host?: string;
  ssh_jump?: string;
  runbook_url?: string;
  source?: string;
  /** "owned" or "triage" when a record exists; absent when nobody has decided yet. */
  status?: string;
  updated_at?: string;
  items: number;
  open: number;
  critical: number;
  overdue: number;
  /** At least one open item has no team, so a decision is needed. */
  triaged: boolean;
  /** Teams the routing currently sends this asset's work to (not an accepted owner). */
  routed_teams?: string[];
}

export interface RemediationItem {
  id: string;
  asset: string;
  finding_key: string;
  vulnerability_id: string;
  product: string;
  installed_version: string;
  ecosystem: string;
  severity: string;
  category: string;
  team?: string;
  owner?: string;
  state: RemediationState;
  priority: string;
  due_at?: string;
  fixed_version?: string;
  remediation?: string;
  evidence: string;
  report_id: string;
  notes?: string;
  verified_report_id?: string;
  accept_reason?: string;
  accepted_by?: string;
  accept_expires_at?: string;
  first_seen: string;
  last_seen: string;
  updated_at: string;
  overdue: boolean;
}

/** One remediation unit: the findings on an asset that a single change closes. */
export interface RemediationGroup {
  key: string;
  asset: string;
  product: string;
  fixed_version?: string;
  team?: string;
  owner?: string;
  severity: string;
  priority: string;
  due_at?: string;
  items: number;
  critical: number;
  overdue: number;
  advisories: string[];
  item_ids: string[];
}

export interface ProcessMetrics {
  generated: string;
  open: number;
  overdue: number;
  unassigned: number;
  acceptances_due: number;
  age_buckets: { label: string; count: number }[];
  time_to_fix: { severity: string; resolved: number; median_days: number; p90_days: number }[];
  reopened: number;
  verified: number;
  units: number;
  findings: number;
}

export interface RemediationSummary {
  summary: {
    total: number;
    open: number;
    unassigned: number;
    overdue: number;
    triage_assets: number;
    resolved: number;
    by_state: Record<string, number>;
    by_team: Record<string, number>;
    by_priority: Record<string, number>;
    automation_eligible: number;
  };
  teams: string[];
  generated: string;
  automation: { enabled: boolean; reason: string };
}
