export type OverviewCounts = {
  active_runs: string;
  kernel_events: string;
  policy_hits: string;
  blocked: string;
};

export type OverviewRun = {
  run_id: string;
  label: string;
  status: "active" | "finished" | "failed";
  started_at: string;
  last_event_at?: string;
  event_count: string;
  blocked_count: string;
};

export type OverviewCapability = {
  name: string;
  status: "available" | "degraded" | "unavailable" | "unknown";
  detail: string;
};

export type OverviewData = {
  schema_version: "1";
  generated_at: string;
  counts: OverviewCounts;
  runs: OverviewRun[];
  capabilities: OverviewCapability[];
};

export type EvidenceSource = "agent_claim" | "kernel_fact" | "policy_decision" | "containment_result";

export type EvidenceAttribution = {
  status: string;
  run_id?: string;
  run_status?: string;
  basis: string;
};

export type EvidenceCorrelation = {
  selected_checkpoint_id?: string;
  confidence: number;
  conflict: boolean;
  correlation_status: string;
  authoritative_clock: string;
};

export type EvidenceOperation = {
  attempt_observed: boolean;
  action_result: string;
  mechanism: string;
};

export type EvidenceDecision = {
  policy_id: string;
  rule_id: string;
  requested_action: string;
  final_decision: string;
  enforced: boolean;
  mechanism: string;
};

export type EvidenceContainment = {
  requested: boolean;
  result: string;
  method: string;
  target_identity: string;
  original_action_result: string;
};

export type EvidenceItem = {
  sequence: string;
  id: string;
  type: string;
  source: EvidenceSource;
  server_monotonic_ns: string;
  server_unix_ns: string;
  summary: string;
  attribution?: EvidenceAttribution;
  correlation?: EvidenceCorrelation;
  operation?: EvidenceOperation;
  decision?: EvidenceDecision;
  containment?: EvidenceContainment;
};

export type EvidenceData = {
  schema_version: "1";
  run_id: string;
  items: EvidenceItem[];
};

export type PolicySummary = {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  scope: string;
  decision: string;
  requested_action: string;
  severity: string;
  condition: "file" | "exec" | "network";
  priority: number;
};

export type PolicyData = {
  schema_version: "1";
  generated_at: string;
  configured: boolean;
  generation: { revision: string; bank: string };
  policies: PolicySummary[];
};

export type APIResult<T> = { data: T; error: null } | { data: null; error: string };

const decimalString = /^(0|[1-9][0-9]*)$/;
const maximumResponseBytes = 1 << 20;

export async function loadOverview(): Promise<APIResult<OverviewData>> {
  return loadControlPlane("/api/v1/overview", isOverviewData, "overview");
}

export async function loadEvidence(runID: string): Promise<APIResult<EvidenceData>> {
  if (!isShortString(runID, 128)) {
    return { data: null, error: "Run ID is invalid." };
  }
  return loadControlPlane(`/api/v1/evidence/${encodeURIComponent(runID)}`, isEvidenceData, "evidence");
}

export async function loadPolicies(): Promise<APIResult<PolicyData>> {
  return loadControlPlane("/api/v1/policies", isPolicyData, "policy");
}

async function loadControlPlane<T>(path: string, validate: (value: unknown) => value is T, schemaName: string): Promise<APIResult<T>> {
  const configuration = controlPlaneConfiguration();
  if (configuration.error !== null) {
    return { data: null, error: configuration.error };
  }

  try {
    const endpoint = new URL(path, configuration.baseURL);
    const response = await fetch(endpoint, {
      headers: { Authorization: `Bearer ${configuration.token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(3_000),
    });
    if (!response.ok) {
      return { data: null, error: `Control plane returned HTTP ${response.status}.` };
    }
    const text = await readLimitedText(response, maximumResponseBytes);
    const parsed: unknown = JSON.parse(text);
    if (!validate(parsed)) {
      return { data: null, error: `Control plane returned an incompatible ${schemaName} schema.` };
    }
    return { data: parsed, error: null };
  } catch (error) {
    if (error instanceof Error && error.message === "response_too_large") {
      return { data: null, error: "Control plane response exceeded the dashboard limit." };
    }
    return { data: null, error: "Control plane is unavailable." };
  }
}

function isEvidenceData(value: unknown): value is EvidenceData {
  return isRecord(value) && value.schema_version === "1" && isShortString(value.run_id, 128) &&
    Array.isArray(value.items) && value.items.length <= 10_000 && value.items.every(isEvidenceItem);
}

function isEvidenceItem(value: unknown): value is EvidenceItem {
  if (!isRecord(value) || !isDecimalString(value.sequence) || !isShortString(value.id, 128) ||
      !isShortString(value.type, 64) || !isEvidenceSource(value.source) ||
      !isDecimalString(value.server_monotonic_ns) || !isDecimalString(value.server_unix_ns) ||
      !isBoundedString(value.summary, 4096)) {
    return false;
  }
  return (value.attribution === undefined || isEvidenceAttribution(value.attribution)) &&
    (value.correlation === undefined || isEvidenceCorrelation(value.correlation)) &&
    (value.operation === undefined || isEvidenceOperation(value.operation)) &&
    (value.decision === undefined || isEvidenceDecision(value.decision)) &&
    (value.containment === undefined || isEvidenceContainment(value.containment));
}

function isEvidenceSource(value: unknown): value is EvidenceSource {
  return value === "agent_claim" || value === "kernel_fact" || value === "policy_decision" || value === "containment_result";
}

function isEvidenceAttribution(value: unknown): value is EvidenceAttribution {
  return isRecord(value) && isShortString(value.status, 32) && isBoundedString(value.basis, 256) &&
    (value.run_id === undefined || isShortString(value.run_id, 128)) &&
    (value.run_status === undefined || isShortString(value.run_status, 32));
}

function isEvidenceCorrelation(value: unknown): value is EvidenceCorrelation {
  return isRecord(value) && (value.selected_checkpoint_id === undefined || isShortString(value.selected_checkpoint_id, 128)) &&
    typeof value.confidence === "number" && Number.isInteger(value.confidence) && value.confidence >= 0 && value.confidence <= 100 &&
    typeof value.conflict === "boolean" && isShortString(value.correlation_status, 32) &&
    isShortString(value.authoritative_clock, 64);
}

function isEvidenceOperation(value: unknown): value is EvidenceOperation {
  return isRecord(value) && typeof value.attempt_observed === "boolean" &&
    isShortString(value.action_result, 32) && isShortString(value.mechanism, 128);
}

function isEvidenceDecision(value: unknown): value is EvidenceDecision {
  return isRecord(value) && isShortString(value.policy_id, 128) && isShortString(value.rule_id, 32) &&
    isShortString(value.requested_action, 32) && isShortString(value.final_decision, 32) &&
    typeof value.enforced === "boolean" && isShortString(value.mechanism, 128);
}

function isEvidenceContainment(value: unknown): value is EvidenceContainment {
  return isRecord(value) && typeof value.requested === "boolean" && isShortString(value.result, 32) &&
    isShortString(value.method, 128) && isShortString(value.target_identity, 256) &&
    isShortString(value.original_action_result, 32);
}

function isPolicyData(value: unknown): value is PolicyData {
  if (!isRecord(value) || value.schema_version !== "1" || !isRFC3339(value.generated_at) ||
      typeof value.configured !== "boolean" || !isRecord(value.generation) ||
      typeof value.generation.revision !== "string" || typeof value.generation.bank !== "string" ||
      !Array.isArray(value.policies) || value.policies.length > 256 || !value.policies.every(isPolicySummary)) {
    return false;
  }
  return value.configured ? isDecimalString(value.generation.revision) && value.generation.revision !== "0" &&
    (value.generation.bank === "A" || value.generation.bank === "B") :
    value.generation.revision === "" && value.generation.bank === "" && value.policies.length === 0;
}

function isPolicySummary(value: unknown): value is PolicySummary {
  return isRecord(value) && isShortString(value.id, 128) && isShortString(value.name, 256) &&
    (value.description === undefined || isBoundedString(value.description, 2048)) && typeof value.enabled === "boolean" &&
    isShortString(value.scope, 1024) && isShortString(value.decision, 32) && isShortString(value.requested_action, 32) &&
    isShortString(value.severity, 32) && (value.condition === "file" || value.condition === "exec" || value.condition === "network") &&
    typeof value.priority === "number" && Number.isSafeInteger(value.priority);
}

export function controlPlaneConfiguration():
  | { baseURL: URL; token: string; error: null }
  | { baseURL: null; token: null; error: string } {
  const rawURL = process.env.AGENTSHIELD_API_URL;
  const token = process.env.AGENTSHIELD_READ_TOKEN;
  if (!rawURL || !token) {
    return { baseURL: null, token: null, error: "Set AGENTSHIELD_API_URL and AGENTSHIELD_READ_TOKEN to connect the dashboard." };
  }
  if (token.length < 24 || token.length > 512 || /\s/.test(token)) {
    return { baseURL: null, token: null, error: "AGENTSHIELD_READ_TOKEN is invalid." };
  }
  try {
    const baseURL = new URL(rawURL);
    const loopback = baseURL.hostname === "localhost" || baseURL.hostname === "127.0.0.1" || baseURL.hostname === "[::1]";
    if (baseURL.protocol !== "https:" && !(baseURL.protocol === "http:" && loopback)) {
      return { baseURL: null, token: null, error: "The control plane must use HTTPS unless it is on loopback." };
    }
    if (baseURL.username || baseURL.password || baseURL.search || baseURL.hash) {
      return { baseURL: null, token: null, error: "AGENTSHIELD_API_URL must not contain credentials, a query, or a fragment." };
    }
    return { baseURL, token, error: null };
  } catch {
    return { baseURL: null, token: null, error: "AGENTSHIELD_API_URL is invalid." };
  }
}

function isOverviewData(value: unknown): value is OverviewData {
  if (!isRecord(value) || value.schema_version !== "1" || !isRFC3339(value.generated_at) ||
      !isRecord(value.counts) || !Array.isArray(value.runs) || value.runs.length > 1_000 ||
      !Array.isArray(value.capabilities) || value.capabilities.length > 128) {
    return false;
  }
  const counts = value.counts;
  if (![counts.active_runs, counts.kernel_events, counts.policy_hits, counts.blocked].every(isDecimalString)) {
    return false;
  }
  return value.runs.every(isOverviewRun) && value.capabilities.every(isOverviewCapability);
}

function isOverviewRun(value: unknown): value is OverviewRun {
  return isRecord(value) && isShortString(value.run_id, 128) && isBoundedString(value.label, 128) &&
    (value.status === "active" || value.status === "finished" || value.status === "failed") &&
    isRFC3339(value.started_at) && (value.last_event_at === undefined || isRFC3339(value.last_event_at)) &&
    isDecimalString(value.event_count) && isDecimalString(value.blocked_count);
}

function isOverviewCapability(value: unknown): value is OverviewCapability {
  return isRecord(value) && isShortString(value.name, 64) && isBoundedString(value.detail, 256) &&
    (value.status === "available" || value.status === "degraded" || value.status === "unavailable" || value.status === "unknown");
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isDecimalString(value: unknown): value is string {
  return typeof value === "string" && value.length <= 20 && decimalString.test(value);
}

function isShortString(value: unknown, limit: number): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= limit;
}

function isBoundedString(value: unknown, limit: number): value is string {
  return typeof value === "string" && value.length <= limit;
}

function isRFC3339(value: unknown): value is string {
  return typeof value === "string" && value.length <= 35 && !Number.isNaN(Date.parse(value));
}

export async function readLimitedText(response: Response, maximumBytes: number): Promise<string> {
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (maximumBytes < 1 || declaredLength > maximumBytes) throw new Error("response_too_large");
  if (!response.body) return "";

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > maximumBytes) {
      await reader.cancel();
      throw new Error("response_too_large");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}

export function controlPlaneWebSocketURL(streamPath: string, baseURL: URL): URL | null {
  try {
    const configured = process.env.AGENTSHIELD_STREAM_URL;
    const endpoint = configured ? new URL(configured) : new URL(streamPath, baseURL);
    if (!configured) endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
    const loopback = endpoint.hostname === "localhost" || endpoint.hostname === "127.0.0.1" || endpoint.hostname === "[::1]";
    if (endpoint.protocol !== "wss:" && !(endpoint.protocol === "ws:" && loopback)) return null;
    if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== "/api/v1/stream") return null;
    return endpoint;
  } catch {
    return null;
  }
}
