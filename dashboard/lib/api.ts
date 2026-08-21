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

export type APIResult<T> = { data: T; error: null } | { data: null; error: string };

const decimalString = /^(0|[1-9][0-9]*)$/;
const maximumResponseBytes = 1 << 20;

export async function loadOverview(): Promise<APIResult<OverviewData>> {
  const configuration = controlPlaneConfiguration();
  if (configuration.error !== null) {
    return { data: null, error: configuration.error };
  }

  try {
    const endpoint = new URL("/api/v1/overview", configuration.baseURL);
    const response = await fetch(endpoint, {
      headers: { Authorization: `Bearer ${configuration.token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(3_000),
    });
    if (!response.ok) {
      return { data: null, error: `Control plane returned HTTP ${response.status}.` };
    }
    const text = await readLimitedText(response);
    const parsed: unknown = JSON.parse(text);
    if (!isOverviewData(parsed)) {
      return { data: null, error: "Control plane returned an incompatible overview schema." };
    }
    return { data: parsed, error: null };
  } catch (error) {
    if (error instanceof Error && error.message === "response_too_large") {
      return { data: null, error: "Control plane response exceeded the dashboard limit." };
    }
    return { data: null, error: "Control plane is unavailable." };
  }
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

async function readLimitedText(response: Response): Promise<string> {
  const declaredLength = Number(response.headers.get("content-length") ?? "0");
  if (declaredLength > maximumResponseBytes) throw new Error("response_too_large");
  if (!response.body) return "";

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytes = 0;
  let text = "";
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > maximumResponseBytes) {
      await reader.cancel();
      throw new Error("response_too_large");
    }
    text += decoder.decode(value, { stream: true });
  }
  return text + decoder.decode();
}
