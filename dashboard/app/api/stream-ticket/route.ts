import { controlPlaneConfiguration, controlPlaneWebSocketURL, readLimitedText } from "../../../lib/api";

export const dynamic = "force-dynamic";

export async function POST(request: Request) {
  const origin = request.headers.get("origin");
  const fetchSite = request.headers.get("sec-fetch-site");
  if ((origin && origin !== new URL(request.url).origin) || fetchSite === "cross-site") {
    return Response.json({ error: "cross_origin_request" }, { status: 403, headers: noStoreHeaders() });
  }
  const configuration = controlPlaneConfiguration();
  if (configuration.error !== null) {
    return Response.json({ error: "control_plane_not_configured" }, { status: 503, headers: noStoreHeaders() });
  }

  try {
    const response = await fetch(new URL("/api/v1/stream-ticket", configuration.baseURL), {
      method: "POST",
      headers: { Authorization: `Bearer ${configuration.token}` },
      cache: "no-store",
      signal: AbortSignal.timeout(3_000),
    });
    if (!response.ok) {
      return Response.json({ error: "ticket_unavailable" }, { status: 503, headers: noStoreHeaders() });
    }
    const text = await readLimitedText(response, 8 << 10);
    const ticket: unknown = JSON.parse(text);
    if (!isTicket(ticket)) {
      return Response.json({ error: "invalid_ticket_response" }, { status: 502, headers: noStoreHeaders() });
    }
    const websocketURL = controlPlaneWebSocketURL(ticket.stream_url, configuration.baseURL);
    if (!websocketURL) {
      return Response.json({ error: "invalid_stream_url" }, { status: 503, headers: noStoreHeaders() });
    }
    return Response.json({ ticket: ticket.ticket, expires_at: ticket.expires_at, websocket_url: websocketURL.toString() }, {
      status: 201,
      headers: noStoreHeaders(),
    });
  } catch {
    return Response.json({ error: "ticket_unavailable" }, { status: 503, headers: noStoreHeaders() });
  }
}

function isTicket(value: unknown): value is { ticket: string; expires_at: string; stream_url: string } {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Record<string, unknown>;
  return typeof candidate.ticket === "string" && /^[A-Za-z0-9_-]{43}$/.test(candidate.ticket) &&
    typeof candidate.expires_at === "string" && candidate.expires_at.length <= 35 && !Number.isNaN(Date.parse(candidate.expires_at)) &&
    candidate.stream_url === "/api/v1/stream";
}

function noStoreHeaders() {
  return { "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" };
}
