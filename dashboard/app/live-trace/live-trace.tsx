"use client";

import Link from "next/link";
import { useEffect, useRef, useState, type FormEvent } from "react";

type Filters = { runID: string; severity: string; eventType: string; includeAudit: boolean };
type ConnectionState = "connecting" | "live" | "reconnecting" | "resync";
type StreamMessage = {
  schema_version: "1";
  sequence: string;
  resume_cursor: string;
  id: string;
  type: string;
  source?: string;
  run_id?: string;
  severity?: string;
  event_type?: string;
  server_monotonic_ns: string;
  server_unix_ns: string;
  payload: Record<string, unknown>;
};

const emptyFilters: Filters = { runID: "", severity: "", eventType: "", includeAudit: true };
const decimal = /^(0|[1-9][0-9]*)$/;
const maxUint64 = BigInt("18446744073709551615");
const nanosecondsPerSecond = BigInt(1_000_000_000);
const millisecondsPerSecond = BigInt(1_000);
const maximumDateMilliseconds = BigInt("8640000000000000");

export function LiveTrace() {
  const [draft, setDraft] = useState(emptyFilters);
  const [filters, setFilters] = useState(emptyFilters);
  const [connection, setConnection] = useState<ConnectionState>("connecting");
  const [statusDetail, setStatusDetail] = useState("Requesting a one-time stream ticket.");
  const [messages, setMessages] = useState<StreamMessage[]>([]);
  const cursor = useRef("");

  useEffect(() => {
    let disposed = false;
    let socket: WebSocket | null = null;
    let ticketAbort: AbortController | null = null;
    let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
    let attempt = 0;
    cursor.current = "";

    const scheduleReconnect = (detail = "Connection closed; retrying with the last committed cursor.") => {
      if (disposed) return;
      attempt += 1;
      setConnection("reconnecting");
      setStatusDetail(detail);
      reconnectTimer = setTimeout(connect, Math.min(1_000 * 2 ** (attempt - 1), 10_000));
    };

    const connect = async () => {
      if (disposed) return;
      setConnection(attempt === 0 ? "connecting" : "reconnecting");
      try {
        ticketAbort = new AbortController();
        const response = await fetch("/api/stream-ticket", {
          method: "POST", cache: "no-store", credentials: "same-origin", signal: ticketAbort.signal,
        });
        const body: unknown = await response.json();
        if (!response.ok || !isTicketResponse(body)) throw new Error("ticket unavailable");
        if (disposed) return;

        const endpoint = new URL(body.websocket_url);
        endpoint.searchParams.set("ticket", body.ticket);
        if (cursor.current) endpoint.searchParams.set("cursor", cursor.current);
        if (filters.runID) endpoint.searchParams.set("run_id", filters.runID);
        if (filters.severity) endpoint.searchParams.set("severity", filters.severity);
        if (filters.eventType) endpoint.searchParams.set("event_type", filters.eventType);
        endpoint.searchParams.set("include_audit", String(filters.includeAudit));

        socket = new WebSocket(endpoint);
        socket.onopen = () => {
          if (disposed) return;
          attempt = 0;
          setConnection("live");
          setStatusDetail("Authenticated stream connected.");
        };
        socket.onmessage = (event) => {
          if (disposed || typeof event.data !== "string") return;
          let parsed: unknown;
          try { parsed = JSON.parse(event.data); } catch { return; }
          if (!isStreamMessage(parsed)) return;
          if (parsed.type === "resync_required") {
            cursor.current = "";
            setMessages([]);
            setConnection("resync");
            setStatusDetail("Recovery window expired; cleared stale rows and will resume from live data.");
            return;
          }
          cursor.current = parsed.resume_cursor;
          setMessages((current) => [parsed, ...current].slice(0, 500));
        };
        socket.onerror = () => socket?.close();
        socket.onclose = () => scheduleReconnect();
      } catch {
        if (disposed) return;
        scheduleReconnect("The stream ticket or control plane is unavailable; retrying.");
      }
    };

    void connect();
    return () => {
      disposed = true;
      ticketAbort?.abort();
      if (reconnectTimer) clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [filters]);

  function applyFilters(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessages([]);
    setFilters({ ...draft });
  }

  return (
    <>
      <header className="page-header">
        <div>
          <h2>Live Trace</h2>
          <p>Authenticated Agent and kernel records, newest first. Sequence, clocks, and cgroup identities remain decimal strings.</p>
        </div>
        <span className={`pill ${connection === "live" ? "ok" : ""}`}>{connection}</span>
      </header>

      <form className="trace-filters" onSubmit={applyFilters}>
        <label>Run<input maxLength={128} value={draft.runID} onChange={(event) => setDraft({ ...draft, runID: event.target.value })} placeholder="all runs" /></label>
        <label>Severity<select value={draft.severity} onChange={(event) => setDraft({ ...draft, severity: event.target.value })}><option value="">all</option><option value="info">info</option><option value="medium">medium</option><option value="high">high</option></select></label>
        <label>Event type<input maxLength={64} value={draft.eventType} onChange={(event) => setDraft({ ...draft, eventType: event.target.value })} placeholder="exec_attempt" /></label>
        <label className="checkbox-label"><input type="checkbox" checked={draft.includeAudit} onChange={(event) => setDraft({ ...draft, includeAudit: event.target.checked })} />Include audit</label>
        <button type="submit">Apply filters</button>
      </form>

      <p className="stream-status" role="status">{statusDetail}</p>

      <section className="panel">
        <div className="panel-header"><h3>Trace stream</h3><span className="pill">{messages.length} / 500 rows</span></div>
        <div className="panel-body trace-list" aria-live="polite">
          {messages.length > 0 ? messages.map((message) => (
            <article className={`trace-row ${message.severity ?? "info"}`} key={`${message.sequence}-${message.id}`}>
              <div className="trace-heading"><strong>{formatUnixNS(message.server_unix_ns)} · {message.event_type ?? message.type}</strong><span className="pill">seq {message.sequence}</span></div>
              <code>{recordSubject(message.payload)}</code>
              <span>{message.run_id ? <Link className="inline-link" href={`/evidence/${encodeURIComponent(message.run_id)}`}>{message.run_id}</Link> : "unattributed"} · {message.source ?? "unknown source"}{cgroupIdentity(message.payload)}</span>
            </article>
          )) : <p className="empty-state">No matching live records received. Start the configured sandbox or adjust filters.</p>}
        </div>
      </section>
    </>
  );
}

function isTicketResponse(value: unknown): value is { ticket: string; expires_at: string; websocket_url: string } {
  if (!isRecord(value)) return false;
  return typeof value.ticket === "string" && /^[A-Za-z0-9_-]{43}$/.test(value.ticket) &&
    typeof value.expires_at === "string" && typeof value.websocket_url === "string" &&
    (value.websocket_url.startsWith("ws://") || value.websocket_url.startsWith("wss://"));
}

function isStreamMessage(value: unknown): value is StreamMessage {
  if (!isRecord(value) || value.schema_version !== "1" || !isRecord(value.payload)) return false;
  const required = [value.sequence, value.resume_cursor, value.server_monotonic_ns, value.server_unix_ns];
  return required.every(isUint64String) && typeof value.id === "string" && value.id.length <= 128 &&
    typeof value.type === "string" && value.type.length <= 64 && optionalString(value.source, 32) &&
    optionalString(value.run_id, 128) && optionalString(value.severity, 32) && optionalString(value.event_type, 64);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function optionalString(value: unknown, limit: number) {
  return value === undefined || (typeof value === "string" && value.length <= limit);
}

function isUint64String(value: unknown): value is string {
  if (typeof value !== "string" || value.length > 20 || !decimal.test(value)) return false;
  return BigInt(value) <= maxUint64;
}

function formatUnixNS(value: string) {
  if (!isUint64String(value)) return "invalid time";
  const nanoseconds = BigInt(value);
  const seconds = nanoseconds / nanosecondsPerSecond;
  const milliseconds = seconds * millisecondsPerSecond;
  if (milliseconds > maximumDateMilliseconds) return `${value} ns`;
  const base = new Date(Number(milliseconds)).toISOString().slice(0, 19);
  const fraction = (nanoseconds % nanosecondsPerSecond).toString().padStart(9, "0");
  return `${base}.${fraction}Z`;
}

function recordSubject(payload: Record<string, unknown>) {
  for (const key of ["summary", "data", "error"]) {
    const value = payload[key];
    if (typeof value === "string" && value) return value;
  }
  if (typeof payload.dst_ip === "string") return `${payload.dst_ip}:${String(payload.dst_port ?? "?")}`;
  return "Structured record";
}

function cgroupIdentity(payload: Record<string, unknown>) {
  return typeof payload.cgroup_id === "string" && decimal.test(payload.cgroup_id) ? ` · cgroup ${payload.cgroup_id}` : "";
}
