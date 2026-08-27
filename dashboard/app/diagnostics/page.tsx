import { loadDiagnostics } from "../../lib/api";

export const dynamic = "force-dynamic";

export default async function DiagnosticsPage() {
  const result = await loadDiagnostics();
  const diagnostics = result.data;
  return (
    <>
      <header className="page-header">
        <div>
          <h2>Diagnostics</h2>
          <p>Environment checks, the actual Go load/attach result, hook state, active generation, and per-type event loss.</p>
        </div>
        <span className={`pill ${statusClass(diagnostics?.load_attach.status)}`}>{diagnostics ? `load/attach: ${diagnostics.load_attach.status}` : "diagnostics unavailable"}</span>
      </header>

      {result.error ? <div className="notice danger-notice" role="status">{result.error}</div> : null}

      <section className="status-strip" aria-label="Runtime platform">
        <div className="metric"><span>Operating system</span><strong>{diagnostics?.os ?? "—"}</strong></div>
        <div className="metric"><span>Architecture</span><strong>{diagnostics?.arch ?? "—"}</strong></div>
        <div className="metric"><span>Byte order</span><strong>{diagnostics?.byte_order ?? "—"}</strong></div>
        <div className="metric"><span>Policy generation</span><strong>{diagnostics?.policy_generation.revision || "—"}</strong></div>
      </section>

      {diagnostics ? <div className={`notice ${diagnostics.load_attach.status === "unavailable" ? "danger-notice" : "probe-notice"}`}>
        <strong>Actual load/attach probe: {diagnostics.load_attach.status}</strong><br />{diagnostics.load_attach.detail}
      </div> : null}

      <section className="panel">
        <div className="panel-header">
          <h3>Capability report</h3>
          <span className="pill">environment evidence</span>
        </div>
        <div className="panel-body table-scroll">
          {diagnostics ? <table className="table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {diagnostics.checks.map((check) => (
                <tr key={check.name}>
                  <td>{check.name}</td>
                  <td>
                    <span className={`pill ${statusClass(check.status)}`}>{check.status}</span>
                  </td>
                  <td><strong>{check.message}</strong>{check.details ? <code className="diagnostic-details">{formatDetails(check.details)}</code> : null}</td>
                </tr>
              ))}
            </tbody>
          </table> : <p className="empty-state">Capability data is unavailable until the control plane is connected.</p>}
        </div>
      </section>

      <section className="grid-two diagnostics-grid">
        <div className="panel">
          <div className="panel-header"><h3>Configured hooks</h3><span className="pill">Go loader</span></div>
          <div className="panel-body capability-list">
            {diagnostics && diagnostics.hooks.length > 0 ? diagnostics.hooks.map((hook) => (
              <div className="capability-row" key={hook.name}><div><strong>{hook.name}</strong><p>{hook.detail}</p></div><span className={`pill ${statusClass(hook.status)}`}>{hook.status}</span></div>
            )) : <p className="empty-state">No hook status is available.</p>}
          </div>
        </div>
        <div className="panel">
          <div className="panel-header"><h3>Event loss</h3><span className={`pill ${diagnostics && diagnostics.drops.length > 0 ? "danger" : "ok"}`}>{diagnostics ? `${diagnostics.drops.length} affected types` : "no data"}</span></div>
          <div className="panel-body">
            {diagnostics && diagnostics.drops.length > 0 ? <table className="table"><thead><tr><th>Event type</th><th>Dropped</th></tr></thead><tbody>{diagnostics.drops.map((drop) => <tr key={drop.event_type}><td>{drop.event_type}</td><td className="numeric">{BigInt(drop.count).toLocaleString("en-US")}</td></tr>)}</tbody></table> : <p className="empty-state">{diagnostics ? "No per-type drop notices have been observed in this process." : "Drop counters are unavailable."}</p>}
          </div>
        </div>
      </section>

      {diagnostics ? <p className="freshness">Snapshot generated {new Date(diagnostics.generated_at).toISOString().replace("T", " ").replace("Z", " UTC")}</p> : null}
    </>
  );
}

function statusClass(status?: string) {
  if (status === "pass" || status === "available" || status === "attached") return "ok";
  if (status === "fail" || status === "unavailable" || status === "not_attached") return "danger";
  return "";
}

function formatDetails(details: Record<string, string>) {
  return Object.entries(details).sort(([left], [right]) => left.localeCompare(right)).map(([key, value]) => `${key}=${value}`).join(" · ");
}
