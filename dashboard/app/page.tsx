import { loadOverview, type OverviewData } from "../lib/api";

export const dynamic = "force-dynamic";

export default async function OverviewPage() {
  const result = await loadOverview();
  const overview = result.data;

  return (
    <>
      <header className="page-header">
        <div>
          <h2>Overview</h2>
          <p>Current Agent runs, policy pressure, and kernel event flow from the read-only control-plane API.</p>
        </div>
        <span className={`pill ${overview ? "ok" : "danger"}`}>
          {overview ? "control plane: connected" : "control plane: unavailable"}
        </span>
      </header>

      {result.error ? <div className="notice danger-notice" role="status">{result.error}</div> : null}

      <section className="status-strip" aria-label="Runtime metrics">
        {metricRows(overview).map((metric) => (
          <div className="metric" key={metric.label}>
            <span>{metric.label}</span>
            <strong>{metric.value}</strong>
          </div>
        ))}
      </section>

      <section className="grid-two">
        <div className="panel">
          <div className="panel-header">
            <h3>Agent runs</h3>
            <span className="pill">{overview ? `${overview.runs.length} total` : "no data"}</span>
          </div>
          <div className="panel-body table-scroll">
            {overview && overview.runs.length > 0 ? (
              <table className="table">
                <thead>
                  <tr><th>Run</th><th>Status</th><th>Started</th><th>Events</th><th>Blocked</th></tr>
                </thead>
                <tbody>
                  {overview.runs.map((run) => (
                    <tr key={run.run_id}>
                      <td><strong>{run.label || run.run_id}</strong><code className="subtle-code">{run.run_id}</code></td>
                      <td><span className={`pill ${statusClass(run.status)}`}>{run.status}</span></td>
                      <td>{formatTimestamp(run.started_at)}</td>
                      <td className="numeric">{formatDecimal(run.event_count)}</td>
                      <td className="numeric">{formatDecimal(run.blocked_count)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : <EmptyState text={overview ? "No Agent runs have been registered." : "Run data is unavailable until the API connection is configured."} />}
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h3>Runtime capabilities</h3>
            <span className="pill">live state</span>
          </div>
          <div className="panel-body capability-list">
            {overview && overview.capabilities.length > 0 ? overview.capabilities.map((capability) => (
              <div className="capability-row" key={capability.name}>
                <div><strong>{capability.name}</strong><p>{capability.detail}</p></div>
                <span className={`pill ${statusClass(capability.status)}`}>{capability.status}</span>
              </div>
            )) : <EmptyState text={overview ? "No capability probes have reported yet." : "Capability data is unavailable."} />}
          </div>
        </div>
      </section>

      {overview ? <p className="freshness">Snapshot generated {formatTimestamp(overview.generated_at)}</p> : null}
    </>
  );
}

function metricRows(overview: OverviewData | null) {
  return [
    { label: "Active runs", value: overview ? formatDecimal(overview.counts.active_runs) : "—" },
    { label: "Kernel events", value: overview ? formatDecimal(overview.counts.kernel_events) : "—" },
    { label: "Policy hits", value: overview ? formatDecimal(overview.counts.policy_hits) : "—" },
    { label: "Blocked", value: overview ? formatDecimal(overview.counts.blocked) : "—" },
  ];
}

function formatDecimal(value: string) {
  return BigInt(value).toLocaleString("en-US");
}

function formatTimestamp(value: string) {
  return new Intl.DateTimeFormat("en", { dateStyle: "medium", timeStyle: "medium", timeZone: "UTC" }).format(new Date(value));
}

function statusClass(status: string) {
  if (status === "active" || status === "available" || status === "finished") return "ok";
  if (status === "failed" || status === "unavailable") return "danger";
  return "";
}

function EmptyState({ text }: { text: string }) {
  return <p className="empty-state">{text}</p>;
}
