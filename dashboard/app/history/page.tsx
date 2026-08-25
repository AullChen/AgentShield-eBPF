import Link from "next/link";
import { loadOverview } from "../../lib/api";

export const dynamic = "force-dynamic";

export default async function HistoryPage() {
  const result = await loadOverview();
  const overview = result.data;
  return (
    <>
      <header className="page-header">
        <div>
          <h2>History</h2>
          <p>Open the bounded evidence snapshot for a known Run. Durable SQLite queries remain a separate capability.</p>
        </div>
        <span className="pill">live recovery window</span>
      </header>

      {result.error ? <div className="notice danger-notice" role="status">{result.error}</div> : null}

      <section className="panel">
        <div className="panel-header">
          <h3>Run evidence index</h3>
          <span className="pill">{overview ? `${overview.runs.length} runs` : "no data"}</span>
        </div>
        <div className="panel-body table-scroll">
          {overview && overview.runs.length > 0 ? <table className="table">
            <thead>
              <tr>
                <th>Run</th>
                <th>Status</th>
                <th>Events</th>
                <th>Blocked</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {overview.runs.map((run) => (
                <tr key={run.run_id}>
                  <td><strong>{run.label || run.run_id}</strong><code className="subtle-code">{run.run_id}</code></td>
                  <td><span className={`pill ${run.status === "active" ? "ok" : ""}`}>{run.status}</span></td>
                  <td className="numeric">{BigInt(run.event_count).toLocaleString("en-US")}</td>
                  <td className="numeric">{BigInt(run.blocked_count).toLocaleString("en-US")}</td>
                  <td><Link className="table-link" href={`/evidence/${encodeURIComponent(run.run_id)}`}>Inspect sources →</Link></td>
                </tr>
              ))}
            </tbody>
          </table> : <p className="empty-state">{overview ? "No Runs are registered." : "Run evidence is unavailable until the control plane is connected."}</p>}
        </div>
      </section>
    </>
  );
}
