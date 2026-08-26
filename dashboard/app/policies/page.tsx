import { loadPolicies } from "../../lib/api";
import { RefreshPolicies } from "./refresh-policies";

export const dynamic = "force-dynamic";

export default async function PoliciesPage() {
  const result = await loadPolicies();
  const catalog = result.data;
  const enabled = catalog?.policies.filter((policy) => policy.enabled).length ?? 0;
  return (
    <>
      <header className="page-header">
        <div>
          <h2>Policies</h2>
          <p>The currently loaded runtime bundle. Refreshing this view does not mutate or reload policy state.</p>
        </div>
        <div className="header-actions"><span className="pill">read only</span><RefreshPolicies /></div>
      </header>

      {result.error ? <div className="notice danger-notice" role="status">{result.error}</div> : null}

      <section className="status-strip policy-status" aria-label="Policy status">
        <div className="metric"><span>Configured policies</span><strong>{catalog ? catalog.policies.length : "—"}</strong></div>
        <div className="metric"><span>Enabled</span><strong>{catalog ? enabled : "—"}</strong></div>
        <div className="metric"><span>Generation</span><strong>{catalog?.configured ? catalog.generation.revision : "—"}</strong></div>
        <div className="metric"><span>Bank</span><strong>{catalog?.configured ? catalog.generation.bank : "—"}</strong></div>
      </section>

      <section className="panel">
        <div className="panel-header">
          <h3>Active policy catalog</h3>
          <span className={`pill ${catalog?.configured ? "ok" : ""}`}>{catalog?.configured ? "bundle loaded" : "not configured"}</span>
        </div>
        <div className="panel-body table-scroll">
          {catalog && catalog.policies.length > 0 ? <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Scope</th>
                <th>Condition</th>
                <th>Decision / action</th>
                <th>Severity</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {catalog.policies.map((policy) => (
                <tr key={policy.id}>
                  <td><strong>{policy.name}</strong><code className="subtle-code">{policy.id} · priority {policy.priority}</code></td>
                  <td>{policy.scope}</td>
                  <td>{policy.condition}</td>
                  <td><strong>{policy.decision}</strong><code className="subtle-code">{policy.requested_action}</code></td>
                  <td>{policy.severity}</td>
                  <td>
                    <span className={`pill ${policy.enabled ? "ok" : ""}`}>
                      {policy.enabled ? "enabled" : "disabled"}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table> : <p className="empty-state">{catalog ? "No policy bundle is configured for this audit process. Start it with --policy-file to populate this read-only catalog." : "Policy data is unavailable until the control plane is connected."}</p>}
        </div>
      </section>

      {catalog ? <p className="freshness">Snapshot generated {new Date(catalog.generated_at).toISOString().replace("T", " ").replace("Z", " UTC")}</p> : null}
    </>
  );
}
