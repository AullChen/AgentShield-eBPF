import { policies } from "../../lib/mock-data";

export default function PoliciesPage() {
  return (
    <>
      <header className="page-header">
        <div>
          <h2>Policies</h2>
          <p>Runtime rules for files, processes, network egress, and fallback actions.</p>
        </div>
        <span className="pill">read only</span>
      </header>

      <section className="panel">
        <div className="panel-header">
          <h3>Default policy set</h3>
          <span className="pill ok">3 rules</span>
        </div>
        <div className="panel-body">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Scope</th>
                <th>Mode</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {policies.map((policy) => (
                <tr key={policy.name}>
                  <td>{policy.name}</td>
                  <td>{policy.scope}</td>
                  <td>{policy.mode}</td>
                  <td>
                    <span className={`pill ${policy.status === "enabled" ? "ok" : ""}`}>
                      {policy.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
