import { diagnostics } from "../../lib/mock-data";

export default function DiagnosticsPage() {
  return (
    <>
      <header className="page-header">
        <div>
          <h2>Diagnostics</h2>
          <p>Kernel capability checks, hook state, map health, and event drops.</p>
        </div>
        <span className="pill">api pending</span>
      </header>

      <section className="panel">
        <div className="panel-header">
          <h3>Capability report</h3>
          <span className="pill">local</span>
        </div>
        <div className="panel-body">
          <table className="table">
            <thead>
              <tr>
                <th>Check</th>
                <th>Status</th>
                <th>Detail</th>
              </tr>
            </thead>
            <tbody>
              {diagnostics.map((check) => (
                <tr key={check.name}>
                  <td>{check.name}</td>
                  <td>
                    <span className="pill">{check.status}</span>
                  </td>
                  <td>{check.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
