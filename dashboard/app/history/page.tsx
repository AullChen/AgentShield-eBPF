import { recentEvents } from "../../lib/mock-data";

export default function HistoryPage() {
  return (
    <>
      <header className="page-header">
        <div>
          <h2>History</h2>
          <p>Persisted evidence chains will be searchable by run, severity, action, and policy.</p>
        </div>
        <span className="pill">sqlite pending</span>
      </header>

      <section className="panel">
        <div className="panel-header">
          <h3>Audit trail preview</h3>
          <span className="pill">mock</span>
        </div>
        <div className="panel-body">
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Run</th>
                <th>Kernel event</th>
                <th>Evidence</th>
              </tr>
            </thead>
            <tbody>
              {recentEvents.map((event) => (
                <tr key={`${event.time}-${event.run}`}>
                  <td>{event.time}</td>
                  <td>{event.run}</td>
                  <td>{event.event}</td>
                  <td>{event.subject}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
