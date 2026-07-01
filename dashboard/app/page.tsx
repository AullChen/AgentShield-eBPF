import { metrics, recentEvents } from "../lib/mock-data";

export default function OverviewPage() {
  return (
    <>
      <header className="page-header">
        <div>
          <h2>Overview</h2>
          <p>Current Agent runs, policy pressure, and kernel event flow.</p>
        </div>
        <span className="pill ok">control plane: skeleton</span>
      </header>

      <section className="status-strip" aria-label="Runtime metrics">
        {metrics.map((metric) => (
          <div className="metric" key={metric.label}>
            <span>{metric.label}</span>
            <strong>{metric.value}</strong>
          </div>
        ))}
      </section>

      <section className="grid-two">
        <div className="panel">
          <div className="panel-header">
            <h3>Recent kernel events</h3>
            <span className="pill">mock</span>
          </div>
          <div className="panel-body">
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Run</th>
                  <th>Event</th>
                  <th>Subject</th>
                  <th>Result</th>
                </tr>
              </thead>
              <tbody>
                {recentEvents.map((event) => (
                  <tr key={`${event.time}-${event.event}`}>
                    <td>{event.time}</td>
                    <td>{event.run}</td>
                    <td>{event.event}</td>
                    <td>{event.subject}</td>
                    <td>
                      <span className={`pill ${event.severity === "high" ? "danger" : ""}`}>
                        {event.result}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="panel-header">
            <h3>Signal queue</h3>
            <span className="pill danger">high</span>
          </div>
          <div className="panel-body trace-list">
            {recentEvents.map((event) => (
              <div className={`trace-row ${event.severity}`} key={event.subject}>
                <strong>{event.event}</strong>
                <code>{event.subject}</code>
                <span>{event.run}</span>
              </div>
            ))}
          </div>
        </div>
      </section>
    </>
  );
}
