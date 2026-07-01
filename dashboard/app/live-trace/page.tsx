import { recentEvents } from "../../lib/mock-data";

export default function LiveTracePage() {
  return (
    <>
      <header className="page-header">
        <div>
          <h2>Live Trace</h2>
          <p>Aligned Agent checkpoints and kernel events will stream here.</p>
        </div>
        <span className="pill">websocket pending</span>
      </header>

      <section className="panel">
        <div className="panel-header">
          <h3>Trace stream</h3>
          <span className="pill">latest first</span>
        </div>
        <div className="panel-body trace-list">
          {recentEvents.map((event) => (
            <div className={`trace-row ${event.severity}`} key={`${event.time}-${event.subject}`}>
              <strong>
                {event.time} · {event.event}
              </strong>
              <code>{event.subject}</code>
              <span>
                {event.run} · {event.result}
              </span>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
