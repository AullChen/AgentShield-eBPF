import Link from "next/link";
import { loadEvidence, type EvidenceItem } from "../../../lib/api";

export const dynamic = "force-dynamic";

export default async function EvidencePage({ params }: { params: Promise<{ runId: string }> }) {
  const { runId } = await params;
  const result = await loadEvidence(runId);
  const timeline = result.data;

  return (
    <>
      <header className="page-header">
        <div>
          <span className="eyebrow">Run evidence / {runId}</span>
          <h2>Evidence detail</h2>
          <p>Agent statements, kernel observations, correlation rationale, policy decisions, and containment results remain separate.</p>
        </div>
        <Link className="button-link secondary" href="/history">Back to runs</Link>
      </header>

      <div className="notice evidence-notice">
        A bounded evidence snapshot for this Run. Operation attempts, policy decisions, and containment outcomes are recorded separately.
      </div>
      {result.error ? <div className="notice danger-notice" role="status">{result.error}</div> : null}

      <section className="evidence-legend" aria-label="Evidence source legend">
        <span className="source-key agent_claim">Agent claim</span>
        <span className="source-key kernel_fact">Kernel fact</span>
        <span className="source-key policy_decision">Policy decision</span>
        <span className="source-key containment_result">Containment result</span>
      </section>

      <section className="evidence-list" aria-live="polite">
        {timeline && timeline.items.length > 0 ? timeline.items.map((item) => (
          <article className={`evidence-event ${item.source}`} key={item.id}>
            <header className="evidence-event-header">
              <div>
                <span className="eyebrow">#{item.sequence} · {sourceLabel(item.source)} · {formatUnixNS(item.server_unix_ns)}</span>
                <h3>{item.summary}</h3>
                <code>{item.type} · monotonic {item.server_monotonic_ns}</code>
              </div>
              <span className={`pill ${item.operation?.action_result === "blocked" ? "danger" : ""}`}>{item.type}</span>
            </header>
            <div className="evidence-grid">
              <EvidenceCell empty={item.source !== "agent_claim"} label="Agent claim" content={agentClaim(item)} />
              <EvidenceCell empty={!item.operation} label="Kernel fact" content={kernelFact(item)} />
              <EvidenceCell label="Attribution / correlation" content={attribution(item)} />
              <EvidenceCell empty={!item.decision} label="Policy decision" content={policyDecision(item)} />
              <EvidenceCell empty={!hasContainmentEvidence(item)} label="Block / containment" content={containment(item)} />
            </div>
          </article>
        )) : (
          <div className="panel"><p className="empty-state">{timeline ? "This Run has an empty evidence snapshot. Check its ID, workload activity, and retention settings." : "Connect the control plane to load Run evidence."}</p></div>
        )}
      </section>
    </>
  );
}

function EvidenceCell({ label, content, empty = false }: { label: string; content: React.ReactNode; empty?: boolean }) {
  return <div className={`evidence-cell${empty ? " empty-cell" : ""}`}><h4>{label}</h4><div>{content}</div></div>;
}

function agentClaim(item: EvidenceItem) {
  if (item.source !== "agent_claim") return <span className="unavailable">No Agent statement on this row.</span>;
  return <><strong>Declared by Agent</strong><p>{item.summary}</p><small>Claim only; not kernel proof.</small></>;
}

function kernelFact(item: EvidenceItem) {
  if (!item.operation) return <span className="unavailable">No kernel operation evidence on this row.</span>;
  return <><strong>{item.operation.attempt_observed ? "Attempt observed" : "Attempt not observed"}</strong><p>{operationResult(item.operation.action_result)}</p><small>{item.operation.mechanism}</small></>;
}

function attribution(item: EvidenceItem) {
  if (!item.attribution && !item.correlation) {
    return <span className="unavailable">Not provided. A stream Run label alone does not prove causal attribution.</span>;
  }
  return <>
    {item.attribution ? <><strong>{item.attribution.status}</strong><p>{item.attribution.basis}</p></> : null}
    {item.correlation ? <><strong>{item.correlation.correlation_status} · {item.correlation.confidence}/100</strong><p>{item.correlation.selected_checkpoint_id ? `Checkpoint ${item.correlation.selected_checkpoint_id}` : "No checkpoint selected"}</p><small>{item.correlation.authoritative_clock}</small></> : <small>No temporal correlation result.</small>}
  </>;
}

function policyDecision(item: EvidenceItem) {
  if (!item.decision) return <span className="unavailable">No policy decision on this row.</span>;
  return <><strong>{item.decision.final_decision} · {item.decision.requested_action}</strong><p>{item.decision.policy_id} / rule {item.decision.rule_id}</p><small>{item.decision.mechanism} · {item.decision.enforced ? "enforced" : "not enforced"}</small></>;
}

function containment(item: EvidenceItem) {
  if (item.containment) {
    return <><strong>{item.containment.result}</strong><p>{item.containment.method}</p><small>{item.containment.target_identity} · original result {item.containment.original_action_result}</small></>;
  }
  if (item.operation?.action_result === "blocked") {
    return <><strong>Kernel block observed</strong><p>The hook returned a blocked result for this attempt.</p></>;
  }
  if (item.decision?.requested_action === "block" || item.decision?.requested_action === "contain") {
    return <><strong>{item.decision.enforced ? "Enforcement evidenced" : "Decision only"}</strong><p>{item.decision.enforced ? "The decision record reports enforcement." : "No block or containment result is attached to this row."}</p></>;
  }
  return <span className="unavailable">No block or containment evidence on this row.</span>;
}

function hasContainmentEvidence(item: EvidenceItem) {
  return Boolean(item.containment || item.operation?.action_result === "blocked" ||
    item.decision?.requested_action === "block" || item.decision?.requested_action === "contain");
}

function sourceLabel(source: EvidenceItem["source"]) {
  return source.replaceAll("_", " ");
}

function operationResult(result: string) {
  if (result === "none") return "No completion outcome was observed.";
  if (result === "blocked") return "The kernel hook reported this attempt blocked.";
  if (result === "allowed") return "The kernel hook reported this attempt allowed.";
  return `Reported action result: ${result}.`;
}

function formatUnixNS(value: string) {
  const nanoseconds = BigInt(value);
  const milliseconds = nanoseconds / BigInt(1_000_000);
  if (milliseconds > BigInt("8640000000000000")) return `${value} ns`;
  return new Date(Number(milliseconds)).toISOString().replace("T", " ").replace("Z", " UTC");
}
