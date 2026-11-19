import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { useTitle } from "../components/useTitle";
import type { IncidentDetail as Detail, ProposedAction } from "../types";

const fmt = (iso: string | null) => (iso ? new Date(iso).toLocaleString() : "–");
const name = (s: string) => s.replace(/_/g, " ");

function ActionCard({ action, canApprove, onDecide }: { action: ProposedAction; canApprove: boolean; onDecide: (id: number, approve: boolean) => void }) {
  const pending = action.status === "pending";
  const hintId = `action-hint-${action.id}`;
  return (
    <li className="card action">
      <div className="row between">
        <h3>{name(action.action_type)}</h3>
        <span>
          <Badge kind="risk" value={action.risk} /> <Badge kind="action" value={action.status} />
        </span>
      </div>
      <p>
        Target: <code>{action.target}</code>
      </p>
      <p>{action.rationale}</p>
      {action.result && <p className="muted">Result: {action.result}</p>}
      {action.decided_by && (
        <p className="muted">
          Decided by {action.decided_by} · {fmt(action.decided_at)}
        </p>
      )}
      {pending && (
        <div className="row">
          <button
            type="button"
            className="btn"
            disabled={!canApprove}
            aria-describedby={canApprove ? undefined : hintId}
            onClick={() => onDecide(action.id, true)}
          >
            Approve<span className="sr-only"> {name(action.action_type)}</span>
          </button>
          <button type="button" className="btn btn-secondary" disabled={!canApprove} onClick={() => onDecide(action.id, false)}>
            Reject<span className="sr-only"> {name(action.action_type)}</span>
          </button>
          {!canApprove && (
            <small id={hintId}>Your role cannot decide {action.risk}-risk actions.</small>
          )}
        </div>
      )}
    </li>
  );
}

export function IncidentDetail() {
  const { id } = useParams();
  const incidentId = Number(id);
  const { user, can } = useAuth();
  const [data, setData] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [comment, setComment] = useState("");
  useTitle(data ? `#${data.id} ${data.title}` : "Incident");

  const load = useCallback(async () => {
    try {
      setData(await api.incident(incidentId));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load incident");
    }
  }, [incidentId]);

  useEffect(() => {
    void load();
  }, [load]);

  async function run(label: string, fn: () => Promise<unknown>) {
    setBusy(true);
    setError(null);
    try {
      await fn();
      setNotice(label);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Action failed");
    } finally {
      setBusy(false);
    }
  }

  if (!Number.isInteger(incidentId)) return <p role="alert" className="error">Invalid incident id.</p>;
  if (!data)
    return error ? (
      <>
        <p role="alert" className="error">{error}</p>
        <Link to="/">Back to incidents</Link>
      </>
    ) : (
      <p role="status">Loading incident…</p>
    );

  const triage = data.triage_results[data.triage_results.length - 1];
  const canDecide = (a: ProposedAction) => (a.risk === "high" ? can("admin") : can("responder"));
  const onComment = (e: FormEvent) => {
    e.preventDefault();
    void run("Comment added", async () => {
      await api.comment(data.id, comment);
      setComment("");
    });
  };

  return (
    <>
      <p>
        <Link to="/">← All incidents</Link>
      </p>
      <div className="page-head">
        <h1>
          #{data.id} {data.title}
        </h1>
        <span>
          <Badge kind="severity" value={data.severity} /> <Badge kind="status" value={data.status} />
        </span>
      </div>
      <dl className="meta">
        <dt>Service</dt>
        <dd>{data.service}</dd>
        <dt>Category</dt>
        <dd>{data.category}</dd>
        <dt>Source</dt>
        <dd>{data.source}</dd>
        <dt>Detected</dt>
        <dd>{fmt(data.detected_at)}</dd>
        <dt>Triaged</dt>
        <dd>{fmt(data.triaged_at)}</dd>
      </dl>
      {data.description && <p className="description">{data.description}</p>}

      <div role="status" aria-live="polite" className="sr-only">
        {notice}
      </div>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      {can("responder") && data.status !== "resolved" && (
        <div className="row">
          <button type="button" className="btn" disabled={busy} onClick={() => void run("Triage complete", () => api.triage(data.id))}>
            {triage ? "Re-run AI triage" : "Run AI triage"}
          </button>
          <button
            type="button"
            className="btn btn-secondary"
            disabled={busy}
            onClick={() => void run("Incident resolved", () => api.updateIncident(data.id, { status: "resolved" }))}
          >
            Mark resolved
          </button>
        </div>
      )}

      <section aria-labelledby="triage-h">
        <h2 id="triage-h">AI triage</h2>
        {!triage ? (
          <p>This incident has not been triaged yet.</p>
        ) : (
          <div className="card">
            {triage.used_fallback && (
              <p className="warning" role="note">
                The language model was unavailable, so the offline rules engine produced this triage.
              </p>
            )}
            <p>{triage.summary}</p>
            <p>
              <strong>Hypothesis:</strong> {triage.root_cause_hypothesis}
            </p>
            <p className="muted">
              Category {triage.category} · severity {triage.severity} · confidence {Math.round(triage.confidence * 100)}% · via {triage.provider}
            </p>
            {triage.retrieved_runbooks.length > 0 && (
              <>
                <h3>Matched runbooks</h3>
                <ul>
                  {triage.retrieved_runbooks.map((r) => (
                    <li key={r.id}>{r.title}</li>
                  ))}
                </ul>
              </>
            )}
          </div>
        )}
      </section>

      <section aria-labelledby="actions-h">
        <h2 id="actions-h">Proposed actions</h2>
        {data.actions.length === 0 ? (
          <p>No actions proposed yet.</p>
        ) : (
          <ul className="plain">
            {data.actions.map((a) => (
              <ActionCard
                key={a.id}
                action={a}
                canApprove={canDecide(a)}
                onDecide={(aid, approve) => void run(approve ? "Action approved" : "Action rejected", () => api.decide(aid, approve))}
              />
            ))}
          </ul>
        )}
      </section>

      <section aria-labelledby="timeline-h">
        <h2 id="timeline-h">Timeline</h2>
        <ol className="timeline">
          {data.events.map((ev) => (
            <li key={ev.id}>
              <time dateTime={ev.created_at}>{fmt(ev.created_at)}</time> · <strong>{name(ev.kind)}</strong> · {ev.actor}
              <br />
              {ev.message}
            </li>
          ))}
        </ol>
        {can("responder") && (
          <form onSubmit={onComment}>
            <div className="field">
              <label htmlFor="comment">Add a comment as {user?.name}</label>
              <textarea id="comment" rows={3} maxLength={2000} value={comment} onChange={(e) => setComment(e.target.value)} />
            </div>
            <button type="submit" className="btn btn-secondary" disabled={busy || !comment.trim()}>
              Post comment
            </button>
          </form>
        )}
      </section>
    </>
  );
}
