import { useEffect, useState } from "react";
import { api } from "../api";
import { useTitle } from "../components/useTitle";
import type { Runbook } from "../types";

export function Runbooks() {
  useTitle("Runbooks");
  const [items, setItems] = useState<Runbook[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api
      .runbooks()
      .then(setItems)
      .catch((e: Error) => setError(e.message));
  }, []);

  return (
    <>
      <h1>Runbooks</h1>
      <p className="muted">The agent retrieves these runbooks (BM25 search) when it triages an incident.</p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      {!items && !error && <p role="status">Loading runbooks…</p>}
      {items?.map((r) => (
        <details key={r.id} className="card">
          <summary>
            {r.title} <span className="muted">({r.category})</span>
          </summary>
          <p>{r.content}</p>
          {r.recommended_actions.length > 0 && <p>Recommended actions: {r.recommended_actions.map((a) => a.replace(/_/g, " ")).join(", ")}</p>}
        </details>
      ))}
    </>
  );
}
