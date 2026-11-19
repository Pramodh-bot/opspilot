import { useCallback, useEffect, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { useAuth } from "../auth";
import { Badge } from "../components/Badge";
import { useTitle } from "../components/useTitle";
import type { IncidentPage, Severity } from "../types";

const PAGE_SIZE = 10;

function NewIncident({ onCreated }: { onCreated: () => void }) {
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [service, setService] = useState("");
  const [description, setDescription] = useState("");
  const [severity, setSeverity] = useState<Severity>("sev3");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await api.createIncident({ title: title.trim(), service: service.trim(), description, severity });
      setTitle("");
      setService("");
      setDescription("");
      setOpen(false);
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not create incident");
    } finally {
      setBusy(false);
    }
  }

  if (!open)
    return (
      <button type="button" className="btn" onClick={() => setOpen(true)}>
        New incident
      </button>
    );

  return (
    <form onSubmit={submit} className="card" aria-labelledby="new-incident-heading" noValidate>
      <h2 id="new-incident-heading">New incident</h2>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}
      <div className="field">
        <label htmlFor="ni-title">Title</label>
        <input id="ni-title" required maxLength={200} value={title} onChange={(e) => setTitle(e.target.value)} />
      </div>
      <div className="field">
        <label htmlFor="ni-service">Service</label>
        <input
          id="ni-service"
          required
          maxLength={64}
          value={service}
          onChange={(e) => setService(e.target.value)}
          aria-describedby="ni-service-hint"
        />
        <small id="ni-service-hint">Letters, digits, dot, dash or underscore, for example checkout-api.</small>
      </div>
      <div className="field">
        <label htmlFor="ni-severity">Severity</label>
        <select id="ni-severity" value={severity} onChange={(e) => setSeverity(e.target.value as Severity)}>
          <option value="sev1">SEV1 Critical</option>
          <option value="sev2">SEV2 Major</option>
          <option value="sev3">SEV3 Minor</option>
          <option value="sev4">SEV4 Info</option>
        </select>
      </div>
      <div className="field">
        <label htmlFor="ni-desc">Description</label>
        <textarea id="ni-desc" rows={4} maxLength={8000} value={description} onChange={(e) => setDescription(e.target.value)} />
      </div>
      <div className="row">
        <button type="submit" className="btn" disabled={busy || !title.trim() || !service.trim()}>
          {busy ? "Creating…" : "Create incident"}
        </button>
        <button type="button" className="btn btn-secondary" onClick={() => setOpen(false)}>
          Cancel
        </button>
      </div>
    </form>
  );
}

export function Incidents() {
  useTitle("Incidents");
  const { can } = useAuth();
  const [status, setStatus] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [applied, setApplied] = useState({ status: "", severity: "", q: "" });
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<IncidentPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(() => {
    setLoading(true);
    api
      .incidents({ ...applied, limit: String(PAGE_SIZE), offset: String(offset) })
      .then((p) => {
        setPage(p);
        setError(null);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [applied, offset]);

  useEffect(load, [load]);

  function onFilter(e: FormEvent) {
    e.preventDefault();
    setOffset(0);
    setApplied({ status, severity, q: q.trim() });
  }

  const total = page?.total ?? 0;
  const from = total === 0 ? 0 : offset + 1;
  const to = Math.min(offset + PAGE_SIZE, total);

  return (
    <>
      <div className="page-head">
        <h1>Incidents</h1>
        {can("responder") && <NewIncident onCreated={load} />}
      </div>

      <form className="filters" onSubmit={onFilter} role="search" aria-label="Filter incidents">
        <div className="field">
          <label htmlFor="f-q">Search</label>
          <input id="f-q" type="search" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="f-status">Status</label>
          <select id="f-status" value={status} onChange={(e) => setStatus(e.target.value)}>
            <option value="">All</option>
            <option value="open">Open</option>
            <option value="triaged">Triaged</option>
            <option value="awaiting_approval">Awaiting approval</option>
            <option value="mitigating">Mitigating</option>
            <option value="resolved">Resolved</option>
          </select>
        </div>
        <div className="field">
          <label htmlFor="f-sev">Severity</label>
          <select id="f-sev" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            <option value="">All</option>
            <option value="sev1">SEV1</option>
            <option value="sev2">SEV2</option>
            <option value="sev3">SEV3</option>
            <option value="sev4">SEV4</option>
          </select>
        </div>
        <button type="submit" className="btn btn-secondary">
          Apply filters
        </button>
      </form>

      <p role="status" aria-live="polite" className="muted">
        {loading ? "Loading incidents…" : error ? "" : `Showing ${from}–${to} of ${total} incidents`}
      </p>
      {error && (
        <p role="alert" className="error">
          {error}
        </p>
      )}

      {page && page.items.length > 0 && (
        <div className="table-wrap">
          <table>
            <caption className="sr-only">Incidents, newest first</caption>
            <thead>
              <tr>
                <th scope="col">ID</th>
                <th scope="col">Title</th>
                <th scope="col">Service</th>
                <th scope="col">Severity</th>
                <th scope="col">Status</th>
                <th scope="col">Category</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((i) => (
                <tr key={i.id}>
                  <td>#{i.id}</td>
                  <td>
                    <Link to={`/incidents/${i.id}`}>{i.title}</Link>
                  </td>
                  <td>{i.service}</td>
                  <td>
                    <Badge kind="severity" value={i.severity} />
                  </td>
                  <td>
                    <Badge kind="status" value={i.status} />
                  </td>
                  <td>{i.category}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {page && page.items.length === 0 && !loading && <p>No incidents match these filters.</p>}

      <nav className="pager" aria-label="Pagination">
        <button type="button" className="btn btn-secondary" disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
          Previous page
        </button>
        <button type="button" className="btn btn-secondary" disabled={offset + PAGE_SIZE >= total} onClick={() => setOffset(offset + PAGE_SIZE)}>
          Next page
        </button>
      </nav>
    </>
  );
}
