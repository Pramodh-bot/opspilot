import type { Incident, IncidentDetail, IncidentPage, ProposedAction, Runbook, Severity, Triage, User } from "./types";

const TOKEN_KEY = "opspilot.token";

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message);
  }
}

let onUnauthorized: () => void = () => {};
export const setUnauthorizedHandler = (fn: () => void) => {
  onUnauthorized = fn;
};

export const tokenStore = {
  get: (): string | null => {
    try {
      return sessionStorage.getItem(TOKEN_KEY);
    } catch {
      return null;
    }
  },
  set: (t: string) => {
    try {
      sessionStorage.setItem(TOKEN_KEY, t);
    } catch {
      /* storage unavailable: session lives in memory only */
    }
  },
  clear: () => {
    try {
      sessionStorage.removeItem(TOKEN_KEY);
    } catch {
      /* ignore */
    }
  },
};

function errorMessage(body: unknown, status: number): string {
  const detail = (body as { detail?: unknown } | null)?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail) && detail.length > 0) {
    const first = detail[0] as { loc?: unknown[]; msg?: string };
    const field = Array.isArray(first.loc) ? String(first.loc[first.loc.length - 1]) : "input";
    return `${field}: ${first.msg ?? "invalid value"}`;
  }
  return `Request failed (${status})`;
}

export async function request<T>(path: string, init: RequestInit & { json?: unknown } = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = tokenStore.get();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  let body = init.body;
  if (init.json !== undefined) {
    headers.set("Content-Type", "application/json");
    body = JSON.stringify(init.json);
  }
  let res: Response;
  try {
    res = await fetch(`/api${path}`, { ...init, headers, body });
  } catch {
    throw new ApiError(0, "Cannot reach the server. Check your connection and try again.");
  }
  if (res.status === 204) return undefined as T;
  let data: unknown = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON body */
  }
  if (!res.ok) {
    if (res.status === 401 && token && !path.startsWith("/auth/login")) onUnauthorized();
    throw new ApiError(res.status, errorMessage(data, res.status));
  }
  return data as T;
}

export const api = {
  login: (email: string, password: string) =>
    request<{ access_token: string }>("/auth/login", { method: "POST", json: { email, password } }),
  me: () => request<User>("/auth/me"),
  incidents: (params: Record<string, string>) => {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== ""));
    return request<IncidentPage>(`/incidents?${qs.toString()}`);
  },
  incident: (id: number) => request<IncidentDetail>(`/incidents/${id}`),
  createIncident: (b: { title: string; description: string; service: string; severity: Severity }) =>
    request<Incident>("/incidents", { method: "POST", json: b }),
  updateIncident: (id: number, b: Partial<{ status: string; severity: string }>) =>
    request<Incident>(`/incidents/${id}`, { method: "PATCH", json: b }),
  comment: (id: number, message: string) => request(`/incidents/${id}/comments`, { method: "POST", json: { message } }),
  triage: (id: number) => request<Triage>(`/incidents/${id}/triage`, { method: "POST" }),
  decide: (actionId: number, approve: boolean, comment?: string) =>
    request<ProposedAction>(`/actions/${actionId}/decision`, { method: "POST", json: { approve, comment } }),
  runbooks: () => request<Runbook[]>("/runbooks"),
};
