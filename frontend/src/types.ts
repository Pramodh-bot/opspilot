export type Role = "viewer" | "responder" | "admin";
export type Severity = "sev1" | "sev2" | "sev3" | "sev4";
export type IncidentStatus = "open" | "triaged" | "awaiting_approval" | "mitigating" | "resolved";
export type Risk = "low" | "medium" | "high";
export type ActionStatus = "pending" | "approved" | "rejected" | "executed" | "failed";

export interface User {
  id: number;
  email: string;
  name: string;
  role: Role;
  is_active: boolean;
}

export interface Incident {
  id: number;
  title: string;
  description: string;
  service: string;
  severity: Severity;
  status: IncidentStatus;
  category: string;
  source: string;
  assignee_id: number | null;
  detected_at: string;
  created_at: string;
  updated_at: string;
  triaged_at: string | null;
  resolved_at: string | null;
}

export interface IncidentEvent {
  id: number;
  kind: string;
  message: string;
  actor: string;
  created_at: string;
}

export interface Triage {
  id: number;
  category: string;
  severity: Severity;
  summary: string;
  root_cause_hypothesis: string;
  confidence: number;
  provider: string;
  used_fallback: boolean;
  retrieved_runbooks: { id: number; title: string; category: string; score: number }[];
  duration_ms: number;
  created_at: string;
}

export interface ProposedAction {
  id: number;
  incident_id: number;
  action_type: string;
  target: string;
  rationale: string;
  risk: Risk;
  status: ActionStatus;
  decided_by: string | null;
  decided_at: string | null;
  result: string | null;
  created_at: string;
}

export interface IncidentDetail extends Incident {
  events: IncidentEvent[];
  triage_results: Triage[];
  actions: ProposedAction[];
}

export interface IncidentPage {
  items: Incident[];
  total: number;
  limit: number;
  offset: number;
}

export interface Runbook {
  id: number;
  title: string;
  category: string;
  tags: string;
  content: string;
  recommended_actions: string[];
}
