import type { ActionStatus, IncidentStatus, Risk, Severity } from "../types";

const LABELS: Record<string, string> = {
  awaiting_approval: "Awaiting approval",
  sev1: "SEV1 Critical",
  sev2: "SEV2 Major",
  sev3: "SEV3 Minor",
  sev4: "SEV4 Info",
};

const pretty = (v: string) => LABELS[v] ?? v.charAt(0).toUpperCase() + v.slice(1).replace(/_/g, " ");

// Meaning is always carried by the text; colour is only reinforcement (WCAG 1.4.1).
export function Badge({ kind, value }: { kind: "severity" | "status" | "risk" | "action"; value: Severity | IncidentStatus | Risk | ActionStatus }) {
  return <span className={`badge badge-${kind}-${value}`}>{pretty(value)}</span>;
}
