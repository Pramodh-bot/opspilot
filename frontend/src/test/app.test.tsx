import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { ApiError, request, tokenStore } from "../api";
import { expectNoA11yViolations, mockApi, renderApp, user } from "./helpers";

const incident = (over: Record<string, unknown> = {}) => ({
  id: 7, title: "Errors spiked after deploy", description: "Error rate jumped after release 2.14", service: "checkout-api",
  severity: "sev2", status: "awaiting_approval", category: "deployment", source: "manual", assignee_id: null,
  detected_at: "2026-01-01T10:00:00Z", created_at: "2026-01-01T10:00:00Z", updated_at: "2026-01-01T10:00:00Z",
  triaged_at: "2026-01-01T10:01:00Z", resolved_at: null, ...over,
});

const action = (over: Record<string, unknown> = {}) => ({
  id: 11, incident_id: 7, action_type: "rollback_deployment", target: "checkout-api", rationale: "Recommended by runbook",
  risk: "high", status: "pending", decided_by: null, decided_at: null, result: null, created_at: "2026-01-01T10:01:00Z", ...over,
});

const detail = (over: Record<string, unknown> = {}) => ({
  ...incident(),
  events: [{ id: 1, kind: "created", message: "Incident created via manual", actor: "a@example.com", created_at: "2026-01-01T10:00:00Z" }],
  triage_results: [{
    id: 1, category: "deployment", severity: "sev2", summary: "Deployment incident affecting checkout-api",
    root_cause_hypothesis: "Bad release", confidence: 0.82, provider: "heuristic", used_fallback: true,
    retrieved_runbooks: [{ id: 8, title: "Bad deployment rollback procedure", category: "deployment", score: 4.2 }],
    duration_ms: 12, created_at: "2026-01-01T10:01:00Z",
  }],
  actions: [action(), action({ id: 10, action_type: "collect_diagnostics", risk: "low", status: "executed", result: "[simulated] ok", decided_by: "policy:auto-low-risk" })],
  ...over,
});

const page = { items: [incident()], total: 1, limit: 10, offset: 0 };

describe("a11y harness", () => {
  it("actually detects violations (guards against a vacuous pass)", async () => {
    const { render } = await import("@testing-library/react");
    const { container } = render(<main><img src="x.png" /><input /><button /></main>);
    await expect(expectNoA11yViolations(container)).rejects.toThrow();
  });
});

describe("login", () => {
  it("is accessible and shows an error alert on bad credentials", async () => {
    mockApi({ "POST /auth/login": new Response(JSON.stringify({ detail: "Invalid email or password" }), { status: 401 }) });
    const { container } = renderApp("/login", null);
    await expectNoA11yViolations(container);
    await userEvent.type(screen.getByLabelText("Email address"), "a@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "wrong");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Invalid email or password");
    expect(screen.getByLabelText("Email address")).toHaveAttribute("aria-invalid", "true");
    await expectNoA11yViolations(container);
  });

  it("signs in and lands on the incident list", async () => {
    mockApi({
      "POST /auth/login": { access_token: "tok" }, "GET /auth/me": user("responder"), "GET /incidents": page,
    });
    renderApp("/login", null);
    await userEvent.type(screen.getByLabelText("Email address"), "r@example.com");
    await userEvent.type(screen.getByLabelText("Password"), "Password12345");
    await userEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("heading", { name: "Incidents" })).toBeInTheDocument();
    expect(tokenStore.get()).toBe("tok");
  });

  it("redirects anonymous users to login", async () => {
    mockApi({});
    renderApp("/", null);
    expect(await screen.findByRole("heading", { name: "Sign in to OpsPilot" })).toBeInTheDocument();
  });
});

describe("incident list", () => {
  it("renders an accessible table with skip link, nav and live status", async () => {
    mockApi({ "GET /auth/me": user("viewer"), "GET /incidents": page });
    const { container } = renderApp("/", "viewer");
    const link = await screen.findByRole("link", { name: "Errors spiked after deploy" });
    expect(link).toHaveAttribute("href", "/incidents/7");
    expect(screen.getByRole("link", { name: "Skip to main content" })).toHaveAttribute("href", "#main");
    expect(screen.getByRole("navigation", { name: "Main" })).toBeInTheDocument();
    expect(screen.getByRole("table")).toHaveAccessibleName("Incidents, newest first");
    expect(screen.getByRole("status")).toHaveTextContent("Showing 1–1 of 1 incidents");
    expect(screen.queryByRole("button", { name: "New incident" })).not.toBeInTheDocument(); // viewers cannot create
    await expectNoA11yViolations(container);
  });

  it("lets responders create an incident and sends validated fields", async () => {
    const m = mockApi({
      "GET /auth/me": user("responder"), "GET /incidents": page, "POST /incidents": incident({ id: 8 }),
    });
    const { container } = renderApp("/", "responder");
    await userEvent.click(await screen.findByRole("button", { name: "New incident" }));
    await expectNoA11yViolations(container);
    await userEvent.type(screen.getByLabelText("Title"), "Disk full");
    await userEvent.type(screen.getByLabelText("Service"), "log-ingest");
    await userEvent.click(screen.getByRole("button", { name: "Create incident" }));
    await waitFor(() => expect(m.calls.some((c) => c.key === "POST /incidents")).toBe(true));
    expect(m.calls.find((c) => c.key === "POST /incidents")?.body).toMatchObject({ title: "Disk full", service: "log-ingest", severity: "sev3" });
  });

  it("surfaces API errors in an alert", async () => {
    mockApi({ "GET /auth/me": user("viewer"), "GET /incidents": new Response(JSON.stringify({ detail: "boom" }), { status: 500 }) });
    renderApp("/", "viewer");
    expect(await screen.findByRole("alert")).toHaveTextContent("boom");
  });
});

describe("incident detail", () => {
  it("shows triage, fallback notice and lets an admin approve a high-risk action", async () => {
    let current = detail();
    const m = mockApi({
      "GET /auth/me": user("admin"),
      "GET /incidents/7": () => current,
      "POST /actions/11/decision": () => {
        current = detail({ actions: [action({ status: "executed", result: "[simulated] done", decided_by: "admin@example.com" })] });
        return action({ status: "executed" });
      },
    });
    const { container } = renderApp("/incidents/7", "admin");
    expect(await screen.findByRole("heading", { name: /#7 Errors spiked after deploy/ })).toBeInTheDocument();
    expect(screen.getByRole("note")).toHaveTextContent("offline rules engine");
    expect(screen.getByText("Bad deployment rollback procedure")).toBeInTheDocument();
    await expectNoA11yViolations(container);
    await userEvent.click(screen.getByRole("button", { name: "Approve rollback deployment" }));
    await waitFor(() => expect(m.calls.find((c) => c.key === "POST /actions/11/decision")?.body).toMatchObject({ approve: true }));
    expect(await screen.findByText(/\[simulated\] done/)).toBeInTheDocument();
    expect(screen.getByRole("status", { hidden: true })).toHaveTextContent("Action approved");
  });

  it("disables high-risk approval for responders and explains why", async () => {
    mockApi({ "GET /auth/me": user("responder"), "GET /incidents/7": detail() });
    renderApp("/incidents/7", "responder");
    const approve = await screen.findByRole("button", { name: "Approve rollback deployment" });
    expect(approve).toBeDisabled();
    expect(approve).toHaveAccessibleDescription("Your role cannot decide high-risk actions.");
    expect(screen.getByRole("button", { name: "Re-run AI triage" })).toBeEnabled();
  });

  it("hides every mutating control from viewers", async () => {
    mockApi({ "GET /auth/me": user("viewer"), "GET /incidents/7": detail() });
    renderApp("/incidents/7", "viewer");
    await screen.findByRole("heading", { name: /#7/ });
    expect(screen.queryByRole("button", { name: /triage/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/Add a comment/)).not.toBeInTheDocument();
    const section = screen.getByRole("region", { name: "Proposed actions" });
    expect(within(section).getByRole("button", { name: "Approve rollback deployment" })).toBeDisabled();
  });

  it("shows an error when the incident does not exist", async () => {
    mockApi({ "GET /auth/me": user("viewer"), "GET /incidents/7": new Response(JSON.stringify({ detail: "Incident not found" }), { status: 404 }) });
    renderApp("/incidents/7", "viewer");
    expect(await screen.findByRole("alert")).toHaveTextContent("Incident not found");
  });

  it("runs triage and posts comments", async () => {
    const m = mockApi({
      "GET /auth/me": user("responder"), "GET /incidents/7": detail({ triage_results: [], actions: [] }),
      "POST /incidents/7/triage": { id: 1 }, "POST /incidents/7/comments": { id: 2 },
    });
    renderApp("/incidents/7", "responder");
    await userEvent.click(await screen.findByRole("button", { name: "Run AI triage" }));
    await waitFor(() => expect(m.calls.some((c) => c.key === "POST /incidents/7/triage")).toBe(true));
    await userEvent.type(screen.getByLabelText(/Add a comment/), "Looking into it");
    await userEvent.click(screen.getByRole("button", { name: "Post comment" }));
    await waitFor(() => expect(m.calls.find((c) => c.key === "POST /incidents/7/comments")?.body).toEqual({ message: "Looking into it" }));
  });
});

describe("runbooks and api client", () => {
  it("lists runbooks accessibly", async () => {
    mockApi({
      "GET /auth/me": user("viewer"),
      "GET /runbooks": [{ id: 1, title: "Disk full", category: "disk", tags: "", content: "Free space", recommended_actions: ["clear_disk_space"] }],
    });
    const { container } = renderApp("/runbooks", "viewer");
    expect(await screen.findByText("Disk full")).toBeInTheDocument();
    await expectNoA11yViolations(container);
  });

  it("attaches the bearer token, formats validation errors and handles network failure", async () => {
    tokenStore.set("abc");
    const m = mockApi({
      "GET /ping": { ok: true },
      "POST /bad": new Response(JSON.stringify({ detail: [{ loc: ["body", "service"], msg: "bad value" }] }), { status: 422 }),
    });
    await request("/ping");
    expect((m.fn.mock.calls[0][1]?.headers as Headers).get("Authorization")).toBe("Bearer abc");
    await expect(request("/bad", { method: "POST", json: {} })).rejects.toMatchObject({ status: 422, message: "service: bad value" });
    const { vi } = await import("vitest");
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("offline"); }));
    await expect(request("/ping")).rejects.toBeInstanceOf(ApiError);
  });
});
