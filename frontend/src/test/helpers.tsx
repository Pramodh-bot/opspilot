import { render } from "@testing-library/react";
import axe from "axe-core";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { App } from "../App";
import { AuthProvider } from "../auth";
import { tokenStore } from "../api";
import type { Role } from "../types";

type Handler = (url: string, init?: RequestInit) => unknown;

/** Replace fetch with a router-style mock. Keys are "METHOD /path-without-/api". */
export function mockApi(routes: Record<string, Handler | unknown>) {
  const calls: { key: string; body: unknown }[] = [];
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input).replace(/^\/api/, "");
    const path = url.split("?")[0];
    const key = `${init?.method ?? "GET"} ${path}`;
    calls.push({ key, body: init?.body ? JSON.parse(String(init.body)) : undefined });
    const route = routes[key];
    if (route === undefined) return new Response(JSON.stringify({ detail: `no mock for ${key}` }), { status: 404 });
    const out = typeof route === "function" ? (route as Handler)(url, init) : route;
    if (out instanceof Response) return out;
    return new Response(JSON.stringify(out), { status: 200, headers: { "Content-Type": "application/json" } });
  });
  vi.stubGlobal("fetch", fn);
  return { fn, calls };
}

export const user = (role: Role) => ({ id: 1, email: `${role}@example.com`, name: "Test User", role, is_active: true });

export function renderApp(path: string, role: Role | null) {
  if (role) tokenStore.set("test-token");
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}

/** Run axe against WCAG 2.x A/AA rules. color-contrast needs real layout, so it is checked by design tokens instead. */
export async function expectNoA11yViolations(container: HTMLElement) {
  const results = await axe.run(container, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false }, region: { enabled: false } },
  });
  const summary = results.violations.map((v) => `${v.id}: ${v.help} (${v.nodes.map((n) => n.target.join(" ")).join(", ")})`);
  expect(summary).toEqual([]);
}
