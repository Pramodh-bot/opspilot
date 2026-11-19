"""LangGraph triage pipeline: retrieve -> analyze -> plan -> gate.

The graph is a pure function of (incident, runbook corpus, LLM). All persistence and every
side effect lives in `service.py`, which keeps this part easy to test and to evaluate offline.
"""

from dataclasses import dataclass
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from app.agent.actions import ACTION_CATALOG, CATEGORY_DEFAULT_ACTIONS
from app.agent.llm import AnalysisResult, IncidentInput, ResilientLLM
from app.agent.rag import BM25Retriever, RetrievedRunbook
from app.models import Risk

MAX_ACTIONS = 4


@dataclass(frozen=True)
class PlannedAction:
    action_type: str
    target: str
    rationale: str
    risk: Risk
    auto_approve: bool  # set by the policy gate; everything else needs a human


class TriageState(TypedDict, total=False):
    incident: IncidentInput
    runbooks: list[RetrievedRunbook]
    analysis: AnalysisResult
    plan: list[PlannedAction]


def build_graph(llm: ResilientLLM, retriever: BM25Retriever, top_k: int):
    def retrieve(state: TriageState) -> TriageState:
        inc = state["incident"]
        query = f"{inc.title} {inc.title} {inc.description} {inc.service}"
        return {"runbooks": retriever.search(query, k=top_k)}

    def analyze(state: TriageState) -> TriageState:
        return {"analysis": llm.analyze(state["incident"], state["runbooks"])}

    def plan(state: TriageState) -> TriageState:
        inc, analysis, runbooks = state["incident"], state["analysis"], state["runbooks"]
        out = analysis.output
        ordered: list[tuple[str, str]] = [("collect_diagnostics", "Gather evidence before changing anything")]
        for s in out.recommended_actions:
            ordered.append((s.action_type, s.rationale))
        for rb in runbooks:
            if rb.category == out.category.value:
                ordered.extend((a, f"Recommended by runbook '{rb.title}'") for a in rb.recommended_actions)
        if len(ordered) < 2:
            ordered.extend((a, "Default response for this category") for a in CATEGORY_DEFAULT_ACTIONS[out.category])

        seen: set[str] = set()
        planned: list[PlannedAction] = []
        for action_type, rationale in ordered:
            spec = ACTION_CATALOG.get(action_type)
            if spec is None or action_type in seen:  # allowlist: unknown/hallucinated actions are dropped
                continue
            seen.add(action_type)
            planned.append(PlannedAction(action_type, inc.service, rationale or spec.description, spec.risk, False))
            if len(planned) >= MAX_ACTIONS:
                break
        return {"plan": planned}

    def gate(state: TriageState) -> TriageState:
        # Policy gate: only allowlisted *low-risk, read-only* actions skip human approval.
        gated = [
            PlannedAction(
                p.action_type,
                p.target,
                p.rationale,
                p.risk,
                auto_approve=ACTION_CATALOG[p.action_type].auto_approve and p.risk is Risk.low,
            )
            for p in state["plan"]
        ]
        return {"plan": gated}

    g = StateGraph(TriageState)
    # node names must differ from state keys ("runbooks", "analysis", "plan")
    g.add_node("retrieve_runbooks", retrieve)
    g.add_node("analyze_incident", analyze)
    g.add_node("plan_actions", plan)
    g.add_node("policy_gate", gate)
    g.add_edge(START, "retrieve_runbooks")
    g.add_edge("retrieve_runbooks", "analyze_incident")
    g.add_edge("analyze_incident", "plan_actions")
    g.add_edge("plan_actions", "policy_gate")
    g.add_edge("policy_gate", END)
    return g.compile()


@dataclass(frozen=True)
class TriageOutcome:
    runbooks: list[RetrievedRunbook]
    analysis: AnalysisResult
    plan: list[PlannedAction]


def run_graph(llm: ResilientLLM, retriever: BM25Retriever, incident: IncidentInput, top_k: int = 3) -> TriageOutcome:
    final = build_graph(llm, retriever, top_k).invoke({"incident": incident})
    return TriageOutcome(final["runbooks"], final["analysis"], final["plan"])


__all__ = ["PlannedAction", "TriageOutcome", "build_graph", "run_graph"]
