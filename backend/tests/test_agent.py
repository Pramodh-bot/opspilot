import json
from types import SimpleNamespace

import pytest

from app.agent import actions, factory
from app.agent import eval as agent_eval
from app.agent.graph import run_graph
from app.agent.llm import (
    HeuristicLLM,
    IncidentInput,
    LLMTriageOutput,
    OpenAILLM,
    ResilientLLM,
    more_severe,
)
from app.agent.rag import BM25Retriever, RunbookDoc, tokenize
from app.circuit_breaker import CircuitBreaker
from app.models import Category, Risk, Severity


@pytest.fixture
def retriever():
    return BM25Retriever(factory.seed_runbook_docs())


def good_json(**over):
    data = {
        "category": "database",
        "severity": "sev2",
        "summary": "DB pool exhausted",
        "root_cause_hypothesis": "Leaking connections",
        "confidence": 0.9,
        "recommended_actions": [
            {"action_type": "restart_service", "rationale": "reset pool"},
            {"action_type": "format_all_disks", "rationale": "evil"},
        ],
    }
    data.update(over)
    return json.dumps(data)


class FakeOpenAI:
    def __init__(self, content=None, exc=None):
        self.calls = 0
        self._content, self._exc = content, exc
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        self.calls += 1
        assert kwargs["response_format"] == {"type": "json_object"} and kwargs["temperature"] == 0
        if self._exc:
            raise self._exc
        return SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=self._content))])


def resilient(client, threshold=2):
    return ResilientLLM(OpenAILLM(client, "m", 5), HeuristicLLM(), CircuitBreaker(threshold, 60))


INC = IncidentInput("Postgres connection pool exhausted", "too many connections from pgbouncer", "payments-api", Severity.sev3)


def test_tokenize_and_bm25_ranking(retriever):
    assert tokenize("The DNS is failing!") == ["dns", "failing"]
    hits = retriever.search("replica replication lag postgres", k=2)
    assert hits[0].title.startswith("PostgreSQL replication")
    assert hits[0].score >= hits[1].score
    assert retriever.search("", 3) == [] and retriever.search("zzzzqqq", 3) == []
    assert BM25Retriever([]).search("anything") == []
    assert hits[0].as_dict()["category"] == "database"


def test_heuristic_classifies_and_unknown():
    out = HeuristicLLM().analyze(INC, [])
    assert out.category is Category.database and 0 < out.confidence <= 0.95
    unknown = HeuristicLLM().analyze(IncidentInput("hmm", "something odd", "svc"), [])
    assert unknown.category is Category.unknown and unknown.severity is Severity.sev3
    sev1 = HeuristicLLM().analyze(IncidentInput("Total outage", "all users cannot use the postgres database", "x"), [])
    assert sev1.severity is Severity.sev1
    minor = HeuristicLLM().analyze(IncidentInput("Minor disk warning", "no customer impact, disk at 80%", "x"), [])
    assert minor.severity is Severity.sev4


def test_more_severe():
    assert more_severe(Severity.sev3, Severity.sev1) is Severity.sev1
    assert more_severe(Severity.sev2, Severity.sev4) is Severity.sev2


def test_openai_success_filters_hallucinated_actions(retriever):
    client = FakeOpenAI(good_json())
    outcome = run_graph(resilient(client), retriever, INC)
    assert outcome.analysis.provider == "openai" and not outcome.analysis.used_fallback
    types = [p.action_type for p in outcome.plan]
    assert types[0] == "collect_diagnostics" and "restart_service" in types
    assert "format_all_disks" not in types  # allowlist enforced
    diag = outcome.plan[0]
    assert diag.auto_approve and diag.risk is Risk.low
    assert all(not p.auto_approve for p in outcome.plan[1:])
    assert len(outcome.plan) <= 4


def test_openai_extracts_json_from_wrapped_text(retriever):
    client = FakeOpenAI("Here you go:\n" + good_json(category="memory"))
    assert run_graph(resilient(client), retriever, INC).analysis.output.category is Category.memory


@pytest.mark.parametrize(
    "client,reason",
    [
        (FakeOpenAI("no json here"), "invalid_output"),
        (FakeOpenAI(good_json(category="astrology")), "invalid_output"),
        (FakeOpenAI(good_json(confidence=7)), "invalid_output"),
        (FakeOpenAI("{not json}"), "invalid_output"),
        (FakeOpenAI(exc=TimeoutError("slow")), "error"),
    ],
)
def test_openai_failures_fall_back(retriever, client, reason):
    outcome = run_graph(resilient(client), retriever, INC)
    assert outcome.analysis.used_fallback and outcome.analysis.provider == "heuristic"
    assert outcome.analysis.fallback_reason == reason
    assert outcome.analysis.output.category is Category.database  # still a useful triage


def test_circuit_opens_and_stops_calling_provider(retriever):
    client = FakeOpenAI(exc=ConnectionError("down"))
    llm = resilient(client, threshold=2)
    reasons = [run_graph(llm, retriever, INC).analysis.fallback_reason for _ in range(4)]
    assert reasons == ["error", "error", "circuit_open", "circuit_open"]
    assert client.calls == 2  # provider not hit while the circuit is open


def test_no_primary_is_not_a_fallback(retriever):
    llm = ResilientLLM(None, HeuristicLLM(), CircuitBreaker())
    res = llm.analyze(INC, [])
    assert res.provider == "heuristic" and not res.used_fallback


def test_graph_default_actions_when_llm_suggests_nothing(retriever):
    class Bare:
        name = "bare"

        def analyze(self, incident, runbooks):
            return LLMTriageOutput(
                category=Category.disk,
                severity=Severity.sev3,
                summary="s",
                root_cause_hypothesis="h",
                confidence=0.5,
                recommended_actions=[],
            )

    outcome = run_graph(ResilientLLM(Bare(), HeuristicLLM(), CircuitBreaker()), BM25Retriever([]), INC)
    assert [p.action_type for p in outcome.plan] == ["collect_diagnostics", "clear_disk_space"]


def test_runbook_actions_only_for_matching_category():
    docs = [RunbookDoc(1, "Disk full", "disk", "disk", "disk full postgres", ["clear_disk_space"])]

    class Fixed:
        name = "fixed"

        def analyze(self, incident, runbooks):
            return LLMTriageOutput(
                category=Category.database,
                severity=Severity.sev3,
                summary="s",
                root_cause_hypothesis="h",
                confidence=0.5,
                recommended_actions=[{"action_type": "restart_service"}],
            )

    out = run_graph(ResilientLLM(Fixed(), HeuristicLLM(), CircuitBreaker()), BM25Retriever(docs), INC)
    assert "clear_disk_space" not in [p.action_type for p in out.plan]


def test_execute_action_modes():
    assert actions.execute_action("restart_service", "svc", "simulate")[0] is True
    ok, msg = actions.execute_action("restart_service", "svc", "disabled")
    assert not ok and "disabled" in msg
    assert not actions.execute_action("restart_service", "svc", "weird")[0]
    ok, msg = actions.execute_action("rm_rf", "svc", "simulate")
    assert not ok and "allowlisted" in msg


def test_factory_builds_openai_when_key_set(monkeypatch, fresh_settings):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-not-real")
    llm = factory.get_llm()
    assert llm.primary is not None and llm.primary.name == "openai"


def test_eval_harness(tmp_path, capsys, monkeypatch):
    cases = json.loads(open("eval/dataset.json").read())
    report = agent_eval.evaluate(cases, agent_eval.build_llm("heuristic"))
    assert report["cases"] == 48 and 0 <= report["category_accuracy"] <= 1
    assert report["fallbacks_used"] == 0
    # wrong labels must lower the score (the metric is not hard-coded)
    bad = [dict(c, category="cpu" if c["category"] != "cpu" else "disk") for c in cases]
    assert agent_eval.evaluate(bad, agent_eval.build_llm("heuristic"))["category_accuracy"] < 0.2

    ds = tmp_path / "d.json"
    ds.write_text(json.dumps(cases[:6]))
    monkeypatch.setattr("sys.argv", ["eval", "--dataset", str(ds), "--json"])
    agent_eval.main()
    assert '"category_accuracy"' in capsys.readouterr().out
    monkeypatch.setattr("sys.argv", ["eval", "--dataset", str(ds)])
    agent_eval.main()
    assert "category accuracy" in capsys.readouterr().out
    monkeypatch.setattr("sys.argv", ["eval", "--dataset", str(ds), "--min-accuracy", "1.01"])
    with pytest.raises(SystemExit):
        agent_eval.main()
    monkeypatch.setattr("sys.argv", ["eval", "--dataset", str(ds), "--provider", "openai"])
    with pytest.raises(SystemExit):  # no OPENAI_API_KEY configured
        agent_eval.main()
