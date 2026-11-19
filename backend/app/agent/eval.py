"""Offline evaluation harness for the triage agent.

    python -m app.agent.eval --dataset eval/dataset.json [--provider heuristic|openai] [--min-accuracy 0.9]

Triage accuracy is MEASURED on the labelled dataset; it is not hard-coded anywhere. Report the number
this prints (and the provider used), and grow the dataset before quoting it externally.
"""

import argparse
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

from app.agent.factory import seed_runbook_docs
from app.agent.graph import run_graph
from app.agent.llm import HeuristicLLM, IncidentInput, OpenAILLM, ResilientLLM
from app.agent.rag import BM25Retriever
from app.circuit_breaker import CircuitBreaker
from app.config import get_settings
from app.models import Severity


def evaluate(cases: list[dict], llm: ResilientLLM, top_k: int = 3) -> dict:
    retriever = BM25Retriever(seed_runbook_docs())
    cat_ok = sev_ok = both_ok = fallbacks = 0
    per_cat: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    misses = []
    confusion: Counter = Counter()
    for case in cases:
        inc = IncidentInput(case["title"], case["description"], case["service"], Severity.sev3)
        outcome = run_graph(llm, retriever, inc, top_k)
        out = outcome.analysis.output
        fallbacks += int(outcome.analysis.used_fallback)
        c_ok = out.category.value == case["category"]
        s_ok = out.severity.value == case["severity"]
        cat_ok += c_ok
        sev_ok += s_ok
        both_ok += c_ok and s_ok
        per_cat[case["category"]][0] += c_ok
        per_cat[case["category"]][1] += 1
        if not c_ok:
            confusion[(case["category"], out.category.value)] += 1
        if not (c_ok and s_ok):
            misses.append(
                {
                    "title": case["title"],
                    "expected": [case["category"], case["severity"]],
                    "got": [out.category.value, out.severity.value],
                }
            )
    n = len(cases)
    return {
        "cases": n,
        "category_accuracy": round(cat_ok / n, 4),
        "severity_accuracy": round(sev_ok / n, 4),
        "joint_accuracy": round(both_ok / n, 4),
        "fallbacks_used": fallbacks,
        "per_category": {k: f"{v[0]}/{v[1]}" for k, v in sorted(per_cat.items())},
        "category_confusions": {f"{a}->{b}": c for (a, b), c in confusion.items()},
        "misses": misses,
    }


def build_llm(provider: str) -> ResilientLLM:
    s = get_settings()
    breaker = CircuitBreaker(s.llm_failure_threshold, s.llm_recovery_seconds)
    if provider == "openai":
        if not s.openai_api_key:
            sys.exit("OPENAI_API_KEY is not set")
        return ResilientLLM(
            OpenAILLM.from_settings(s.openai_api_key, s.openai_model, s.llm_timeout_seconds), HeuristicLLM(), breaker
        )
    return ResilientLLM(None, HeuristicLLM(), breaker)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--dataset", default="eval/dataset.json")
    p.add_argument("--provider", choices=["heuristic", "openai"], default="heuristic")
    p.add_argument("--min-accuracy", type=float, default=0.0, help="fail (exit 1) if category accuracy is below this")
    p.add_argument("--json", action="store_true", help="print the full report as JSON")
    args = p.parse_args()
    cases = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    report = evaluate(cases, build_llm(args.provider))
    report["provider"] = args.provider
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"provider={args.provider} cases={report['cases']} fallbacks={report['fallbacks_used']}")
        print(f"category accuracy : {report['category_accuracy']:.1%}")
        print(f"severity accuracy : {report['severity_accuracy']:.1%}")
        print(f"joint accuracy    : {report['joint_accuracy']:.1%}")
        print("per category      :", report["per_category"])
        for m in report["misses"]:
            print(f"  MISS {m['title']!r}: expected={m['expected']} got={m['got']}")
    if report["category_accuracy"] < args.min_accuracy:
        sys.exit(f"category accuracy {report['category_accuracy']:.1%} < required {args.min_accuracy:.1%}")


if __name__ == "__main__":
    main()
