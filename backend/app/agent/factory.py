"""Wiring: build the resilient LLM once per process and load runbooks into a retriever."""

import json
from functools import lru_cache
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.llm import HeuristicLLM, OpenAILLM, ResilientLLM
from app.agent.rag import BM25Retriever, RunbookDoc
from app.circuit_breaker import CircuitBreaker
from app.config import get_settings
from app.models import Runbook

SEED_FILE = Path(__file__).resolve().parent.parent / "seed_data" / "runbooks.json"


@lru_cache
def get_llm() -> ResilientLLM:
    s = get_settings()
    primary = OpenAILLM.from_settings(s.openai_api_key, s.openai_model, s.llm_timeout_seconds) if s.openai_api_key else None
    breaker = CircuitBreaker(s.llm_failure_threshold, s.llm_recovery_seconds)
    return ResilientLLM(primary, HeuristicLLM(), breaker)


def seed_runbook_docs() -> list[RunbookDoc]:
    items = json.loads(SEED_FILE.read_text(encoding="utf-8"))
    return [
        RunbookDoc(i + 1, r["title"], r["category"], r["tags"], r["content"], r["recommended_actions"])
        for i, r in enumerate(items)
    ]


def retriever_from_db(db: Session) -> BM25Retriever:
    rows = db.scalars(select(Runbook).order_by(Runbook.id)).all()
    docs = [RunbookDoc(r.id, r.title, r.category.value, r.tags, r.content, list(r.recommended_actions or [])) for r in rows]
    return BM25Retriever(docs)
