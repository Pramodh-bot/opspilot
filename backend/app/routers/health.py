from fastapi import APIRouter, Depends, HTTPException, Response, status
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.agent.factory import get_llm
from app.db import get_db
from app.metrics import LLM_BREAKER_STATE

router = APIRouter(tags=["ops"])


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


@router.get("/readyz")
def readyz(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "database unavailable") from None
    llm = get_llm()
    return {
        "status": "ready",
        "llm": llm.primary.name if llm.primary else "heuristic-only",
        "llm_circuit": llm.breaker.state.value,
    }


@router.get("/metrics", include_in_schema=False)
def metrics():
    LLM_BREAKER_STATE.set(get_llm().breaker.gauge_value())
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
