from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.agent.actions import ACTION_CATALOG
from app.db import get_db
from app.deps import require_admin, require_viewer
from app.models import Runbook, User
from app.schemas import RunbookCreate, RunbookOut

router = APIRouter(prefix="/api/runbooks", tags=["runbooks"])


@router.get("", response_model=list[RunbookOut])
def list_runbooks(_: User = Depends(require_viewer), db: Session = Depends(get_db)):
    return db.scalars(select(Runbook).order_by(Runbook.title)).all()


@router.post("", response_model=RunbookOut, status_code=status.HTTP_201_CREATED)
def create_runbook(body: RunbookCreate, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    unknown = [a for a in body.recommended_actions if a not in ACTION_CATALOG]
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Unknown action types: {', '.join(unknown)}")
    rb = Runbook(**body.model_dump())
    db.add(rb)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, "A runbook with this title already exists") from None
    return rb


@router.delete("/{runbook_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_runbook(runbook_id: int, _: User = Depends(require_admin), db: Session = Depends(get_db)):
    rb = db.get(Runbook, runbook_id)
    if rb is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Runbook not found")
    db.delete(rb)
    db.commit()
