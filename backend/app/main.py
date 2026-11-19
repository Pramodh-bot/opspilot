"""OpsPilot FastAPI application."""

import logging
import time
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import get_settings
from app.db import SessionLocal, init_db
from app.logging_config import configure_logging, request_id_var
from app.metrics import HTTP_LATENCY, HTTP_REQUESTS, refresh_incident_gauge
from app.routers import auth, health, incidents, runbooks, webhooks
from app.seed import bootstrap_admin, seed_runbooks

log = logging.getLogger("opspilot")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


@asynccontextmanager
async def lifespan(_: FastAPI):
    settings = get_settings()
    configure_logging(settings.log_level)
    if settings.auto_create_schema:
        init_db()
    with SessionLocal() as db:
        seed_runbooks(db)
        if bootstrap_admin(db):
            log.info("bootstrap admin created")
        refresh_incident_gauge(db)
    log.info("opspilot started", extra={"environment": settings.environment})
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title=settings.app_name,
        version="1.0.0",
        lifespan=lifespan,
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_production else "/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_methods=["GET", "POST", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Webhook-Token"],
        max_age=600,
    )

    @app.middleware("http")
    async def observe(request: Request, call_next):
        rid = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex
        token = request_id_var.set(rid)
        start = time.perf_counter()
        status_code = 500
        try:
            response = await call_next(request)
            status_code = response.status_code
        except Exception:
            log.exception("unhandled error", extra={"path": request.url.path})
            response = JSONResponse({"detail": "Internal server error"}, status_code=500)
        finally:
            elapsed = time.perf_counter() - start
            route = request.scope.get("route")
            route_path = getattr(route, "path", "unmatched")
            HTTP_REQUESTS.labels(request.method, route_path, str(status_code)).inc()
            HTTP_LATENCY.labels(request.method, route_path).observe(elapsed)
            if route_path not in ("/metrics", "/healthz"):
                log.info(
                    "request",
                    extra={"method": request.method, "path": route_path, "status": status_code, "ms": round(elapsed * 1000, 1)},
                )
            request_id_var.reset(token)
        response.headers["X-Request-ID"] = rid
        for k, v in SECURITY_HEADERS.items():
            response.headers.setdefault(k, v)
        return response

    for r in (health.router, auth.router, incidents.router, runbooks.router, webhooks.router):
        app.include_router(r)
    return app


app = create_app()
