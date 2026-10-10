"""CPTM — Cloud Pentest Tool Manager backend."""
import os

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from .auth import require_token
from .db import init_db
from .routers import jobs, tools, ws

app = FastAPI(title="CPTM", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=os.environ.get("CPTM_CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(tools.router, prefix="/api")
app.include_router(jobs.router, prefix="/api")
app.include_router(ws.router)


@app.middleware("http")
async def no_store_cache(request, call_next):
    """Never let the browser cache the app or API responses.

    A stale cached bundle silently re-introduces old bugs after a rebuild —
    with no cache headers at all, browsers heuristically cached everything,
    which is exactly how 'results not reflected' reports happen after an
    update. API responses must never be cached either (job status changes).
    """
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store, max-age=0"
    return response


@app.on_event("startup")
async def _startup() -> None:
    await init_db()
    from .registry import seed_tools

    await seed_tools()


@app.get("/api/health")
async def health() -> dict:
    """Liveness probe. Deliberately unauthenticated so container health
    checks work; the UI must NOT use this to decide whether a token is valid."""
    return {"status": "ok"}


@app.get("/api/auth/check", dependencies=[Depends(require_token)])
async def auth_check() -> dict:
    """Token-gated. The UI calls this to decide whether to show the login
    screen, so an invalid or missing token is reported instead of silently
    rendering an empty app."""
    return {"status": "ok", "authenticated": True}


# ---- Serve built frontend (single-port deployment) ----
_DIST = os.environ.get("CPTM_FRONTEND_DIST", "/frontend")
if os.path.isdir(_DIST):
    app.mount("/assets", StaticFiles(directory=os.path.join(_DIST, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def spa(full_path: str):
        candidate = os.path.realpath(os.path.join(_DIST, full_path))
        if full_path and candidate.startswith(os.path.realpath(_DIST) + os.sep) and os.path.isfile(candidate):
            return FileResponse(candidate)
        return FileResponse(os.path.join(_DIST, "index.html"))
