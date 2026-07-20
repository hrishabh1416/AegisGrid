"""AegisGrid Resilience Engine — Application Entry Point.

This module is deliberately minimal.  It:

1. Creates the FastAPI application instance with metadata from settings.
2. Attaches CORS middleware for cross-origin dashboard access.
3. Mounts the telemetry and containment routers.
4. Exposes a root ``GET /`` health-check that returns OPERATIONAL status.
5. Manages the WebSocket endpoint for real-time dashboard communication.
6. Runs the ``aiosqlite`` schema bootstrap via the application lifespan.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.core.state import node_statuses, ws_manager
from app.database.supabase import db_manager
from app.routers import containment_router, telemetry_router

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(name)-30s | %(levelname)-7s | %(message)s",
)
logger = logging.getLogger("aegisgrid.main")


# ── Lifespan ────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup / shutdown lifecycle hook.

    - **Startup**: initialise the SQLite schema so the DB is ready before
      the first request arrives.
    - **Shutdown**: (reserved for future connection-pool teardown).
    """
    logger.info("AegisGrid boot sequence initiated.")
    await db_manager.init_sqlite()
    logger.info("AegisGrid is OPERATIONAL.")
    yield
    logger.info("AegisGrid shutdown complete.")


# ── Application Instance ───────────────────────────────────────────────────

app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="AI-Driven Cyber Resilience Engine — Anomaly Detection & Automated Containment",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Router Mounting ─────────────────────────────────────────────────────────

app.include_router(telemetry_router)
app.include_router(containment_router)


# ── Root Health Check ───────────────────────────────────────────────────────

@app.get("/", summary="System health probe", tags=["Health"])
async def root() -> dict:
    """Return operational status and engine metadata.

    This is the canonical liveness probe for load-balancers and uptime
    monitors.
    """
    return {
        "status": "OPERATIONAL",
        "engine": settings.app_name,
        "version": settings.app_version,
    }


# ── WebSocket Endpoint ─────────────────────────────────────────────────────

@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket) -> None:
    """Real-time bidirectional channel for dashboard clients.

    On connect, immediately pushes the current topology snapshot so the
    client can render without an extra REST call.
    """
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json(
            {
                "type": "TOPOLOGY_UPDATE",
                "nodes": [
                    {"id": k, "label": k, "status": v}
                    for k, v in node_statuses.items()
                ],
            }
        )
        while True:
            await websocket.receive_text()
            await websocket.send_json({"type": "PONG"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)


# ── Development Server ─────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
    )
