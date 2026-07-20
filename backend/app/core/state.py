"""AegisGrid Shared Application State Module.

Centralises mutable runtime state that is accessed across multiple routers
and background services.  Placing these objects here prevents circular
imports between the telemetry and containment routers.

Exports
-------
- ``node_statuses``      – dict mapping asset names to their current status.
- ``mitigation_history`` – ordered audit trail of isolation actions taken.
- ``ws_manager``         – singleton WebSocket broadcast hub.
"""

from __future__ import annotations

import logging
from typing import Dict, List

from fastapi import WebSocket

logger = logging.getLogger("aegisgrid.state")

# ── Topology State ──────────────────────────────────────────────────────────

node_statuses: Dict[str, str] = {
    "GATEWAY-01": "SECURE",
    "ADMIN-GATEWAY": "SECURE",
    "BILLING-SRV": "SECURE",
    "DATABASE-CORE": "SECURE",
}

mitigation_history: List[dict] = []


# ── WebSocket Connection Manager ────────────────────────────────────────────

class ConnectionManager:
    """Manages active WebSocket connections and provides broadcast capability.

    Connections are stored in an ordered list.  Dead connections detected
    during broadcast are pruned automatically so the list never grows
    unbounded.
    """

    def __init__(self) -> None:
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        """Accept an incoming WebSocket handshake and register the client."""
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(
            "WSManager: Client connected. Total active: %d",
            len(self.active_connections),
        )

    def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket from the active pool."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        logger.info(
            "WSManager: Client disconnected. Total active: %d",
            len(self.active_connections),
        )

    async def broadcast(self, message: dict) -> None:
        """Send a JSON payload to every connected client.

        Connections that raise during send are silently pruned to keep the
        pool healthy.
        """
        dead_connections: List[WebSocket] = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:  # noqa: BLE001
                dead_connections.append(connection)

        for connection in dead_connections:
            self.disconnect(connection)


# Singleton instance — imported by routers and main.py
ws_manager = ConnectionManager()
