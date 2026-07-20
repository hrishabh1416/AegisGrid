"""AegisGrid Containment Router.

Handles node isolation and system reset operations:

- ``POST /api/isolate-node`` – Manually isolate a compromised network asset
                                by invoking OS-level shell script hooks.
- ``POST /api/reset``        – Restore all nodes to SECURE and clear logs.
"""

from __future__ import annotations

import datetime
import logging
import os
import subprocess
import sys

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.state import mitigation_history, node_statuses, ws_manager

logger = logging.getLogger("aegisgrid.routers.containment")

router = APIRouter(prefix="/api", tags=["Containment"])


# ── Request Schemas ─────────────────────────────────────────────────────────

class IsolationRequest(BaseModel):
    """Payload for the manual node-isolation endpoint.

    Attributes
    ----------
    node_name:
        The asset identifier to isolate (must exist in ``node_statuses``).
    """

    node_name: str = Field(
        ...,
        examples=["DATABASE-CORE"],
        description="Target network asset name to isolate.",
    )


# ── Internal Helpers ────────────────────────────────────────────────────────

async def trigger_isolation_sequence(
    node_name: str, trigger_reason: str
) -> str:
    """Invoke the platform-specific isolation script and update shared state.

    On Windows, executes ``isolate_node.ps1`` via PowerShell; on Unix,
    runs ``isolate_node.sh``.  The node is marked ``ISOLATED`` in the
    topology graph regardless of script outcome, and the action is
    appended to the mitigation audit trail.

    Parameters
    ----------
    node_name:
        Asset identifier to isolate.
    trigger_reason:
        Human-readable reason (displayed in the forensic report).

    Returns
    -------
    str
        Combined stdout from the isolation script, or an error message.
    """
    node_statuses[node_name] = "ISOLATED"

    # Resolve script path relative to the backend root
    backend_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    is_windows = sys.platform.startswith("win")

    script_output = ""
    try:
        if is_windows:
            script_path = os.path.join(backend_dir, "isolate_node.ps1")
            cmd = [
                "powershell.exe",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                script_path,
                "-NodeName",
                node_name,
            ]
        else:
            script_path = os.path.join(backend_dir, "isolate_node.sh")
            subprocess.run(["chmod", "+x", script_path], check=False)
            cmd = [script_path, node_name]

        result = subprocess.run(
            cmd, capture_output=True, text=True, check=True
        )
        script_output = result.stdout
    except Exception as exc:
        script_output = f"Isolation Script Error: {exc}"
        logger.error(script_output)

    logger.info(
        "Node %s isolated. Script output:\n%s", node_name, script_output
    )

    # ── Audit trail ─────────────────────────────────────────────────────
    mitre_tactic = (
        "T1486: Data Encrypted for Impact"
        if "DATABASE" in node_name
        else "T1048: Exfiltration Over Alternative Protocol"
    )

    mitigation_history.append(
        {
            "node_name": node_name,
            "reason": trigger_reason,
            "timestamp": (
                datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
            ),
            "mitre_tactic": mitre_tactic,
            "script_output": script_output,
        }
    )

    # ── Broadcast isolation event ───────────────────────────────────────
    await ws_manager.broadcast(
        {
            "type": "NODE_ISOLATED",
            "node_name": node_name,
            "reason": trigger_reason,
            "mitre_tactic": mitre_tactic,
            "timestamp": datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat(),
            "script_output": script_output,
        }
    )
    await ws_manager.broadcast(
        {
            "type": "TOPOLOGY_UPDATE",
            "nodes": [
                {"id": k, "label": k, "status": v}
                for k, v in node_statuses.items()
            ],
        }
    )

    return script_output


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/isolate-node", summary="Manually isolate a network node")
async def isolate_node(payload: IsolationRequest) -> dict:
    """Execute the containment procedure for a specified asset.

    Validates the node name against the known topology, invokes the
    OS-level isolation script, and returns the combined output.

    Raises
    ------
    HTTPException 400
        If ``node_name`` does not exist in the topology map.
    """
    if payload.node_name not in node_statuses:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid node asset name: '{payload.node_name}'.",
        )

    result = await trigger_isolation_sequence(
        payload.node_name, "Manual operator command execution."
    )
    return {
        "status": "isolated",
        "node": payload.node_name,
        "script_output": result,
    }


@router.post("/reset", summary="Reset all system state")
async def reset_system() -> dict:
    """Restore every node to SECURE, clear the database, and notify clients.

    Also removes the ``isolated_nodes.txt`` lock file and empties the
    in-memory mitigation history.
    """
    # ── Reset topology ──────────────────────────────────────────────────
    for k in node_statuses:
        node_statuses[k] = "SECURE"

    # ── Clear database ──────────────────────────────────────────────────
    from app.database.supabase import db_manager

    await db_manager.clear_logs()

    # ── Remove lock file ────────────────────────────────────────────────
    backend_dir = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    lock_file = os.path.join(backend_dir, "isolated_nodes.txt")
    if os.path.exists(lock_file):
        try:
            os.remove(lock_file)
            logger.info("isolated_nodes.txt cleared.")
        except OSError:
            logger.exception("Failed to remove isolated_nodes.txt.")

    # ── Clear mitigation history ────────────────────────────────────────
    mitigation_history.clear()

    # ── Broadcast reset ─────────────────────────────────────────────────
    await ws_manager.broadcast({"type": "RESET"})
    await ws_manager.broadcast(
        {
            "type": "TOPOLOGY_UPDATE",
            "nodes": [
                {"id": k, "label": k, "status": v}
                for k, v in node_statuses.items()
            ],
        }
    )

    return {"status": "success", "message": "System state reset completed."}
