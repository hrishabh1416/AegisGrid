# """AegisGrid Telemetry Router.

# Handles all telemetry-related endpoints:

# - ``POST /api/telemetry``       – Ingest raw syslog, score via Isolation Forest,
#                                    persist to DB, broadcast via WebSocket, and
#                                    yield mitigation rules when threshold breached.
# - ``POST /api/simulate-attack`` – Generate a synthetic anomalous event.
# - ``GET  /api/topology``        – Return the current network node graph.
# - ``GET  /api/forensic-report`` – Generate a MITRE ATT&CK-aligned incident report.
# """

# from __future__ import annotations

# import datetime
# import logging
# import uuid

# from fastapi import APIRouter, HTTPException
# from pydantic import BaseModel, Field

# from app.core.config import settings
# from app.core.state import mitigation_history, node_statuses, ws_manager
# from app.database.supabase import db_manager
# from app.ml.isolation import AnomalyDetector
# from app.ml.pipeline import parse_log

# logger = logging.getLogger("aegisgrid.routers.telemetry")

# router = APIRouter(prefix="/api", tags=["Telemetry"])

# # ── Singleton ML model (trained once at import time) ────────────────────────
# _detector = AnomalyDetector()


# # ── Request Schemas ─────────────────────────────────────────────────────────

# class TelemetryRequest(BaseModel):
#     """Structured payload for the telemetry ingestion endpoint.

#     Attributes
#     ----------
#     raw_log:
#         A single syslog-formatted line matching the pattern
#         ``TIMESTAMP [ASSET] USER BYTES STATUS``.
#     """

#     raw_log: str = Field(
#         ...,
#         min_length=10,
#         examples=[
#             "2026-07-19T10:05:00Z [GATEWAY-01] admin_svc 150000 SUCCESS"
#         ],
#         description="Raw syslog line for anomaly evaluation.",
#     )


# # ── Endpoints ───────────────────────────────────────────────────────────────

# @router.post("/telemetry", summary="Ingest & score a telemetry event")
# async def process_telemetry(payload: TelemetryRequest) -> dict:
#     """Asynchronous telemetry ingestion pipeline.

#     1. Parse the raw log line into structured metadata.
#     2. Run the parsed event through the Isolation Forest anomaly detector.
#     3. Persist the scored record to Supabase / SQLite asynchronously.
#     4. Broadcast the event over WebSocket to all connected dashboards.
#     5. If the anomaly score falls below the configured threshold
#        (``-0.02`` by default), yield MITRE-aligned mitigation rules and
#        auto-trigger node isolation.

#     Returns
#     -------
#     dict
#         ``status``, ``score``, ``classification``, and ``parsed`` fields.
#         When the score is below threshold, an additional ``mitigation``
#         key contains recommended containment rules.
#     """
#     raw_line = payload.raw_log.strip()
#     logger.info("Ingested telemetry: %.200s", raw_line)

#     # ── 1. Parse ────────────────────────────────────────────────────────
#     parsed = parse_log(raw_line)
#     if not parsed:
#         raise HTTPException(
#             status_code=400,
#             detail=(
#                 "Log format invalid. "
#                 "Expected: TIMESTAMP [ASSET] USER BYTES STATUS"
#             ),
#         )

#     # ── 2. Score ────────────────────────────────────────────────────────
#     score, status = _detector.predict(parsed)

#     # ── 3. Persist (non-blocking) ───────────────────────────────────────
#     try:
#         await db_manager.insert_log(parsed, score, status)
#     except Exception:
#         logger.exception("Database write failed — event still processed.")

#     # ── 4. Topology state mutation ──────────────────────────────────────
#     node_name = parsed["source_asset"]
#     if node_statuses.get(node_name) == "ISOLATED":
#         status = "ISOLATED"
#     elif status == "CRITICAL_ANOMALY":
#         node_statuses[node_name] = "CRITICAL"

#     # ── 5. WebSocket broadcast ──────────────────────────────────────────
#     event = {
#         "type": "TELEMETRY_LOG",
#         "raw_log": raw_line,
#         "parsed": {
#             "timestamp": parsed["timestamp"].isoformat(),
#             "source_asset": parsed["source_asset"],
#             "user_principal": parsed["user_principal"],
#             "bytes_transferred": parsed["bytes_transferred"],
#             "anomaly_score": score,
#             "status": status,
#         },
#     }
#     await ws_manager.broadcast(event)

#     # ── 6. Mitigation rules (threshold breach) ──────────────────────────
#     response: dict = {
#         "status": "processed",
#         "score": score,
#         "classification": status,
#         "parsed": {
#             "timestamp": parsed["timestamp"].isoformat(),
#             "source_asset": parsed["source_asset"],
#             "user_principal": parsed["user_principal"],
#             "bytes_transferred": parsed["bytes_transferred"],
#         },
#     }

#     if score < settings.anomaly_threshold:
#         mitre_tactic = (
#             "T1486: Data Encrypted for Impact"
#             if "DATABASE" in node_name
#             else "T1048: Exfiltration Over Alternative Protocol"
#         )
#         response["mitigation"] = {
#             "action": "AUTO_ISOLATE",
#             "target_node": node_name,
#             "mitre_tactic": mitre_tactic,
#             "rules": [
#                 f"BLOCK all egress traffic from {node_name}",
#                 f"REVOKE active sessions for principal '{parsed['user_principal']}'",
#                 f"SNAPSHOT forensic image of {node_name} disk state",
#                 "ESCALATE to SOC Tier-2 for manual review",
#             ],
#         }
#         logger.warning(
#             "Anomaly threshold breached on %s (score=%.6f). "
#             "Mitigation rules yielded.",
#             node_name,
#             score,
#         )

#         # Auto-isolation trigger — import here to avoid circular at module level
#         if node_statuses.get(node_name) != "ISOLATED":
#             from app.routers.containment import trigger_isolation_sequence

#             await trigger_isolation_sequence(
#                 node_name,
#                 f"Auto-mitigation triggered by anomaly score {score:.4f}",
#             )

#     return response


# @router.post("/simulate-attack", summary="Simulate a ransomware-scale event")
# async def simulate_attack() -> dict:
#     """Generate an anomalous out-of-bounds telemetry event.

#     Crafts a synthetic log line with an extreme byte volume on the
#     ``DATABASE-CORE`` asset to trigger a critical alert and demonstrate
#     the full isolation pipeline.
#     """
#     now = (
#         datetime.datetime.now(datetime.timezone.utc)
#         .isoformat()
#         .replace("+00:00", "Z")
#     )
#     simulated_log = f"{now} [DATABASE-CORE] backup_agent 5800000000 SUCCESS"
#     logger.info("Simulating ransomware attack: %s", simulated_log)

#     return await process_telemetry(TelemetryRequest(raw_log=simulated_log))


# @router.get("/topology", summary="Retrieve current network topology")
# async def get_topology() -> dict:
#     """Return the live node graph with status and link adjacency data."""
#     nodes = [
#         {
#             "id": k,
#             "label": k,
#             "status": v,
#             "type": (
#                 "gateway"
#                 if "GATEWAY" in k
#                 else ("database" if "DATABASE" in k else "server")
#             ),
#         }
#         for k, v in node_statuses.items()
#     ]
#     links = [
#         {"from": "GATEWAY-01", "to": "BILLING-SRV"},
#         {"from": "ADMIN-GATEWAY", "to": "DATABASE-CORE"},
#         {"from": "BILLING-SRV", "to": "DATABASE-CORE"},
#         {"from": "GATEWAY-01", "to": "ADMIN-GATEWAY"},
#     ]
#     return {"nodes": nodes, "links": links}


# @router.get("/forensic-report", summary="Generate an incident forensic report")
# async def generate_forensic_report() -> dict:
#     """Produce a MITRE ATT&CK-aligned forensic incident report.

#     Aggregates current topology state, recent anomaly records, mitigation
#     history, and compliance sign-off stubs into a structured JSON document
#     suitable for SOC handoff.
#     """
#     incident_id = (
#         f"INC-{datetime.datetime.now().strftime('%Y%m%d')}"
#         f"-{str(uuid.uuid4())[:8].upper()}"
#     )
#     timestamp = (
#         datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
#     )

#     active_isolated = [
#         k for k, v in node_statuses.items() if v == "ISOLATED"
#     ]
#     active_critical = [
#         k for k, v in node_statuses.items() if v in ("CRITICAL", "CRITICAL_ANOMALY")
#     ]

#     if active_isolated:
#         threat_level = "CRITICAL (BREACH ENCOUNTERED)"
#     elif active_critical:
#         threat_level = "HIGH (ANOMALY DETECTED)"
#     else:
#         threat_level = "SECURE"

#     total_logs = await db_manager.get_total_logs_count()

#     # ── Threat vectors ──────────────────────────────────────────────────
#     threat_vectors: list[dict] = []
#     seen_tactics: set[str] = set()

#     for node in active_isolated:
#         tactic = (
#             "T1486: Data Encrypted for Impact"
#             if "DATABASE" in node
#             else "T1048: Exfiltration Over Alternative Protocol"
#         )
#         if tactic not in seen_tactics:
#             seen_tactics.add(tactic)
#             threat_vectors.append(
#                 {
#                     "id": tactic.split(":")[0],
#                     "name": tactic.split(":")[1].strip(),
#                     "mapped_assets": [node],
#                     "description": (
#                         "Adversary behavior targeting specific system enclave "
#                         "elements to disrupt service or exfiltrate state data."
#                     ),
#                 }
#             )

#     recent_anomalies = await db_manager.get_recent_anomalies(limit=5)
#     for log_entry in recent_anomalies:
#         asset = log_entry.get("source_asset", "UNKNOWN")
#         tactic = (
#             "T1486: Data Encrypted for Impact"
#             if "DATABASE" in asset
#             else "T1048: Exfiltration Over Alternative Protocol"
#         )
#         if tactic not in seen_tactics:
#             seen_tactics.add(tactic)
#             threat_vectors.append(
#                 {
#                     "id": tactic.split(":")[0],
#                     "name": tactic.split(":")[1].strip(),
#                     "mapped_assets": [asset],
#                     "description": (
#                         "Telemetry analysis detected volume anomalies suggesting "
#                         "potential automated script exfiltration or encryption "
#                         "payloads."
#                     ),
#                 }
#             )
#         else:
#             for vector in threat_vectors:
#                 if (
#                     vector["id"] == tactic.split(":")[0]
#                     and asset not in vector["mapped_assets"]
#                 ):
#                     vector["mapped_assets"].append(asset)

#     if not threat_vectors:
#         threat_vectors.append(
#             {
#                 "id": "BASELINE",
#                 "name": "No anomalies detected",
#                 "mapped_assets": [],
#                 "description": (
#                     "System matches standard behavioral telemetry signatures."
#                 ),
#             }
#         )

#     # ── Mitigation audit trail ──────────────────────────────────────────
#     mitigation_logs = [
#         {
#             "timestamp": entry["timestamp"],
#             "node_name": entry["node_name"],
#             "reason": entry["reason"],
#             "mitre_tactic": entry["mitre_tactic"],
#             "script_output": entry["script_output"],
#         }
#         for entry in mitigation_history
#     ]

#     # ── Compliance stubs ────────────────────────────────────────────────
#     compliance = {
#         "auditor_sign_off": {
#             "title": "Lead SecOps Auditor",
#             "status": "PENDING",
#             "signature": None,
#             "timestamp": None,
#         },
#         "ciso_sign_off": {
#             "title": "Chief Information Security Officer (CISO)",
#             "status": "PENDING",
#             "signature": None,
#             "timestamp": None,
#         },
#     }

#     return {
#         "incident_metadata": {
#             "incident_id": incident_id,
#             "timestamp": timestamp,
#             "threat_level": threat_level,
#             "total_logs": total_logs,
#             "active_isolated_nodes": active_isolated,
#         },
#         "threat_vectors": threat_vectors,
#         "mitigation_logs": mitigation_logs,
#         "compliance_sign_off": compliance,
#     }
"""AegisGrid Telemetry Router.

Handles all telemetry-related endpoints:

- ``POST /api/telemetry``       – Ingest raw syslog or structured metrics, score via Isolation Forest,
                                  persist to DB, broadcast via WebSocket, and
                                  yield mitigation rules when threshold breached.
- ``POST /api/simulate-attack`` – Generate a synthetic anomalous event.
- ``GET  /api/topology``        – Return the current network node graph.
- ``GET  /api/forensic-report`` – Generate a MITRE ATT&CK-aligned incident report.
"""

from __future__ import annotations

import datetime
import logging
import uuid
from typing import Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from app.core.config import settings
from app.core.state import mitigation_history, node_statuses, ws_manager
from app.database.supabase import db_manager
from app.ml.isolation import AnomalyDetector
from app.ml.pipeline import parse_log

logger = logging.getLogger("aegisgrid.routers.telemetry")

router = APIRouter(prefix="/api", tags=["Telemetry"])

# ── Singleton ML model (trained once at import time) ────────────────────────
_detector = AnomalyDetector()


# ── Request Schemas ─────────────────────────────────────────────────────────

class TelemetryRequest(BaseModel):
    """Structured payload for the telemetry ingestion endpoint."""

    raw_log: Optional[str] = Field(
        None,
        description="Raw syslog line for anomaly evaluation.",
        examples=["2026-07-19T10:05:00Z [GATEWAY-01] admin_svc 150000 SUCCESS"]
    )
    timestamp_delta: Optional[float] = Field(None, description="Time delta since previous event")
    payload_bytes: Optional[int] = Field(None, description="Payload transfer volume in bytes")
    structural_entropy: Optional[float] = Field(None, description="Structural string randomness score")
    auth_scope_level: Optional[int] = Field(None, description="Privilege level of acting user")


# ── Endpoints ───────────────────────────────────────────────────────────────

@router.post("/telemetry", summary="Ingest & score a telemetry event")
async def process_telemetry(payload: TelemetryRequest) -> dict:
    """Asynchronous telemetry ingestion pipeline.

    1. Parse raw log OR build structured metadata from explicit fields.
    2. Run the event through the Isolation Forest anomaly detector.
    3. Persist the scored record to Supabase / SQLite asynchronously.
    4. Broadcast the event over WebSocket to all connected dashboards.
    5. Yield MITRE-aligned mitigation rules if threshold is breached.
    """
    raw_line = payload.raw_log.strip() if payload.raw_log else ""
    logger.info("Ingested telemetry log/payload: %.200s", raw_line or payload)

    # ── 1. Flexible Parsing Logic ──────────────────────────────────────────
    parsed = None
    if raw_line:
        parsed = parse_log(raw_line)

    # Fallback if raw_log parsing failed or if explicit fields were provided
    if not parsed:
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        parsed = {
            "timestamp": now_dt,
            "source_asset": "GATEWAY-01",
            "user_principal": "system_user",
            "bytes_transferred": payload.payload_bytes or 500,
            "timestamp_delta": payload.timestamp_delta or 1.0,
            "structural_entropy": payload.structural_entropy or 0.1,
            "auth_scope_level": payload.auth_scope_level or 1,
            "status": "SUCCESS"
        }

    # ── 2. Score ────────────────────────────────────────────────────────
    score, status = _detector.predict(parsed)

    # ── 3. Persist (non-blocking) ───────────────────────────────────────
    try:
        await db_manager.insert_log(parsed, score, status)
    except Exception:
        logger.exception("Database write failed — event still processed.")

    # ── 4. Topology state mutation ──────────────────────────────────────
    node_name = parsed["source_asset"]
    if node_statuses.get(node_name) == "ISOLATED":
        status = "ISOLATED"
    elif status == "CRITICAL_ANOMALY":
        node_statuses[node_name] = "CRITICAL"

    # ── 5. WebSocket broadcast ──────────────────────────────────────────
    event = {
        "type": "TELEMETRY_LOG",
        "raw_log": raw_line or f"{parsed['timestamp'].isoformat()} [{node_name}] {parsed['user_principal']} {parsed['bytes_transferred']} SUCCESS",
        "parsed": {
            "timestamp": parsed["timestamp"].isoformat(),
            "source_asset": parsed["source_asset"],
            "user_principal": parsed["user_principal"],
            "bytes_transferred": parsed["bytes_transferred"],
            "anomaly_score": score,
            "status": status,
        },
    }
    await ws_manager.broadcast(event)

    # ── 6. Mitigation rules (threshold breach) ──────────────────────────
    response: dict = {
        "status": "processed",
        "score": score,
        "classification": status,
        "parsed": {
            "timestamp": parsed["timestamp"].isoformat(),
            "source_asset": parsed["source_asset"],
            "user_principal": parsed["user_principal"],
            "bytes_transferred": parsed["bytes_transferred"],
        },
    }

    if score < settings.anomaly_threshold:
        mitre_tactic = (
            "T1486: Data Encrypted for Impact"
            if "DATABASE" in node_name
            else "T1048: Exfiltration Over Alternative Protocol"
        )
        response["mitigation"] = {
            "action": "AUTO_ISOLATE",
            "target_node": node_name,
            "mitre_tactic": mitre_tactic,
            "rules": [
                f"BLOCK all egress traffic from {node_name}",
                f"REVOKE active sessions for principal '{parsed['user_principal']}'",
                f"SNAPSHOT forensic image of {node_name} disk state",
                "ESCALATE to SOC Tier-2 for manual review",
            ],
        }
        logger.warning(
            "Anomaly threshold breached on %s (score=%.6f). "
            "Mitigation rules yielded.",
            node_name,
            score,
        )

        # Auto-isolation trigger — import here to avoid circular at module level
        if node_statuses.get(node_name) != "ISOLATED":
            from app.routers.containment import trigger_isolation_sequence

            await trigger_isolation_sequence(
                node_name,
                f"Auto-mitigation triggered by anomaly score {score:.4f}",
            )

    return response


@router.post("/simulate-attack", summary="Simulate a ransomware-scale event")
async def simulate_attack() -> dict:
    """Generate an anomalous out-of-bounds telemetry event."""
    now = (
        datetime.datetime.now(datetime.timezone.utc)
        .isoformat()
        .replace("+00:00", "Z")
    )
    simulated_log = f"{now} [DATABASE-CORE] backup_agent 5800000000 SUCCESS"
    logger.info("Simulating ransomware attack: %s", simulated_log)

    return await process_telemetry(TelemetryRequest(raw_log=simulated_log))


@router.get("/topology", summary="Retrieve current network topology")
async def get_topology() -> dict:
    """Return the live node graph with status and link adjacency data."""
    nodes = [
        {
            "id": k,
            "label": k,
            "status": v,
            "type": (
                "gateway"
                if "GATEWAY" in k
                else ("database" if "DATABASE" in k else "server")
            ),
        }
        for k, v in node_statuses.items()
    ]
    links = [
        {"from": "GATEWAY-01", "to": "BILLING-SRV"},
        {"from": "ADMIN-GATEWAY", "to": "DATABASE-CORE"},
        {"from": "BILLING-SRV", "to": "DATABASE-CORE"},
        {"from": "GATEWAY-01", "to": "ADMIN-GATEWAY"},
    ]
    return {"nodes": nodes, "links": links}


@router.get("/forensic-report", summary="Generate an incident forensic report")
async def generate_forensic_report() -> dict:
    """Produce a MITRE ATT&CK-aligned forensic incident report."""
    incident_id = (
        f"INC-{datetime.datetime.now().strftime('%Y%m%d')}"
        f"-{str(uuid.uuid4())[:8].upper()}"
    )
    timestamp = (
        datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
    )

    active_isolated = [
        k for k, v in node_statuses.items() if v == "ISOLATED"
    ]
    active_critical = [
        k for k, v in node_statuses.items() if v in ("CRITICAL", "CRITICAL_ANOMALY")
    ]

    if active_isolated:
        threat_level = "CRITICAL (BREACH ENCOUNTERED)"
    elif active_critical:
        threat_level = "HIGH (ANOMALY DETECTED)"
    else:
        threat_level = "SECURE"

    total_logs = await db_manager.get_total_logs_count()

    threat_vectors: list[dict] = []
    seen_tactics: set[str] = set()

    for node in active_isolated:
        tactic = (
            "T1486: Data Encrypted for Impact"
            if "DATABASE" in node
            else "T1048: Exfiltration Over Alternative Protocol"
        )
        if tactic not in seen_tactics:
            seen_tactics.add(tactic)
            threat_vectors.append(
                {
                    "id": tactic.split(":")[0],
                    "name": tactic.split(":")[1].strip(),
                    "mapped_assets": [node],
                    "description": (
                        "Adversary behavior targeting specific system enclave "
                        "elements to disrupt service or exfiltrate state data."
                    ),
                }
            )

    recent_anomalies = await db_manager.get_recent_anomalies(limit=5)
    for log_entry in recent_anomalies:
        asset = log_entry.get("source_asset", "UNKNOWN")
        tactic = (
            "T1486: Data Encrypted for Impact"
            if "DATABASE" in asset
            else "T1048: Exfiltration Over Alternative Protocol"
        )
        if tactic not in seen_tactics:
            seen_tactics.add(tactic)
            threat_vectors.append(
                {
                    "id": tactic.split(":")[0],
                    "name": tactic.split(":")[1].strip(),
                    "mapped_assets": [asset],
                    "description": (
                        "Telemetry analysis detected volume anomalies suggesting "
                        "potential automated script exfiltration or encryption "
                        "payloads."
                    ),
                }
            )
        else:
            for vector in threat_vectors:
                if (
                    vector["id"] == tactic.split(":")[0]
                    and asset not in vector["mapped_assets"]
                ):
                    vector["mapped_assets"].append(asset)

    if not threat_vectors:
        threat_vectors.append(
            {
                "id": "BASELINE",
                "name": "No anomalies detected",
                "mapped_assets": [],
                "description": "System matches standard behavioral telemetry signatures.",
            }
        )

    mitigation_logs = [
        {
            "timestamp": entry["timestamp"],
            "node_name": entry["node_name"],
            "reason": entry["reason"],
            "mitre_tactic": entry["mitre_tactic"],
            "script_output": entry["script_output"],
        }
        for entry in mitigation_history
    ]

    compliance = {
        "auditor_sign_off": {
            "title": "Lead SecOps Auditor",
            "status": "PENDING",
            "signature": None,
            "timestamp": None,
        },
        "ciso_sign_off": {
            "title": "Chief Information Security Officer (CISO)",
            "status": "PENDING",
            "signature": None,
            "timestamp": None,
        },
    }

    return {
        "incident_metadata": {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "threat_level": threat_level,
            "total_logs": total_logs,
            "active_isolated_nodes": active_isolated,
        },
        "threat_vectors": threat_vectors,
        "mitigation_logs": mitigation_logs,
        "compliance_sign_off": compliance,
    }