import os
import sys
import json
import re
import subprocess
import sqlite3
import datetime
from typing import List, Dict, Any

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv

from ml_core import AegisMLPipeline

load_dotenv()

app = FastAPI(title="AegisGrid Resilience Engine Backend", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ml_pipeline = AegisMLPipeline()

node_statuses = {
    "GATEWAY-01": "SECURE",
    "ADMIN-GATEWAY": "SECURE",
    "BILLING-SRV": "SECURE",
    "DATABASE-CORE": "SECURE"
}

mitigation_history = []

class DatabaseManager:
    def __init__(self):
        self.use_sqlite = True
        self.supabase_client = None
        
        self.supabase_url = os.getenv("SUPABASE_URL")
        self.supabase_key = os.getenv("SUPABASE_KEY")
        
        if self.supabase_url and self.supabase_key:
            try:
                from supabase import create_client
                self.supabase_client = create_client(self.supabase_url, self.supabase_key)
                self.use_sqlite = False
                print("DBManager: Connected to Supabase Cloud Database.")
            except Exception as e:
                print(f"DBManager: Failed to connect to Supabase: {e}. Falling back to SQLite.")
        else:
            print("DBManager: Supabase credentials missing. Falling back to local SQLite database.")
            
        if self.use_sqlite:
            self._init_sqlite()

    def _init_sqlite(self):
        conn = sqlite3.connect("aegisgrid.db")
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_asset TEXT NOT NULL,
                user_principal TEXT NOT NULL,
                bytes_transferred INTEGER NOT NULL,
                anomaly_score REAL NOT NULL,
                status TEXT NOT NULL
            );
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_telemetry_source_timestamp 
            ON telemetry_logs (source_asset, timestamp);
        """)
        conn.commit()
        conn.close()

    def insert_log(self, parsed_log: dict, score: float, status: str):
        record = {
            "timestamp": parsed_log["timestamp"].isoformat(),
            "source_asset": parsed_log["source_asset"],
            "user_principal": parsed_log["user_principal"],
            "bytes_transferred": parsed_log["bytes_transferred"],
            "anomaly_score": score,
            "status": status
        }
        
        if not self.use_sqlite and self.supabase_client:
            try:
                self.supabase_client.table("telemetry_logs").insert(record).execute()
                print("DBManager: Log inserted successfully into Supabase.")
                return
            except Exception as e:
                print(f"DBManager: Supabase insert failed: {e}. Falling back to SQLite.")
                
        conn = sqlite3.connect("aegisgrid.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO telemetry_logs (timestamp, source_asset, user_principal, bytes_transferred, anomaly_score, status)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            record["timestamp"],
            record["source_asset"],
            record["user_principal"],
            record["bytes_transferred"],
            record["anomaly_score"],
            record["status"]
        ))
        conn.commit()
        conn.close()
        print("DBManager: Log inserted successfully into SQLite.")

    def clear_logs(self):
        if not self.use_sqlite and self.supabase_client:
            try:
                self.supabase_client.table("telemetry_logs").delete().neq("id", -1).execute()
                print("DBManager: Logs deleted from Supabase.")
            except Exception as e:
                print(f"DBManager: Supabase delete failed: {e}. Falling back to SQLite.")
        
        conn = sqlite3.connect("aegisgrid.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM telemetry_logs;")
        conn.commit()
        conn.close()
        print("DBManager: SQLite database logs cleared.")

    def get_total_logs_count(self) -> int:
        if not self.use_sqlite and self.supabase_client:
            try:
                res = self.supabase_client.table("telemetry_logs").select("id", count="exact").execute()
                return res.count if res.count is not None else 0
            except Exception as e:
                print(f"DBManager: Supabase count query failed: {e}. Falling back to SQLite.")
        
        conn = sqlite3.connect("aegisgrid.db")
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM telemetry_logs;")
        count = cursor.fetchone()[0]
        conn.close()
        return count

    def get_recent_anomalies(self, limit: int = 10) -> List[Dict[str, Any]]:
        if not self.use_sqlite and self.supabase_client:
            try:
                res = self.supabase_client.table("telemetry_logs")\
                    .select("*")\
                    .eq("status", "CRITICAL_ANOMALY")\
                    .order("timestamp", descending=True)\
                    .limit(limit)\
                    .execute()
                return res.data
            except Exception as e:
                print(f"DBManager: Supabase query failed: {e}. Falling back to SQLite.")
        
        conn = sqlite3.connect("aegisgrid.db")
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM telemetry_logs 
            WHERE status = 'CRITICAL_ANOMALY' 
            ORDER BY timestamp DESC 
            LIMIT ?;
        """, (limit,))
        rows = cursor.fetchall()
        conn.close()
        return [dict(row) for row in rows]

db_manager = DatabaseManager()

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"WSManager: New client connected. Total connections: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        print(f"WSManager: Client disconnected. Total connections: {len(self.active_connections)}")

    async def broadcast(self, message: dict):
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
                
        for connection in dead_connections:
            self.disconnect(connection)

ws_manager = ConnectionManager()

class TelemetryRequest(BaseModel):
    raw_log: str

class IsolationRequest(BaseModel):
    node_name: str



@app.websocket("/api/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "TOPOLOGY_UPDATE",
            "nodes": [
                {"id": k, "label": k, "status": v}
                for k, v in node_statuses.items()
            ]
        })
        while True:
            data = await websocket.receive_text()
       
            await websocket.send_json({"type": "PONG"})
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)

@app.post("/api/telemetry")
async def process_telemetry(payload: TelemetryRequest):
    raw_line = payload.raw_log.strip()
    print(f"API: Ingested telemetry raw log: {raw_line}")
    
    parsed = ml_pipeline.parse_log(raw_line)
    if not parsed:
        raise HTTPException(status_code=400, detail="Log format invalid. Must match: TIMESTAMP [ASSET] USER BYTES STATUS")
        
    score, status = ml_pipeline.evaluate(parsed)
    
    db_manager.insert_log(parsed, score, status)
    
    node_name = parsed["source_asset"]
    if node_statuses.get(node_name) == "ISOLATED":
        status = "ISOLATED"
    elif status == "CRITICAL_ANOMALY":
        node_statuses[node_name] = "CRITICAL"
        
    event = {
        "type": "TELEMETRY_LOG",
        "raw_log": raw_line,
        "parsed": {
            "timestamp": parsed["timestamp"].isoformat(),
            "source_asset": parsed["source_asset"],
            "user_principal": parsed["user_principal"],
            "bytes_transferred": parsed["bytes_transferred"],
            "anomaly_score": score,
            "status": status
        }
    }
    await ws_manager.broadcast(event)
    
    if status == "CRITICAL_ANOMALY" and node_statuses.get(node_name) != "ISOLATED":
        print(f"API: Anomaly threshold breached on {node_name}! Triggering auto-isolation...")
        await trigger_isolation_sequence(node_name, f"Auto-mitigation triggered by anomaly score {score:.4f}")
        
    return {"status": "processed", "score": score, "classification": status, "parsed": parsed}

@app.get("/api/topology")
def get_topology():
    nodes = [
        {"id": k, "label": k, "status": v, "type": "gateway" if "GATEWAY" in k else ("database" if "DATABASE" in k else "server")}
        for k, v in node_statuses.items()
    ]
    links = [
        {"from": "GATEWAY-01", "to": "BILLING-SRV"},
        {"from": "ADMIN-GATEWAY", "to": "DATABASE-CORE"},
        {"from": "BILLING-SRV", "to": "DATABASE-CORE"},
        {"from": "GATEWAY-01", "to": "ADMIN-GATEWAY"}
    ]
    return {"nodes": nodes, "links": links}

@app.post("/api/simulate-attack")
async def simulate_attack():
    """Generates an anomalous out-of-bounds telemetry event that triggers a critical alert."""

    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    
    simulated_log = f"{now} [DATABASE-CORE] backup_agent 5800000000 SUCCESS"
    print(f"API: Simulating ransomware attack scenario: {simulated_log}")
    
    return await process_telemetry(TelemetryRequest(raw_log=simulated_log))

@app.post("/api/isolate-node")
async def isolate_node(payload: IsolationRequest):
    node_name = payload.node_name
    if node_name not in node_statuses:
        raise HTTPException(status_code=400, detail="Invalid node asset name.")
        
    result = await trigger_isolation_sequence(node_name, "Manual operator command execution.")
    return {"status": "isolated", "node": node_name, "script_output": result}

async def trigger_isolation_sequence(node_name: str, trigger_reason: str) -> str:
    """Invokes the localized PowerShell or Shell script to isolate the targeted node."""
    node_statuses[node_name] = "ISOLATED"
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    is_windows = sys.platform.startswith("win")
    
    script_output = ""
    try:
        if is_windows:
            script_path = os.path.join(current_dir, "isolate_node.ps1")
            cmd = ["powershell.exe", "-ExecutionPolicy", "Bypass", "-File", script_path, "-NodeName", node_name]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            script_output = result.stdout
        else:
            script_path = os.path.join(current_dir, "isolate_node.sh")
         
            subprocess.run(["chmod", "+x", script_path], check=False)
            cmd = [script_path, node_name]
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            script_output = result.stdout
    except Exception as e:
        script_output = f"Isolation Script Error: {str(e)}"
        print(script_output)
        
    print(f"API: Isolated node {node_name}. Script Output:\n{script_output}")
    
    mitigation_history.append({
        "node_name": node_name,
        "reason": trigger_reason,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z",
        "mitre_tactic": "T1486: Data Encrypted for Impact" if "DATABASE" in node_name else "T1048: Exfiltration Over Alternative Protocol",
        "script_output": script_output
    })
    
    await ws_manager.broadcast({
        "type": "NODE_ISOLATED",
        "node_name": node_name,
        "reason": trigger_reason,
        "mitre_tactic": "T1486: Data Encrypted for Impact" if "DATABASE" in node_name else "T1048: Exfiltration Over Alternative Protocol",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "script_output": script_output
    })
    
    await ws_manager.broadcast({
        "type": "TOPOLOGY_UPDATE",
        "nodes": [
            {"id": k, "label": k, "status": v}
            for k, v in node_statuses.items()
        ]
    })
    
    return script_output

@app.post("/api/reset")
async def reset_system():

    for k in node_statuses:
        node_statuses[k] = "SECURE"
        
    db_manager.clear_logs()
    
    current_dir = os.path.dirname(os.path.abspath(__file__))
    lock_file = os.path.join(current_dir, "isolated_nodes.txt")
    if os.path.exists(lock_file):
        try:
            os.remove(lock_file)
            print("API: isolated_nodes.txt file cleared.")
        except Exception as e:
            print(f"API: Error clearing isolated_nodes.txt: {e}")
            
    global mitigation_history
    mitigation_history.clear()
    
    await ws_manager.broadcast({
        "type": "RESET"
    })
    
    await ws_manager.broadcast({
        "type": "TOPOLOGY_UPDATE",
        "nodes": [
            {"id": k, "label": k, "status": v}
            for k, v in node_statuses.items()
        ]
    })
    
    return {"status": "success", "message": "System state reset completed."}

@app.get("/api/forensic-report")
def generate_forensic_report():
    import uuid
    
    incident_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat() + "Z"
    
    active_isolated = [k for k, v in node_statuses.items() if v == "ISOLATED"]
    active_critical = [k for k, v in node_statuses.items() if v in ("CRITICAL", "CRITICAL_ANOMALY")]
    
    if active_isolated:
        threat_level = "CRITICAL (BREACH ENCOUNTERED)"
    elif active_critical:
        threat_level = "HIGH (ANOMALY DETECTED)"
    else:
        threat_level = "SECURE"
        
    total_logs = db_manager.get_total_logs_count()
    
    threat_vectors = []
    seen_tactics = set()
    
    for node in active_isolated:
        tactic = "T1486: Data Encrypted for Impact" if "DATABASE" in node else "T1048: Exfiltration Over Alternative Protocol"
        if tactic not in seen_tactics:
            seen_tactics.add(tactic)
            threat_vectors.append({
                "id": tactic.split(":")[0],
                "name": tactic.split(":")[1].strip(),
                "mapped_assets": [node],
                "description": "Adversary behavior targeting specific system enclave elements to disrupt service or exfiltrate state data."
            })
            
    recent_anomalies = db_manager.get_recent_anomalies(limit=5)
    for log in recent_anomalies:
        asset = log.get("source_asset", "UNKNOWN")
        tactic = "T1486: Data Encrypted for Impact" if "DATABASE" in asset else "T1048: Exfiltration Over Alternative Protocol"
        if tactic not in seen_tactics:
            seen_tactics.add(tactic)
            threat_vectors.append({
                "id": tactic.split(":")[0],
                "name": tactic.split(":")[1].strip(),
                "mapped_assets": [asset],
                "description": "Telemetry analysis detected volume anomalies suggesting potential automated script exfiltration or encryption payloads."
            })
        else:
            for vector in threat_vectors:
                if vector["id"] == tactic.split(":")[0] and asset not in vector["mapped_assets"]:
                    vector["mapped_assets"].append(asset)
                    
    if not threat_vectors:
        threat_vectors.append({
            "id": "BASELINE",
            "name": "No anomalies detected",
            "mapped_assets": [],
            "description": "System matches standard behavioral telemetry signatures."
        })
        
    mitigation_logs = []
    for entry in mitigation_history:
        mitigation_logs.append({
            "timestamp": entry["timestamp"],
            "node_name": entry["node_name"],
            "reason": entry["reason"],
            "mitre_tactic": entry["mitre_tactic"],
            "script_output": entry["script_output"]
        })
        
    compliance = {
        "auditor_sign_off": {
            "title": "Lead SecOps Auditor",
            "status": "PENDING",
            "signature": None,
            "timestamp": None
        },
        "ciso_sign_off": {
            "title": "Chief Information Security Officer (CISO)",
            "status": "PENDING",
            "signature": None,
            "timestamp": None
        }
    }
    
    return {
        "incident_metadata": {
            "incident_id": incident_id,
            "timestamp": timestamp,
            "threat_level": threat_level,
            "total_logs": total_logs,
            "active_isolated_nodes": active_isolated
        },
        "threat_vectors": threat_vectors,
        "mitigation_logs": mitigation_logs,
        "compliance_sign_off": compliance
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
