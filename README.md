# 🛡️ AegisGrid: Autonomous Cyber Resilience & Threat Mitigation Platform

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python" />
  <img src="https://img.shields.io/badge/FastAPI-0.100+-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Next.js-14.0-000000?style=for-the-badge&logo=next.js&logoColor=white" alt="Next.js" />
  <img src="https://img.shields.io/badge/Scikit--Learn-Isolation--Forest-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white" alt="Scikit-Learn" />
  <img src="https://img.shields.io/badge/Architecture-Modular--Monorepo-blueviolet?style=for-the-badge" alt="Architecture" />
  <img src="https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge" alt="License" />
</p>

> **AegisGrid is a high-throughput, enterprise cyber resilience engine unifying unsupervised Machine Learning anomaly analysis, persistent WebSocket state synchronization, and automated PowerShell/Bash micro-isolation to defend critical infrastructure against zero-day threat vectors.**

---

## ⚡ 30-Second Evaluator Quickstart

Reviewers and judges can instantly execute the diagnostic test suite to verify the end-to-end ML prediction loop, synthetic vector parsing, and containment logic in under 30 seconds without requiring external database keys or complex setup.

```bash
# 1. Clone the AegisGrid repository
git clone [https://github.com/hrishabh1416/AegisGrid.git](https://github.com/hrishabh1416/AegisGrid.git)
cd AegisGrid

# 2. Install backend environment requirements
pip install -r backend/requirements.txt

# 3. Launch Core FastAPI ASGI Server (Terminal 1)
python -m uvicorn main:app --reload --port 8000

# 4. Execute Standalone Evaluator Diagnostic Trace (Terminal 2)
python run_simulation.py

📸 Dashboard & SOC Interface Walkthrough : <img width="959" height="410" alt="image" src="https://github.com/user-attachments/assets/2355178b-f1fa-4fb4-9693-29dbca4f6a0e" /> <img width="955" height="404" alt="image" src="https://github.com/user-attachments/assets/fd150f82-4d62-42ec-bf9f-8685e6c43467" />
: Displays real-time operational status for registered network nodes (GATEWAY-01, DB-PRIMARY, AUTH-SERVICE). Assets dynamically transition between SECURE, WARNING, and ISOLATED states as telemetry streams through the pipeline.2. <img width="384" height="375" alt="image" src="https://github.com/user-attachments/assets/efbe3bb9-8879-4d02-b3ce-6b1aa797d990" />
 Threat Forensics & Post-Mortem Export ModalAutomated Forensics Panel: Generates audit-ready post-mortem JSON artifacts detailing ML decision score deviations ($Score < 0.000$), triggered MITRE ATT&CK tactics, and operator sign-off histories.

🏗️ Technical Architecture & DataflowAegisGrid uses a decoupled monorepo structure designed for sub-millisecond threat evaluation, real-time frontend propagation, and resilient containment execution.Plaintext


                        ┌──────────────────────────────────┐
                               │ Inbound Telemetry Stream (HTTP)  │
                               └────────────────┬─────────────────┘
                                                │
                                                ▼
                               ┌──────────────────────────────────┐
                               │ Regex Parser & Normalizer        │
                               │ (app/ml/pipeline.py)             │
                               └────────────────┬─────────────────┘
                                                │
                                                ▼
                               ┌──────────────────────────────────┐
                               │ Isolation Forest Predictor       │
                               │ (app/ml/isolation.py)            │
                               └────────────────┬─────────────────┘
                                                │
                          ┌─────────────────────┴─────────────────────┐
                          │                                           │
             [Score ≥ 0.000: SECURE]                     [Score < 0.000: THREAT DETECTED]
                          │                                           │
                          ▼                                           ▼
             ┌─────────────────────────┐                 ┌─────────────────────────┐
             │ Log Recorded            │                 │ Execute Containment     │
             │ Status: 200 OK          │                 │ (PowerShell/Bash Script)│
             └─────────────────────────┘                 └────────────┬────────────┘
                                                                      │
                                               ┌──────────────────────┴──────────────────────┐
                                               │                                             │
                                               ▼                                             ▼
                                 ┌──────────────────────────┐                  ┌──────────────────────────┐
                                 │ WebSocket Broadcast Pipe │                  │ Post-Mortem Audit Logger │
                                 │ (Next.js Dashboard)      │                  │ (Database Artifact Engine)│
                                 └──────────────────────────┘                  └──────────────────────────┘
🔬 Anomaly Detection Engine & Mathematical FormulationAegisGrid replaces static, rule-based signature matching with an unsupervised Isolation Forest estimator. The system constructs an ensemble of isolation trees to isolate anomalous observations.Anomaly Decision Score FormulaFor a given instance $x$ and sample size $n$, the anomaly score $Score(x)$ is computed as:$$Score(x) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}$$Where:$\mathbb{E}(h(x))$ represents the average path length of sample $x$ across the ensemble of isolation trees.$c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}$ is the average path length of unsuccessful searches in a Binary Search Tree (BST) built over $n$ nodes.Classification Thresholds$Score(x) \ge 0.0000$ (SECURE): Telemetry exhibits standard, baseline network behavior.$Score(x) < 0.0000$ (CRITICAL_ANOMALY): Observation isolates significantly closer to tree roots, triggering autonomous micro-isolation.🎯 MITRE ATT&CK Threat MappingWhen anomalous telemetry crosses the prediction threshold, AegisGrid maps extracted feature vectors directly to the MITRE ATT&CK Matrix:Technique IDTechnique NameAttack Pattern / ScenarioAutonomous MitigationT1048Exfiltration Over Alternative ProtocolOut-of-hours connection spike with massive egress volume.Immediate host firewall port block (e.g., port 3306 / 8080).T1486Data Encrypted for ImpactHigh-frequency IOPS and mass file access on primary databases.Micro-isolation script termination & asset process freeze.T1078Valid Accounts (Hijacking)Unexpected service principal login from non-standard origin subnet.Session termination & automatic credential revocation event.🔌 API Endpoint Documentation1. Ingest Telemetry StreamPOST /api/telemetryRequest Payload:JSON{
  "raw_log": "2026-07-20T10:02:48Z [DATABASE-CORE] backup_agent 5800000000 SUCCESS"
}
Response (Threat Detected):JSON{
  "status": "CRITICAL_ANOMALY",
  "anomaly_score": -0.045211,
  "mitre_tactic": "T1048 [Exfiltration Over Alternative Protocol]",
  "mitigation_action": "MICRO_ISOLATION_ENGAGED",
  "target_asset": "DATABASE-CORE"
}
2. Manual Operator Override ContainmentPOST /api/containment/overrideRequest Payload:JSON{
  "node_id": "DATABASE-CORE",
  "action": "ISOLATE",
  "operator_id": "SEC_OPS_ADMIN_01",
  "reason": "Preemptive maintenance during active threat window."
}
3. Real-Time WebSocket PipelineWS /api/wsIncoming Event Streams: TELEMETRY_LOG, NODE_ISOLATED, TOPOLOGY_UPDATE.📂 Project Directory StructurePlaintextAegisGrid/
├── backend/                         # Core Python FastAPI Backend
│   ├── app/
│   │   ├── core/                    # Security Primitives & System State
│   │   │   ├── config.py            # Global Settings & Environment Constants
│   │   │   ├── security.py          # CORS & Token Protocols
│   │   │   └── state.py             # In-Memory Network Asset Registry
│   │   ├── database/                # Persistence Layer
│   │   │   └── supabase.py          # Database Connection Client
│   │   ├── ml/                      # Machine Learning Subsystem
│   │   │   ├── isolation.py         # IsolationForest Model Execution
│   │   │   └── pipeline.py          # Log Parsing & Feature Extraction Engine
│   │   └── routers/                 # Modular API Route Controllers
│   │       ├── containment.py       # Isolation & Post-Mortem APIs
│   │       └── telemetry.py         # Ingestion & Attack Simulation APIs
│   ├── main.py                      # FastAPI Application Entry Point
│   └── requirements.txt             # Python Package Dependencies
│
├── src/                             # Next.js 14 Frontend Application
│   ├── app/                         # App Router Page Layouts
│   │   ├── layout.js                # Root Page Layout
│   │   ├── page.js                  # Main Operations SOC Dashboard
│   │   └── components/              # Interactive Graphs, Toast Alerts, Modals
│
├── test_suite/                      # Diagnostic Test Vector Matrix
│   ├── baseline_telemetry.json      # Standard Infrastructure Telemetry Vector
│   └── malicious_payload_t1048.json # Critical Ransomware / Exfiltration Vector
│
├── run_simulation.py                # Standalone Evaluator Diagnostic Script
├── verify_aegisgrid.py              # ML Pipeline Unit Test Suite
├── verify_e2e.py                    # Programmatic End-to-End WebSocket Test
└── README.md                        # Documentation
🧪 Comprehensive Verification & Test SuitesAegisGrid includes three distinct testing mechanisms:Verification ScriptScopeCommandrun_simulation.pyStandalone Evaluator CLI Trace (30s)python run_simulation.pyverify_aegisgrid.pyMachine Learning Unit Test Suitepython verify_aegisgrid.pyverify_e2e.pyProgrammatic Async WebSocket & REST Looppython verify_e2e.py

🛡️ License
Distributed under the MIT License. See LICENSE for more information.
