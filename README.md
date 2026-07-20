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
git clone https://github.com/hrishabh1416/AegisGrid.git
cd AegisGrid

# 2. Install backend environment requirements
pip install -r backend/requirements.txt

# 3. Launch Core FastAPI ASGI Server (Terminal 1)
python -m uvicorn main:app --reload --port 8000

# 4. Launch frontend (Terminal 2)
npm run dev

# 5. Execute Standalone Evaluator Diagnostic Trace (Terminal 3)
python run_simulation.py
```

---

## 📸 Dashboard & SOC Interface Walkthrough

### 1. Operations Dashboard
<p align="center">
  <img width="959" height="410" alt="AegisGrid Security Operations Center Interface" src="https://github.com/user-attachments/assets/2355178b-f1fa-4fb4-9693-29dbca4f6a0e" />
</p>

<p align="center">
  <img width="955" height="404" alt="Real-time Node Monitoring Stream" src="https://github.com/user-attachments/assets/fd150f82-4d62-42ec-bf9f-8685e6c43467" />
</p>

Displays real-time operational status for registered network nodes (`GATEWAY-01`, `DB-PRIMARY`, `AUTH-SERVICE`). Assets dynamically transition between `SECURE`, `WARNING`, and `ISOLATED` states as telemetry streams through the pipeline.

### 2. Threat Forensics & Post-Mortem Export Modal
<p align="center">
  <img width="384" height="375" alt="Automated Threat Forensics Panel" src="https://github.com/user-attachments/assets/efbe3bb9-8879-4d02-b3ce-6b1aa797d990" />
</p>

**Automated Forensics Panel:** Generates audit-ready post-mortem JSON artifacts detailing ML decision score deviations (\(Score < 0.000\)), triggered MITRE ATT&CK tactics, and operator sign-off histories.

---

## 🏗️ Technical Architecture & Dataflow

AegisGrid uses a decoupled monorepo structure designed for sub-millisecond threat evaluation, real-time frontend propagation, and resilient containment execution.

```text
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
                        ┌──────────────────────────────────────┴──────────────────────────────────────┐
                        │                                                                             │
                        ▼                                                                             ▼
          ┌──────────────────────────┐                                                  ┌──────────────────────────┐
          │ WebSocket Broadcast Pipe │                                                  │ Post-Mortem Audit Logger │
          │ (Next.js Dashboard)      │                                                  │ (Database Artifact Engine)│
          └──────────────────────────┘                                                  └──────────────────────────┘
```

---

## 🔬 Anomaly Detection Engine & Mathematical Formulation

AegisGrid replaces static, rule-based signature matching with an unsupervised Isolation Forest estimator. The system constructs an ensemble of isolation trees to isolate anomalous observations.

### Anomaly Decision Score Formula
For a given instance \(x\) and sample size \(n\), the anomaly score \(Score(x)\) is computed as:

\[Score(x) = 2^{-\frac{\mathbb{E}(h(x))}{c(n)}}\]

Where:
* \(\mathbb{E}(h(x))\) represents the average path length of sample \(x\) across the ensemble of isolation trees.
* \(c(n) = 2 \ln(n - 1) + 0.5772156649 - \frac{2(n - 1)}{n}\) is the average path length of unsuccessful searches in a Binary Search Tree (BST) built over \(n\) nodes.

### Classification Thresholds
* **\(Score(x) \ge 0.0000\) (SECURE):** Telemetry exhibits standard, baseline network behavior.
* **\(Score(x) < 0.0000\) (CRITICAL_ANOMALY):** Observation isolates significantly closer to tree roots, triggering autonomous micro-isolation.

---

## 🎯 MITRE ATT&CK Threat Mapping

When anomalous telemetry crosses the prediction threshold, AegisGrid maps extracted feature vectors directly to the MITRE ATT&CK Matrix:

| Technique ID | Technique Name | Attack Pattern / Scenario | Autonomous Mitigation |
| :--- | :--- | :--- | :--- |
| **T1048** | Exfiltration Over Alternative Protocol | Out-of-hours connection spike with massive egress volume. | Immediate host firewall port block (e.g., port 3306 / 8080). |
| **T1486** | Data Encrypted for Impact | High-frequency IOPS and mass file access on primary databases. | Micro-isolation script termination & asset process freeze. |
| **T1078** | Valid Accounts (Hijacking) | Unexpected service principal login from non-standard origin subnet. | Session termination & automatic credential revocation event. |

---

## 🔌 API Endpoint Documentation

### 1. Ingest Telemetry Stream
`POST /api/telemetry`

**Request Payload:**
```json
{
  "raw_log": "2026-07-20T10:02:48Z [DATABASE-CORE] backup_agent 5800000000 SUCCESS"
}
```

**Response (Threat Detected):**
```json
{
  "status": "CRITICAL_ANOMALY",
  "anomaly_score": -0.045211,
  "mitre_tactic": "T1048 [Exfiltration Over Alternative Protocol]",
  "mitigation_action": "MICRO_ISOLATION_ENGAGED",
  "target_asset": "DATABASE-CORE"
}
```

### 2. Manual Operator Override Containment
`POST /api/containment/override`

**Request Payload:**
```json
{
  "node_id": "DATABASE-CORE",
  "action": "ISOLATE",
  "operator_id": "SEC_OPS_ADMIN_01",
  "reason": "Preemptive maintenance during active threat window."
}
```

### 3. Real-Time WebSocket Pipeline
`WS /api/ws`

**Incoming Event Streams:** `TELEMETRY_LOG`, `NODE_ISOLATED`, `TOPOLOGY_UPDATE`.

---

## 📂 Project Directory Structure

```text
AegisGrid/
├── backend/                         # Core Python FastAPI Backend
│   ├── app/
│   │   ├── core/                    # Security Primitives & System State
│   │   ├── ml/                      # Pipeline, Parser & Isolation Forest
│   │   └── api/                     # REST Endpoints & WebSocket Routers
│   ├── main.py                      # ASGI Application Entrypoint
│   └── requirements.txt             # Engine Dependency Manifesto
├── frontend/                        # Next.js Security Dashboard
│   ├── components/                  # SOC Interface Widgets & Modal Panels
│   └── app/                         # App Router Views & State Sockets
├── run_simulation.py                # Standalone Evaluator Diagnostic Engine
└── README.md                        # Documentation Registry
```


🧪 Comprehensive Verification & Test Suite- sAegisGrid includes three distinct testing mechanisms Verification Script Scope Command 
run_simulation.py:  Standalone Evaluator CLI Trace (30s) : python run_simulation.py 
verify_aegisgrid.py: Machine Learning Unit Test Suite : python verify_aegisgrid.py 
verify_e2e.py : Programmatic Async WebSocket & REST Loop : python verify_e2e.py

🛡️ License
Distributed under the MIT License. See LICENSE for more information
