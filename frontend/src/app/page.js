"use client";

import { useEffect, useRef, useState } from "react";
import { 
  Shield, 
  ShieldAlert, 
  ShieldCheck, 
  Terminal, 
  Activity, 
  Zap, 
  Server, 
  Cpu, 
  Network as NetIcon, 
  AlertTriangle,
  Play, 
  Wifi, 
  WifiOff, 
  RotateCcw,
  User,
  Clock,
  HardDrive,
  Award,
  FileText,
  CheckCircle2,
  X
} from "lucide-react";

export default function Home() {
  const containerRef = useRef(null);
  const networkRef = useRef(null);
  const wsRef = useRef(null);

  // Connection & System States
  const [wsStatus, setWsStatus] = useState("DISCONNECTED");
  const [threatLevel, setThreatLevel] = useState("SECURE"); // SECURE, WARNING, BREACH
  const [logs, setLogs] = useState([]);
  const [isolatedNodes, setIsolatedNodes] = useState([]);
  const [stats, setStats] = useState({
    totalLogs: 0,
    anomalies: 0,
    isolated: 0,
  });

  // Forensic Report & Compliance Sign-offs
  const [showForensicModal, setShowForensicModal] = useState(false);
  const [forensicReport, setForensicReport] = useState(null);
  const [auditorSigned, setAuditorSigned] = useState(false);
  const [cisoSigned, setCisoSigned] = useState(false);
  const [signatureAuditorTime, setSignatureAuditorTime] = useState("");
  const [signatureCisoTime, setSignatureCisoTime] = useState("");

  // Current topology states (synced from server and updated locally)
  const [nodesData, setNodesData] = useState([
    { id: "GATEWAY-01", label: "GATEWAY-01", status: "SECURE" },
    { id: "ADMIN-GATEWAY", label: "ADMIN-GATEWAY", status: "SECURE" },
    { id: "BILLING-SRV", label: "BILLING-SRV", status: "SECURE" },
    { id: "DATABASE-CORE", label: "DATABASE-CORE", status: "SECURE" }
  ]);

  // Connect to backend WebSocket
  useEffect(() => {
    connectWebSocket();
    return () => {
      if (wsRef.current) wsRef.current.close();
    };
  }, []);

  const connectWebSocket = () => {
    setWsStatus("CONNECTING");
    const ws = new WebSocket("ws://localhost:8000/api/ws");

    ws.onopen = () => {
      setWsStatus("CONNECTED");
      console.log("WebSocket connection established.");
    };

    ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      console.log("WebSocket event received:", data);

      if (data.type === "TOPOLOGY_UPDATE") {
        setNodesData(data.nodes);
        updateStatsAndThreats(data.nodes);
      } else if (data.type === "TELEMETRY_LOG") {
        // Append log to ticker
        setLogs((prev) => [data, ...prev].slice(0, 100));
        setStats((prev) => ({ ...prev, totalLogs: prev.totalLogs + 1 }));
        
        if (data.parsed.status === "CRITICAL_ANOMALY" || data.parsed.status === "CRITICAL") {
          setStats((prev) => ({ ...prev, anomalies: prev.anomalies + 1 }));
          setThreatLevel("BREACH");
        }
      } else if (data.type === "NODE_ISOLATED" || data.type === "ISOLATED") {
        const nodeName = data.node_name || data.nodeName || data.node;
        const reason = data.reason || "Containment action";
        const mitre = data.mitre_tactic || data.mitre || "T1048: Exfiltration";
        const timestamp = data.timestamp || new Date().toISOString();
        const output = data.script_output || data.output || "Isolated via automated agent script.";

        setIsolatedNodes((prev) => {
          if (prev.some((n) => n.nodeName === nodeName)) return prev;
          return [
            {
              nodeName,
              reason,
              mitre,
              timestamp,
              output,
            },
            ...prev
          ];
        });
        setStats((prev) => ({ ...prev, isolated: prev.isolated + 1 }));
        setThreatLevel("BREACH");
      } else if (data.type === "RESET") {
        setLogs([]);
        setIsolatedNodes([]);
        setStats({
          totalLogs: 0,
          anomalies: 0,
          isolated: 0,
        });
        setThreatLevel("SECURE");
        setAuditorSigned(false);
        setCisoSigned(false);
        setSignatureAuditorTime("");
        setSignatureCisoTime("");
      }
    };

    ws.onclose = () => {
      setWsStatus("DISCONNECTED");
      console.log("WebSocket connection closed. Retrying in 3 seconds...");
      setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (err) => {
      console.error("WebSocket error:", err);
      ws.close();
    };

    wsRef.current = ws;
  };

  const updateStatsAndThreats = (nodes) => {
    const isolatedCount = nodes.filter(n => n.status === "ISOLATED").length;
    const criticalCount = nodes.filter(n => n.status === "CRITICAL" || n.status === "CRITICAL_ANOMALY").length;
    
    setStats((prev) => ({
      ...prev,
      isolated: isolatedCount,
    }));

    if (isolatedCount > 0 || criticalCount > 0) {
      setThreatLevel("BREACH");
    } else {
      setThreatLevel("SECURE");
    }
  };

  // Vis.js Network Rendering
  useEffect(() => {
    if (typeof window === "undefined" || !containerRef.current) return;

    const vis = require("vis-network/standalone");
    
    // Convert current node states into Vis.js nodes config
    const networkNodes = nodesData.map((node) => {
      let color = {
        background: "#0f172a",
        border: "#10b981",
        highlight: { background: "#064e3b", border: "#10b981" }
      };
      let shapeProperties = {};

      if (node.status === "CRITICAL" || node.status === "CRITICAL_ANOMALY") {
        color = {
          background: "#450a0a",
          border: "#ef4444",
          highlight: { background: "#7f1d1d", border: "#ef4444" }
        };
        shapeProperties = {
          borderDashes: false
        };
      } else if (node.status === "ISOLATED") {
        color = {
          background: "#1e293b",
          border: "#f97316",
          highlight: { background: "#334155", border: "#f97316" }
        };
        shapeProperties = {
          borderDashes: [5, 5]
        };
      }

      return {
        id: node.id,
        label: `${node.label}\n(${node.status})`,
        shape: "box",
        margin: 15,
        color: color,
        borderWidth: 2,
        font: {
          color: "#f1f5f9",
          size: 14,
          face: "monospace"
        },
        shadow: {
          enabled: true,
          color: node.status === "ISOLATED" ? "#f97316" : (node.status === "SECURE" ? "#10b981" : "#ef4444"),
          size: node.status === "SECURE" ? 10 : 25,
          x: 0,
          y: 0
        },
        shapeProperties: shapeProperties
      };
    });

    const networkEdges = [
      { from: "GATEWAY-01", to: "BILLING-SRV", color: { color: "#334155", highlight: "#38bdf8" }, width: 2 },
      { from: "ADMIN-GATEWAY", to: "DATABASE-CORE", color: { color: "#334155", highlight: "#38bdf8" }, width: 2 },
      { from: "BILLING-SRV", to: "DATABASE-CORE", color: { color: "#334155", highlight: "#38bdf8" }, width: 2 },
      { from: "GATEWAY-01", to: "ADMIN-GATEWAY", color: { color: "#334155", highlight: "#38bdf8" }, width: 2 }
    ];

    const data = {
      nodes: new vis.DataSet(networkNodes),
      edges: new vis.DataSet(networkEdges)
    };

    const options = {
      physics: {
        enabled: true,
        solver: "repulsion",
        repulsion: {
          nodeDistance: 160,
          centralGravity: 0.2,
          springLength: 120,
          springConstant: 0.05
        }
      },
      interaction: {
        hover: true,
        zoomView: true,
        dragView: true
      }
    };

    const network = new vis.Network(containerRef.current, data, options);
    networkRef.current = network;

    // Handle clicks on nodes
    network.on("selectNode", (params) => {
      const selectedNodeId = params.nodes[0];
      console.log("Selected node for potential manual isolation:", selectedNodeId);
    });

    return () => {
      if (networkRef.current) {
        networkRef.current.destroy();
        networkRef.current = null;
      }
    };
  }, [nodesData]);

  // Simulator Triggers
  const injectAttackScenario = async () => {
    try {
      setThreatLevel("WARNING");
      const res = await fetch("http://localhost:8000/api/simulate-attack", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      const data = await res.json();
      console.log("Attack scenario injected successfully:", data);
    } catch (e) {
      console.error("Failed to inject attack scenario:", e);
    }
  };

  const manualIsolateNode = async (nodeName) => {
    try {
      const res = await fetch("http://localhost:8000/api/isolate-node", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ node_name: nodeName })
      });
      const data = await res.json();
      console.log(`Node ${nodeName} manually isolated:`, data);
    } catch (e) {
      console.error(`Failed to manually isolate node ${nodeName}:`, e);
    }
  };

  const fetchForensicReport = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/forensic-report");
      const data = await res.json();
      setForensicReport(data);
      setShowForensicModal(true);
    } catch (e) {
      console.error("Failed to fetch forensic report:", e);
    }
  };

  const resetTopology = async () => {
    try {
      const res = await fetch("http://localhost:8000/api/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      const data = await res.json();
      console.log("System state reset response:", data);
    } catch (e) {
      console.error("Failed to reset system:", e);
    }
  };

  return (
    <div className="flex flex-col min-h-screen bg-slate-950 text-slate-100 cyber-grid">
      
      {/* 1. Header Control Bar */}
      <header className="border-b border-slate-800 bg-slate-900/80 backdrop-blur-md sticky top-0 z-50 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Shield className="h-8 w-8 text-emerald-500 animate-pulse" />
          <div>
            <h1 className="text-xl font-black tracking-wider text-slate-100 font-mono">
              AEGIS<span className="text-emerald-500">GRID</span>
            </h1>
            <p className="text-xs text-slate-400 uppercase tracking-widest font-mono">
              Cyber Resilience & Containment Engine
            </p>
          </div>
        </div>

        {/* Live Status Indicators */}
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-950 border border-slate-800 text-xs font-mono">
            <span className="text-slate-400">WS STATUS:</span>
            {wsStatus === "CONNECTED" ? (
              <span className="text-emerald-400 flex items-center gap-1.5 font-bold">
                <Wifi className="h-3.5 w-3.5" /> ONLINE
              </span>
            ) : wsStatus === "CONNECTING" ? (
              <span className="text-amber-400 flex items-center gap-1.5 font-bold animate-pulse">
                <Activity className="h-3.5 w-3.5" /> SYNCING
              </span>
            ) : (
              <span className="text-rose-500 flex items-center gap-1.5 font-bold">
                <WifiOff className="h-3.5 w-3.5" /> OFFLINE
              </span>
            )}
          </div>

          <div className="flex items-center gap-2">
            <button 
              onClick={injectAttackScenario}
              className="flex items-center gap-2 bg-gradient-to-r from-rose-600 to-red-700 hover:from-rose-500 hover:to-red-650 text-white font-mono text-xs font-bold uppercase py-2 px-4 rounded-md shadow-lg shadow-rose-900/30 transition-all border border-rose-500 active:scale-95 cursor-pointer"
            >
              <Play className="h-3.5 w-3.5 fill-current" /> Inject Ransomware Attack Scenario
            </button>

            <button 
              onClick={fetchForensicReport}
              className="flex items-center gap-2 bg-gradient-to-r from-indigo-600 to-blue-700 hover:from-indigo-500 hover:to-blue-650 text-white font-mono text-xs font-bold uppercase py-2 px-4 rounded-md shadow-lg shadow-indigo-900/30 transition-all border border-indigo-500 active:scale-95 cursor-pointer"
            >
              <Terminal className="h-3.5 w-3.5" /> Generate Post-Mortem
            </button>

            <button 
              onClick={resetTopology}
              className="flex items-center gap-2 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono text-xs font-bold uppercase py-2 px-3 rounded-md transition-all border border-slate-700 cursor-pointer"
              title="Re-Initialize Dashboard State"
            >
              <RotateCcw className="h-3.5 w-3.5" /> Reset
            </button>
          </div>
        </div>
      </header>

      {/* 2. Hero Component Rows */}
      <section className="p-6 grid grid-cols-1 md:grid-cols-4 gap-6">
        
        {/* Threat Level Gauge Card */}
        <div className="md:col-span-1 rounded-xl border border-slate-800 bg-slate-900/40 backdrop-blur-md p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-xs text-slate-400 font-mono uppercase tracking-wider">SYSTEM THREAT LEVEL</span>
            <Activity className="h-4 w-4 text-slate-400" />
          </div>
          
          <div className="py-6 flex flex-col items-center justify-center">
            {threatLevel === "SECURE" ? (
              <div className="flex flex-col items-center gap-3">
                <div className="p-4 rounded-full bg-emerald-500/10 border-2 border-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.2)] pulse-node-green">
                  <ShieldCheck className="h-12 w-12 text-emerald-500" />
                </div>
                <span className="text-2xl font-black font-mono text-emerald-400 tracking-widest mt-1">SECURE</span>
                <span className="text-center text-xs text-slate-400 max-w-[180px]">All network perimeter elements operational & baseline aligned.</span>
              </div>
            ) : threatLevel === "WARNING" ? (
              <div className="flex flex-col items-center gap-3">
                <div className="p-4 rounded-full bg-amber-500/10 border-2 border-amber-500 shadow-[0_0_20px_rgba(245,158,11,0.2)]">
                  <AlertTriangle className="h-12 w-12 text-amber-500 animate-bounce" />
                </div>
                <span className="text-2xl font-black font-mono text-amber-400 tracking-widest mt-1">WARNING</span>
                <span className="text-center text-xs text-slate-400 max-w-[180px]">Unusual telemetry signals detected. Evaluating logs...</span>
              </div>
            ) : (
              <div className="flex flex-col items-center gap-3">
                <div className="p-4 rounded-full bg-rose-500/10 border-2 border-rose-500 shadow-[0_0_25px_rgba(239,68,68,0.3)] pulse-node-red">
                  <ShieldAlert className="h-12 w-12 text-rose-500" />
                </div>
                <span className="text-2xl font-black font-mono text-rose-500 tracking-widest mt-1 animate-pulse">BREACH ALERT</span>
                <span className="text-center text-xs text-rose-400 font-bold max-w-[180px] uppercase">Micro-isolation sequence active!</span>
              </div>
            )}
          </div>
        </div>

        {/* Stats Cards */}
        <div className="rounded-xl border border-slate-800 bg-slate-900/40 backdrop-blur-md p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-xs text-slate-400 font-mono uppercase tracking-wider">TOTAL INGESTED LOGS</span>
            <Terminal className="h-4 w-4 text-slate-400" />
          </div>
          <div className="py-4">
            <span className="text-4xl font-extrabold font-mono text-slate-100">{stats.totalLogs}</span>
          </div>
          <div className="text-xs text-slate-400 font-mono">
            Parser speed: <span className="text-emerald-400">&lt; 1.5ms / line</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/40 backdrop-blur-md p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-xs text-slate-400 font-mono uppercase tracking-wider">ACTIVE ANOMALIES</span>
            <AlertTriangle className="h-4 w-4 text-rose-500" />
          </div>
          <div className="py-4">
            <span className="text-4xl font-extrabold font-mono text-rose-500">{stats.anomalies}</span>
          </div>
          <div className="text-xs text-slate-400 font-mono">
            Unsupervised threshold: <span className="text-rose-400">IsolationForest 99%</span>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-slate-900/40 backdrop-blur-md p-5 flex flex-col justify-between">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3">
            <span className="text-xs text-slate-400 font-mono uppercase tracking-wider">ISOLATED ENCLAVES</span>
            <NetIcon className="h-4 w-4 text-amber-500" />
          </div>
          <div className="py-4">
            <span className="text-4xl font-extrabold font-mono text-amber-500">{stats.isolated}</span>
          </div>
          <div className="text-xs text-slate-400 font-mono">
            Active Containment Ledger: <span className="text-amber-500">{stats.isolated} enclaves</span>
          </div>
        </div>

      </section>

      {/* 3. Main Workspace Grid */}
      <section className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6 flex-1">
        
        {/* Interactive Topology Graph (Left/Center) */}
        <div className="lg:col-span-2 rounded-xl border border-slate-800 bg-slate-900/20 backdrop-blur-md p-5 flex flex-col min-h-[450px] relative">
          <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
            <div className="flex items-center gap-2">
              <NetIcon className="h-5 w-5 text-emerald-500" />
              <span className="text-sm font-bold font-mono text-slate-200">CNI DIGITAL NETWORK TOPOLOGY</span>
            </div>
            <div className="flex gap-2 text-xxs font-mono">
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-emerald-500"></span> SECURE</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-rose-500"></span> CRITICAL</span>
              <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-amber-500"></span> ISOLATED</span>
            </div>
          </div>
          
          {/* Topology Canvas */}
          <div 
            ref={containerRef} 
            className="flex-1 w-full bg-slate-950/60 rounded-lg border border-slate-900 overflow-hidden min-h-[380px]"
            id="topology-graph-container"
          />

          {/* Quick Manual Actions Overlay */}
          <div className="absolute bottom-8 left-8 bg-slate-900/90 border border-slate-800 p-4 rounded-lg flex flex-col gap-2 z-10 max-w-xs">
            <span className="text-xs font-bold font-mono text-slate-300 border-b border-slate-800 pb-1 mb-1">MANUAL CONTAINMENT BLOCK</span>
            <div className="grid grid-cols-2 gap-2">
              {nodesData.map((node) => (
                <button
                  key={node.id}
                  disabled={node.status === "ISOLATED"}
                  onClick={() => manualIsolateNode(node.id)}
                  className={`text-[10px] font-mono font-bold uppercase p-1.5 rounded text-center transition-all ${
                    node.status === "ISOLATED" 
                      ? "bg-slate-800 text-slate-500 border border-slate-800 cursor-not-allowed"
                      : "bg-slate-950 text-amber-500 border border-amber-600/50 hover:bg-amber-600/10 active:scale-95"
                  }`}
                >
                  ISOLATE {node.id.split("-")[0]}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Containment Ledger Sidebar (Right) */}
        <div className="lg:col-span-1 rounded-xl border border-slate-800 bg-slate-900/20 backdrop-blur-md p-5 flex flex-col min-h-[450px]">
          <div className="flex items-center gap-2 border-b border-slate-800 pb-3 mb-4">
            <Zap className="h-5 w-5 text-amber-500" />
            <span className="text-sm font-bold font-mono text-slate-200 uppercase">Containment Action Ledger</span>
          </div>

          <div className="flex-1 overflow-y-auto flex flex-col gap-3 pr-1">
            {isolatedNodes.length === 0 ? (
              <div className="flex-1 flex flex-col items-center justify-center text-center p-6 border border-dashed border-slate-800/80 rounded-lg">
                <ShieldCheck className="h-10 w-10 text-emerald-500/40 mb-2" />
                <span className="text-xs font-mono text-slate-500 uppercase">No Micro-isolation Events Logged</span>
              </div>
            ) : (
              isolatedNodes.map((item, idx) => (
                <div 
                  key={idx}
                  className="p-4 rounded-lg bg-slate-950 border border-amber-500/30 flex flex-col gap-2 relative shadow-lg shadow-amber-950/10 border-l-4 border-l-amber-500"
                >
                  <div className="flex items-start justify-between">
                    <span className="text-xs font-bold font-mono text-amber-400 uppercase tracking-wider">
                      {item.nodeName}
                    </span>
                    <span className="text-[10px] text-slate-500 font-mono">
                      {new Date(item.timestamp).toLocaleTimeString()}
                    </span>
                  </div>

                  <div className="flex flex-col gap-1 text-[11px] font-mono text-slate-300">
                    <div className="flex items-center gap-1.5">
                      <User className="h-3 w-3 text-slate-500" /> 
                      <span>Trigger: {item.reason}</span>
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Shield className="h-3 w-3 text-rose-500" /> 
                      <span className="bg-rose-950/50 text-rose-400 px-1 py-0.5 rounded text-[10px] font-bold border border-rose-900/30">
                        {item.mitre}
                      </span>
                    </div>
                  </div>

                  <div className="mt-2 bg-slate-900 border border-slate-850 p-2 rounded text-[10px] font-mono text-slate-400 whitespace-pre-wrap leading-relaxed max-h-[100px] overflow-y-auto">
                    {item.output}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>

      </section>

      {/* 4. Bottom Active Live Terminal Ticker */}
      <footer className="border-t border-slate-800 bg-slate-900/60 backdrop-blur-md p-6">
        <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
          <div className="flex items-center gap-2">
            <Terminal className="h-5 w-5 text-emerald-400" />
            <span className="text-sm font-bold font-mono text-slate-200 uppercase tracking-wider">Active System Telemetry Stream</span>
          </div>
          <span className="text-xs font-mono text-slate-500 uppercase">
            WebSocket feed active
          </span>
        </div>

        <div className="w-full bg-slate-950 border border-slate-900 rounded-lg p-4 font-mono text-xs h-[180px] overflow-y-auto flex flex-col gap-1.5 shadow-inner">
          {logs.length === 0 ? (
            <div className="text-slate-600 flex items-center justify-center h-full">
              <span>Awaiting telemetry ingestion events... Use control panel or simulation triggers.</span>
            </div>
          ) : (
            logs.map((log, idx) => (
              <div 
                key={idx} 
                className={`py-1 border-b border-slate-900/50 flex items-start gap-3 hover:bg-slate-900/40 px-2 rounded transition-colors ${
                  log.parsed.status === "CRITICAL_ANOMALY" || log.parsed.status === "CRITICAL"
                    ? "text-rose-400 font-bold bg-rose-950/20 border-l-2 border-l-rose-500"
                    : log.parsed.status === "ISOLATED" 
                      ? "text-amber-400 border-l-2 border-l-amber-500 bg-amber-950/10" 
                      : "text-slate-300"
                }`}
              >
                <span className="text-slate-500 select-none text-[10px] mt-0.5">[{idx+1}]</span>
                <div className="flex-1 break-all font-mono leading-relaxed">
                  <span className="text-emerald-500 font-bold">RAW:</span> {log.raw_log}
                  <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-1 text-[11px] text-slate-400">
                    <span className="flex items-center gap-1"><Clock className="h-3 w-3 text-slate-500" /> {new Date(log.parsed.timestamp).toLocaleTimeString()}</span>
                    <span className="flex items-center gap-1"><HardDrive className="h-3 w-3 text-slate-500" /> {log.parsed.source_asset}</span>
                    <span className="flex items-center gap-1"><User className="h-3 w-3 text-slate-500" /> {log.parsed.user_principal}</span>
                    <span className="font-bold">Bytes: <span className="text-sky-400 font-normal">{log.parsed.bytes_transferred.toLocaleString()}</span></span>
                    <span className="font-bold">Anomaly Score: <span className={log.parsed.anomaly_score < -0.02 ? "text-rose-400" : "text-emerald-400"}>{log.parsed.anomaly_score.toFixed(4)}</span></span>
                    <span className={`px-1 py-0.2 rounded font-extrabold text-[9px] uppercase border ${
                      log.parsed.status === "CRITICAL_ANOMALY" || log.parsed.status === "CRITICAL"
                        ? "bg-rose-950/50 text-rose-400 border-rose-900"
                        : log.parsed.status === "ISOLATED"
                          ? "bg-amber-950/50 text-amber-400 border-amber-900"
                          : "bg-emerald-950/50 text-emerald-400 border-emerald-900"
                    }`}>{log.parsed.status}</span>
                  </div>
                </div>
              </div>
            ))
          )}
        </div>
      </footer>

      {/* Forensic Report Modal */}
      {showForensicModal && forensicReport && (
        <div className="fixed inset-0 bg-slate-950/90 backdrop-blur-md z-50 flex items-center justify-center p-4">
          <div className="bg-slate-900 border-2 border-slate-700/80 rounded-xl max-w-3xl w-full max-h-[90vh] overflow-y-auto shadow-2xl flex flex-col font-mono text-xs text-slate-100 animate-in fade-in zoom-in-95 duration-150 relative">
            
            {/* Modal Header */}
            <div className="border-b border-slate-800 bg-slate-900/50 p-5 flex items-center justify-between sticky top-0 backdrop-blur-sm z-10">
              <div className="flex items-center gap-2.5">
                <Award className="h-5 w-5 text-indigo-400" />
                <div>
                  <span className="text-sm font-bold tracking-wider text-slate-100">AEGISGRID CYBER-FORENSICS POST-MORTEM</span>
                  <div className="text-[10px] text-slate-400">INCIDENT DISCLOSURE LEDGER (SECURED / AUDITED)</div>
                </div>
              </div>
              <button 
                onClick={() => setShowForensicModal(false)}
                className="p-1 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-400 hover:text-slate-100 border border-slate-750 transition-colors cursor-pointer"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            <div className="p-6 flex flex-col gap-6 overflow-y-auto">
              
              {/* 1. Incident Metadata */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4 bg-slate-950 border border-slate-800 p-4 rounded-lg">
                <div className="flex flex-col gap-2">
                  <span className="text-slate-500 uppercase tracking-widest text-[9px]">Incident Identifiers</span>
                  <div className="font-bold text-slate-200">Incident ID: <span className="text-indigo-400">{forensicReport.incident_metadata.incident_id}</span></div>
                  <div>Timestamp: <span className="text-slate-300">{new Date(forensicReport.incident_metadata.timestamp).toLocaleString()}</span></div>
                  <div>Threat Level: <span className={`px-1.5 py-0.5 rounded font-extrabold text-[9px] ${
                    forensicReport.incident_metadata.threat_level.includes("CRITICAL") 
                      ? "bg-rose-950/60 text-rose-400 border border-rose-900 animate-pulse"
                      : forensicReport.incident_metadata.threat_level.includes("HIGH")
                        ? "bg-amber-950/60 text-amber-400 border border-amber-900"
                        : "bg-emerald-950/60 text-emerald-400 border border-emerald-900"
                  }`}>{forensicReport.incident_metadata.threat_level}</span></div>
                </div>

                <div className="flex flex-col gap-2 border-t md:border-t-0 md:border-l border-slate-800 pt-3 md:pt-0 md:pl-4 justify-between">
                  <div>
                    <span className="text-slate-500 uppercase tracking-widest text-[9px]">Ingested Data State</span>
                    <div className="text-slate-200 font-bold">Total Ingested Telemetry: <span className="text-sky-400 font-normal">{forensicReport.incident_metadata.total_logs} logs</span></div>
                  </div>
                  <div>
                    <span className="text-slate-500 uppercase tracking-widest text-[9px]">Active Containments</span>
                    <div className="text-slate-300">
                      {forensicReport.incident_metadata.active_isolated_nodes.length === 0 
                        ? "No active enclaves isolated."
                        : `Isolated: ${forensicReport.incident_metadata.active_isolated_nodes.join(", ")}`}
                    </div>
                  </div>
                </div>
              </div>

              {/* 2. MITRE ATT&CK Vectors */}
              <div className="flex flex-col gap-2">
                <div className="text-slate-400 font-bold uppercase tracking-wider border-b border-slate-800 pb-1.5 flex items-center gap-1.5">
                  <Shield className="h-4 w-4 text-indigo-400" />
                  <span>Identified Threat Vectors (MITRE Mappings)</span>
                </div>
                <div className="flex flex-col gap-3">
                  {forensicReport.threat_vectors.map((vector) => (
                    <div key={vector.id} className="p-3.5 bg-slate-950 border border-slate-800/80 rounded-lg flex flex-col gap-1.5">
                      <div className="flex items-center justify-between">
                        <span className="font-extrabold text-indigo-400">{vector.id}: {vector.name}</span>
                        <span className="text-[10px] bg-slate-905 border border-slate-850 px-2 py-0.5 rounded text-slate-400">
                          {vector.mapped_assets.length === 0 ? "Global System" : `Affected: ${vector.mapped_assets.join(", ")}`}
                        </span>
                      </div>
                      <p className="text-slate-400 text-[11px] leading-relaxed">{vector.description}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* 3. Containment Log */}
              <div className="flex flex-col gap-2">
                <div className="text-slate-400 font-bold uppercase tracking-wider border-b border-slate-800 pb-1.5 flex items-center gap-1.5">
                  <Terminal className="h-4 w-4 text-amber-500" />
                  <span>Mitigation & Terminal Containment Logs</span>
                </div>
                
                {forensicReport.mitigation_logs.length === 0 ? (
                  <div className="p-4 border border-dashed border-slate-800/80 rounded-lg text-slate-500 text-center uppercase tracking-wider animate-pulse">
                    No active mitigation logs recorded during this session.
                  </div>
                ) : (
                  <div className="flex flex-col gap-3.5">
                    {forensicReport.mitigation_logs.map((log, idx) => (
                      <div key={idx} className="bg-slate-950 border border-slate-800 rounded-lg overflow-hidden">
                        <div className="bg-slate-900 px-3.5 py-2 border-b border-slate-800 flex items-center justify-between">
                          <span className="font-bold text-amber-500 uppercase tracking-wide">CONTAINMENT SEQUENCE: {log.node_name}</span>
                          <span className="text-[9px] text-slate-500">{new Date(log.timestamp).toLocaleTimeString()}</span>
                        </div>
                        <div className="p-3 text-[10px] leading-relaxed text-slate-400">
                          <div className="mb-2"><span className="text-slate-500">Trigger Reason:</span> {log.reason}</div>
                          <div className="mb-2"><span className="text-slate-500">MITRE Tactic:</span> <span className="text-rose-400 font-bold bg-rose-950/40 px-1 rounded">{log.mitre_tactic}</span></div>
                          <div className="mt-2.5 font-mono text-[9px] bg-slate-900 border border-slate-850 p-2.5 rounded text-slate-300 max-h-[140px] overflow-y-auto whitespace-pre-wrap leading-normal">
                            {log.script_output}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* 4. Compliance Sign-off Block */}
              <div className="flex flex-col gap-2">
                <div className="text-slate-400 font-bold uppercase tracking-wider border-b border-slate-800 pb-1.5 flex items-center gap-1.5">
                  <FileText className="h-4 w-4 text-emerald-400" />
                  <span>SecOps Compliance Auditor Sign-Off</span>
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-1">
                  {/* Auditor */}
                  <div className={`p-4 bg-slate-950 border rounded-lg flex flex-col justify-between min-h-[150px] transition-all duration-300 ${
                    auditorSigned ? "border-emerald-500/50 shadow-lg shadow-emerald-950/10" : "border-slate-800 hover:border-slate-700"
                  }`}>
                    <div className="flex flex-col gap-1">
                      <span className="text-[10px] text-slate-500 font-bold tracking-widest uppercase">Lead SecOps Auditor</span>
                      {auditorSigned ? (
                        <div className="flex items-center gap-1.5 text-emerald-400 font-bold text-xs uppercase mt-2 animate-in fade-in duration-200">
                          <CheckCircle2 className="h-4 w-4" /> APPROVED & SIGNED
                        </div>
                      ) : (
                        <span className="text-amber-500 font-bold uppercase text-[10px] mt-2">PENDING AUDIT REVIEW</span>
                      )}
                    </div>
                    
                    {auditorSigned ? (
                      <div className="mt-4 pt-3 border-t border-slate-900 text-[10px] text-slate-400 flex flex-col gap-0.5">
                        <div>STAMP ID: <span className="text-slate-300 font-bold">AUD-{forensicReport.incident_metadata.incident_id.split("-")[2]}</span></div>
                        <div>SIGNED: <span className="text-slate-300 font-bold">{signatureAuditorTime}</span></div>
                      </div>
                    ) : (
                      <button 
                        onClick={() => {
                          setAuditorSigned(true);
                          setSignatureAuditorTime(new Date().toLocaleString());
                        }}
                        className="mt-4 w-full bg-emerald-600/10 hover:bg-emerald-600 text-emerald-400 hover:text-white border border-emerald-500/30 hover:border-emerald-400 py-1.5 rounded text-[10px] font-bold uppercase tracking-wider transition-all duration-250 cursor-pointer active:scale-[0.98]"
                      >
                        Digitally Sign Report
                      </button>
                    )}
                  </div>

                  {/* CISO */}
                  <div className={`p-4 bg-slate-950 border rounded-lg flex flex-col justify-between min-h-[150px] transition-all duration-300 ${
                    cisoSigned ? "border-emerald-500/50 shadow-lg shadow-emerald-950/10" : "border-slate-800 hover:border-slate-700"
                  }`}>
                    <div className="flex flex-col gap-1">
                      <span className="text-[10px] text-slate-500 font-bold tracking-widest uppercase">Chief Information Security Officer (CISO)</span>
                      {cisoSigned ? (
                        <div className="flex items-center gap-1.5 text-emerald-400 font-bold text-xs uppercase mt-2 animate-in fade-in duration-200">
                          <CheckCircle2 className="h-4 w-4" /> APPROVED & SIGNED
                        </div>
                      ) : (
                        <span className="text-amber-500 font-bold uppercase text-[10px] mt-2">PENDING MANAGEMENT SIGN-OFF</span>
                      )}
                    </div>
                    
                    {cisoSigned ? (
                      <div className="mt-4 pt-3 border-t border-slate-900 text-[10px] text-slate-400 flex flex-col gap-0.5">
                        <div>STAMP ID: <span className="text-slate-300 font-bold">CISO-{forensicReport.incident_metadata.incident_id.split("-")[2]}</span></div>
                        <div>SIGNED: <span className="text-slate-300 font-bold">{signatureCisoTime}</span></div>
                      </div>
                    ) : (
                      <button 
                        onClick={() => {
                          setCisoSigned(true);
                          setSignatureCisoTime(new Date().toLocaleString());
                        }}
                        className="mt-4 w-full bg-emerald-600/10 hover:bg-emerald-600 text-emerald-400 hover:text-white border border-emerald-500/30 hover:border-emerald-400 py-1.5 rounded text-[10px] font-bold uppercase tracking-wider transition-all duration-250 cursor-pointer active:scale-[0.98]"
                      >
                        Digitally Sign Report
                      </button>
                    )}
                  </div>
                </div>
              </div>
            </div>

            {/* Modal Footer */}
            <div className="border-t border-slate-800 p-5 bg-slate-900/50 flex items-center justify-between sticky bottom-0 backdrop-blur-sm z-10">
              <button 
                onClick={() => {
                  const reportCopy = { 
                    ...forensicReport,
                    compliance_sign_off: {
                      auditor_sign_off: {
                        ...forensicReport.compliance_sign_off.auditor_sign_off,
                        status: auditorSigned ? "APPROVED" : "PENDING",
                        signature: auditorSigned ? `AUD-${forensicReport.incident_metadata.incident_id.split("-")[2]}` : null,
                        timestamp: auditorSigned ? signatureAuditorTime : null
                      },
                      ciso_sign_off: {
                        ...forensicReport.compliance_sign_off.ciso_sign_off,
                        status: cisoSigned ? "APPROVED" : "PENDING",
                        signature: cisoSigned ? `CISO-${forensicReport.incident_metadata.incident_id.split("-")[2]}` : null,
                        timestamp: cisoSigned ? signatureCisoTime : null
                      }
                    }
                  };
                  const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(reportCopy, null, 2));
                  const downloadAnchor = document.createElement('a');
                  downloadAnchor.setAttribute("href", dataStr);
                  downloadAnchor.setAttribute("download", `aegisgrid_forensic_${forensicReport.incident_metadata.incident_id}.json`);
                  document.body.appendChild(downloadAnchor);
                  downloadAnchor.click();
                  downloadAnchor.remove();
                }}
                className="px-4 py-2 border border-slate-850 hover:border-slate-700 bg-slate-950 hover:bg-slate-900 text-slate-300 font-bold uppercase text-[10px] tracking-wider rounded-md transition-all cursor-pointer active:scale-[0.97]"
              >
                Export Forensic JSON Ledger
              </button>
              <button 
                onClick={() => setShowForensicModal(false)}
                className="px-4 py-2 bg-indigo-600 hover:bg-indigo-500 text-white font-bold uppercase text-[10px] tracking-wider rounded-md transition-all border border-indigo-400 cursor-pointer active:scale-[0.97]"
              >
                Close Ledger
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
