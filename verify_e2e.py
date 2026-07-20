import asyncio
import httpx
import websockets
import json
import sys

async def run_e2e_test():
    print("==================================================")
    print("     AEGISGRID PROGRAMMATIC E2E VERIFICATION      ")
    print("==================================================")
    
    ws_uri = "ws://localhost:8000/api/ws"
    sim_url = "http://localhost:8000/api/simulate-attack"
    
    print(f"[+] Connecting to active WebSocket endpoint: {ws_uri}")
    try:
        async with websockets.connect(ws_uri) as websocket:
            print("[+] WebSocket connection established successfully.")
          
            init_msg = await websocket.recv()
            init_data = json.loads(init_msg)
            print(f"[+] Received Initial State: {init_data['type']}")
            for node in init_data.get("nodes", []):
                print(f"    - Asset: {node['id']} Status: {node['status']}")
                
            print(f"\n[+] Triggering Ransomware Attack Scenario via REST API: {sim_url}")
            async with httpx.AsyncClient() as client:
                res = await client.post(sim_url, timeout=10.0)
                if res.status_code != 200:
                    print(f"[-] Failed: Attack simulation endpoint returned {res.status_code}")
                    return False
                sim_res = res.json()
                print(f"[+] REST Response Status: {sim_res['status']}")
                print(f"    ML Classification: {sim_res['classification']}")
                print(f"    Calculated Anomaly Score: {sim_res['score']:.6f}")
                
            print("\n[+] Awaiting WebSocket real-time events...")
            
            telemetry_received = False
            isolation_received = False
            
            for _ in range(5):  
                try:
                    msg = await asyncio.wait_for(websocket.recv(), timeout=3.0)
                    event = json.loads(msg)
                    print(f"\n[+] Intercepted WS Event: {event['type']}")
                    
                    if event["type"] == "TELEMETRY_LOG":
                        telemetry_received = True
                        print(f"    Raw Telemetry: {event['raw_log']}")
                        print(f"    Target Asset: {event['parsed']['source_asset']}")
                        print(f"    User Principal: {event['parsed']['user_principal']}")
                        print(f"    Anomaly Score: {event['parsed']['anomaly_score']:.6f}")
                        print(f"    State Classification: {event['parsed']['status']}")
                        
                    elif event["type"] == "NODE_ISOLATED":
                        isolation_received = True
                        print(f"    Isolated Node: {event['node_name']}")
                        print(f"    MITRE ATT&CK Tactic: {event['mitre_tactic']}")
                        print(f"    Trigger Reason: {event['reason']}")
                        print(f"    Mitigation Script Output:")
                        print("    " + "-"*40)
                        for line in event['script_output'].strip().split("\n"):
                            print(f"    {line}")
                        print("    " + "-"*40)
                        
                    elif event["type"] == "TOPOLOGY_UPDATE":
                        print("    Updated Topology State:")
                        for node in event.get("nodes", []):
                            print(f"      - Node: {node['id']} Status: {node['status']}")
                            
                except asyncio.TimeoutError:
                    break
                    
            if telemetry_received and isolation_received:
                print("\n==================================================")
              
                async with httpx.AsyncClient() as client:
                    res_topo = await client.get("http://localhost:8000/api/topology")
                topo_data = res_topo.json()
                db_core_status = next(n["status"] for n in topo_data["nodes"] if n["id"] == "DATABASE-CORE")
                
                print(f"[+] Post-Mitigation Check: DATABASE-CORE status = {db_core_status}")
                if db_core_status == "ISOLATED":
                    print("[+] VERIFICATION COMPLETED: E2E CYBER CONTAINMENT LOOP PASSED.")
                    print("==================================================")
                    return True
                else:
                    print("[-] Failed: DATABASE-CORE is not marked as isolated.")
                    return False
            else:
                print("[-] Failed: Did not receive both telemetry and isolation WebSocket events.")
                return False
                
    except Exception as e:
        print(f"[-] Connection or Test Error: {e}")
        return False

if __name__ == "__main__":
    success = asyncio.run(run_e2e_test())
    sys.exit(0 if success else 1)
