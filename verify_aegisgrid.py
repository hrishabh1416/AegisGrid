import sys
import os
import datetime

sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend"))

try:
    from ml_core import AegisMLPipeline
except ImportError as e:
    print(f"Error importing ml_core: {e}")
    sys.exit(1)

def run_tests():
    print("==================================================")
    print("      AEGISGRID RESILIENCE PIPELINE TEST SUITE    ")
    print("==================================================")
    
    print("\n[+] Initializing AegisMLPipeline and loading baseline training models...")
    pipeline = AegisMLPipeline()
    print("[+] Model loaded successfully.")

    now = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    
    normal_log = f"{now} [GATEWAY-01] user_alpha 245000 SUCCESS"
    
    anomaly_time = datetime.datetime.combine(datetime.date.today(), datetime.time(3, 15, 0)).isoformat() + "Z"
    anomalous_log = f"{anomaly_time} [DATABASE-CORE] backup_agent 5800000000 SUCCESS"
    
    invalid_log = "Invalid log entry that does not conform to system patterns."

    print("\n--- TEST CASE 1: Baseline Telemetry Log Ingestion ---")
    print(f"Raw Input: '{normal_log}'")
    parsed_1 = pipeline.parse_log(normal_log)
    if not parsed_1:
        print("[-] Failed: Normal log parse error.")
        return False
    print(f"Parsed Fields: {parsed_1}")
    score_1, status_1 = pipeline.evaluate(parsed_1)
    print(f"Decision Score: {score_1:.6f}")
    print(f"Classification: {status_1}")
    if status_1 != "SECURE":
        print("[-] Failed: Normal log classified as anomaly.")
        return False
    print("[+] Test Case 1 Passed.")

    print("\n--- TEST CASE 2: Ransomware Anomaly Log Ingestion ---")
    print(f"Raw Input: '{anomalous_log}'")
    parsed_2 = pipeline.parse_log(anomalous_log)
    if not parsed_2:
        print("[-] Failed: Anomalous log parse error.")
        return False
    print(f"Parsed Fields: {parsed_2}")
    score_2, status_2 = pipeline.evaluate(parsed_2)
    print(f"Decision Score: {score_2:.6f}")
    print(f"Classification: {status_2}")
    if status_2 != "CRITICAL_ANOMALY":
        print("[-] Failed: Anomalous ransomware log was not flagged as anomaly.")
        return False
    print("[+] Test Case 2 Passed.")

    print("\n--- TEST CASE 3: Invalid Log Input Validation ---")
    print(f"Raw Input: '{invalid_log}'")
    parsed_3 = pipeline.parse_log(invalid_log)
    if parsed_3 is not None:
        print("[-] Failed: Invalid log pattern was parsed successfully.")
        return False
    print("[+] Invalid log pattern rejected successfully.")
    print("[+] Test Case 3 Passed.")

    print("\n==================================================")
    print("          ALL VERIFICATION TESTS COMPLETED         ")
    print("                    STATUS: PASSED                ")
    print("==================================================")
    return True

if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
