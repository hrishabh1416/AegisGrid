import re
import datetime
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
LOG_REGEX = r"(\S+) \[([^\]]+)\] (\S+) (\d+) (\S+)"

ASSETS_MAP = {
    "GATEWAY-01": 0,
    "ADMIN-GATEWAY": 1,
    "BILLING-SRV": 2,
    "DATABASE-CORE": 3
}
DEFAULT_ASSET_VAL = 4

USERS_MAP = {
    "admin_svc": 0,
    "billing_svc": 1,
    "user_alpha": 2,
    "backup_agent": 3
}
DEFAULT_USER_VAL = 4

class AegisMLPipeline:
    def __init__(self):
        self.model = IsolationForest(contamination=0.015, random_state=42)
        self.trained = False
        self._pretrain_baseline()

    def _pretrain_baseline(self):
        """Generates synthetic normal telemetry baseline data and fits the model."""
        np.random.seed(42)
        num_samples = 1000
        
        hours = np.random.randint(8, 18, size=num_samples) 
        days = np.random.randint(0, 5, size=num_samples)     
        assets = []
        users = []
        bytes_transferred = []
        
        for i in range(num_samples):
            rand_choice = np.random.rand()
            if rand_choice < 0.3:
                assets.append("GATEWAY-01")
                users.append("user_alpha")
                bytes_transferred.append(np.random.uniform(5000, 1000000))  
            elif rand_choice < 0.6:
                assets.append("DATABASE-CORE")
                users.append("billing_svc")
                bytes_transferred.append(np.random.uniform(10000, 5000000)) 
            elif rand_choice < 0.8:
                assets.append("BILLING-SRV")
                users.append("billing_svc")
                bytes_transferred.append(np.random.uniform(2000, 2000000))
            else:
                assets.append("ADMIN-GATEWAY")
                users.append("admin_svc")
                bytes_transferred.append(np.random.uniform(10000, 10000000)) 
                
        df_normal = pd.DataFrame({
            "hour": hours,
            "day": days,
            "asset_encoded": [ASSETS_MAP[a] for a in assets],
            "user_encoded": [USERS_MAP[u] for u in users],
            "bytes_log": np.log1p(bytes_transferred)
        })
        
        anom_hours = np.random.randint(0, 6, size=15)
        anom_days = np.random.randint(0, 7, size=15)
        anom_assets = np.random.randint(0, 4, size=15)
        anom_users = np.random.randint(0, 4, size=15)
        anom_bytes = np.log1p(np.random.uniform(100000000, 10000000000, size=15)) 
        
        df_anom = pd.DataFrame({
            "hour": anom_hours,
            "day": anom_days,
            "asset_encoded": anom_assets,
            "user_encoded": anom_users,
            "bytes_log": anom_bytes
        })
        
        df_train = pd.concat([df_normal, df_anom], ignore_index=True)
        
        self.model.fit(df_train)
        self.trained = True
        print(f"ML Pipeline: IsolationForest trained successfully on {len(df_train)} events (including 15 outlier anomalies).")

    def parse_log(self, log_line: str):
        """Parses a log line and extracts metadata."""
        match = re.search(LOG_REGEX, log_line.strip())
        if not match:
            return None
        
        timestamp_str, source_asset, user_principal, bytes_str, status = match.groups()
        try:
            timestamp = datetime.datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
        except ValueError:
            timestamp = datetime.datetime.now(datetime.timezone.utc)
            
        try:
            bytes_transferred = int(bytes_str)
        except ValueError:
            bytes_transferred = 0
            
        return {
            "timestamp": timestamp,
            "source_asset": source_asset,
            "user_principal": user_principal,
            "bytes_transferred": bytes_transferred,
            "status": status
        }

    def evaluate(self, parsed_log: dict):
        """Runs the log features through IsolationForest and determines anomaly status."""
        if not self.trained:
            raise ValueError("Model is not trained.")
            
        dt = parsed_log["timestamp"]
        hour = dt.hour
        day = dt.weekday()
        
        asset_encoded = ASSETS_MAP.get(parsed_log["source_asset"], DEFAULT_ASSET_VAL)
        user_encoded = USERS_MAP.get(parsed_log["user_principal"], DEFAULT_USER_VAL)
        bytes_log = np.log1p(parsed_log["bytes_transferred"])
        
        features = pd.DataFrame([{
            "hour": hour,
            "day": day,
            "asset_encoded": asset_encoded,
            "user_encoded": user_encoded,
            "bytes_log": bytes_log
        }])
        prediction = self.model.predict(features)[0]
        raw_score = float(self.model.decision_function(features)[0])
        is_anomaly = (prediction == -1) or (raw_score < -0.02)
        status = "CRITICAL_ANOMALY" if is_anomaly else "SECURE"
        
        return raw_score, status
