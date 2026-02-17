import pandas as pd
import numpy as np
import joblib

class AnomalyInference:
    """Inference engine for anomaly-based rogue AP detection"""
    
    def __init__(self, model_path='rogue_ap_anomaly_detector.pkl'):
        """Load the trained anomaly detector"""
        print(f"Loading anomaly detector from {model_path}...")
        model_data = joblib.load(model_path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        print("Model loaded successfully")
        
    def preprocess_beacon(self, beacon):
        """Preprocess a single beacon frame"""
        df = pd.DataFrame([beacon])
        
        # Engineer features
        features = df.copy()
        features['SSID_Length'] = features['SSID'].fillna('').str.len()
        features['BSSID_LocalAdmin'] = features['BSSID'].apply(
            lambda x: int(x.split(':')[0], 16) & 2 if pd.notna(x) else 0
        )
        features['UnusualChannel'] = features['Channel'].apply(
            lambda x: 0 if x in [1, 6, 11] else 1
        )
        features['EmptySSID'] = (features['SSID'].isna() | (features['SSID'] == '')).astype(int)
        features['IsWEP'] = (features['Encryption'] == 'WEP').astype(int)
        
        X = features[self.feature_names].fillna(0)
        return X.values[0]
    
    def predict(self, beacon):
        """
        Predict if beacon is anomalous (potential rogue)
        
        Returns:
            is_anomalous: True if flagged as anomaly
            anomaly_score: Lower = more anomalous (negative values)
        """
        X = self.preprocess_beacon(beacon)
        X_scaled = self.scaler.transform([X])
        
        # -1 = anomaly, 1 = normal
        prediction = self.model.predict(X_scaled)[0]
        score = self.model.decision_function(X_scaled)[0]
        
        is_anomalous = (prediction == -1)
        
        return is_anomalous, score


if __name__ == '__main__':
    # Demo with sample beacons
    detector = AnomalyInference()
    
    # Normal beacon
    normal = {
        'SSID': 'Satz',
        'BSSID': '10:27:F5:5C:C6:A3',
        'RSSI': -75,
        'Channel': 6,
        'BeaconInterval': 100,
        'RateCount': 8,
        'ExtRateCount': 4,
        'Encryption': 'WPA2',
        'Privacy': 1,
        'ShortPreamble': 0,
        'ShortSlot': 1,
        'HasHT': 1,
        'HTStreams': 2,
        'HasExtCap': 1,
        'IsHidden': 0,
        'FrameLength': 254
    }
    
    # Suspicious beacon
    suspicious = {
        'SSID': '',
        'BSSID': 'FE:7A:58:1B:1B:9A',  # Locally administered
        'RSSI': -91,
        'Channel': 13,  # Unusual
        'BeaconInterval': 100,
        'RateCount': 0,
        'ExtRateCount': 0,
        'Encryption': 'WEP',  # Outdated
        'Privacy': 1,
        'ShortPreamble': 0,
        'ShortSlot': 1,
        'HasHT': 0,
        'HTStreams': 0,
        'HasExtCap': 0,
        'IsHidden': 0,
        'FrameLength': 320
    }
    
    print("\nTesting anomaly detection:")
    print("-" * 60)
    
    for name, beacon in [('Normal', normal), ('Suspicious', suspicious)]:
        is_anom, score = detector.predict(beacon)
        status = "ANOMALY" if is_anom else "NORMAL"
        print(f"\n{name} beacon: {beacon['SSID'] or '(Hidden)'}")
        print(f"  Status: {status}")
        print(f"  Anomaly Score: {score:.4f} (lower = more anomalous)")
