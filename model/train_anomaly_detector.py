import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import os
import glob

class AnomalyBasedRogueDetector:
    """
    Anomaly detection for rogue AP detection
    Use this when you only have LEGITIMATE beacon frames
    
    This learns what "normal" looks like, then flags anomalies as potential rogues
    """
    
    def __init__(self, contamination=0.1):
        """
        Initialize anomaly detector
        
        Args:
            contamination: Expected proportion of anomalies (0.1 = 10% of data)
        """
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
            max_samples=256,  # Low for faster inference
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.feature_names = None
        
    def load_dataset(self, dataset_dir='../dataset'):
        """Load all CSV files from the dataset directory"""
        csv_files = []
        for session_dir in glob.glob(os.path.join(dataset_dir, 'session_*')):
            csv_files.extend(glob.glob(os.path.join(session_dir, '*.csv')))
        
        if not csv_files:
            raise ValueError(f"No CSV files found in {dataset_dir}")
        
        print(f"Loading {len(csv_files)} CSV files...")
        dfs = []
        for file in csv_files:
            try:
                df = pd.read_csv(file)
                dfs.append(df)
            except Exception as e:
                print(f"Error loading {file}: {e}")
        
        data = pd.concat(dfs, ignore_index=True)
        print(f"Loaded {len(data)} beacon frames (assumed LEGITIMATE)")
        return data
    
    def engineer_features(self, df):
        """Engineer features for anomaly detection"""
        features = df.copy()
        
        # Numeric features
        numeric_features = ['RSSI', 'Channel', 'BeaconInterval', 
                           'RateCount', 'ExtRateCount', 'FrameLength']
        
        # Binary features
        binary_features = ['Privacy', 'ShortPreamble', 'ShortSlot', 
                          'HasHT', 'HTStreams', 'HasExtCap', 'IsHidden']
        
        # Engineered features
        features['SSID_Length'] = features['SSID'].fillna('').str.len()
        features['BSSID_LocalAdmin'] = features['BSSID'].apply(
            lambda x: int(x.split(':')[0], 16) & 2 if pd.notna(x) else 0
        )
        features['UnusualChannel'] = features['Channel'].apply(
            lambda x: 0 if x in [1, 6, 11] else 1
        )
        features['EmptySSID'] = (features['SSID'].isna() | (features['SSID'] == '')).astype(int)
        
        # WEP encryption flag (suspicious)
        features['IsWEP'] = (features['Encryption'] == 'WEP').astype(int)
        
        final_features = (
            numeric_features + 
            binary_features + 
            ['SSID_Length', 'BSSID_LocalAdmin', 'UnusualChannel', 'EmptySSID', 'IsWEP']
        )
        
        X = features[final_features].fillna(0)
        self.feature_names = final_features
        
        return X
    
    def train(self, dataset_dir='../dataset'):
        """Train anomaly detector on LEGITIMATE data only"""
        print("=" * 60)
        print("Training Anomaly-Based Rogue AP Detector")
        print("=" * 60)
        print("\nIMPORTANT: This assumes your dataset contains ONLY legitimate APs")
        print("The model will learn normal patterns and flag deviations as anomalies\n")
        
        # Load data
        df = self.load_dataset(dataset_dir)
        
        # Engineer features
        X = self.engineer_features(df)
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Train model (no labels needed!)
        print("Training Isolation Forest...")
        self.model.fit(X_scaled)
        
        # Get anomaly scores for validation
        scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        
        n_anomalies = np.sum(predictions == -1)
        pct_anomalies = (n_anomalies / len(predictions)) * 100
        
        print(f"\nTraining complete!")
        print(f"Detected {n_anomalies} anomalies ({pct_anomalies:.2f}%) in training data")
        print(f"These might be unusual legitimate APs or data quality issues")
        
        # Show some anomalies for inspection
        print("\nTop 5 anomalies detected (lowest scores = most anomalous):")
        anomaly_indices = np.argsort(scores)[:5]
        for i, idx in enumerate(anomaly_indices):
            print(f"\n{i+1}. SSID: {df.iloc[idx]['SSID'] or '(Hidden)'}")
            print(f"   BSSID: {df.iloc[idx]['BSSID']}")
            print(f"   RSSI: {df.iloc[idx]['RSSI']}, Channel: {df.iloc[idx]['Channel']}")
            print(f"   Encryption: {df.iloc[idx]['Encryption']}")
            print(f"   Anomaly Score: {scores[idx]:.4f}")
        
        return X_scaled, scores
    
    def save(self, model_path='rogue_ap_anomaly_detector.pkl'):
        """Save the trained model"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'contamination': self.contamination
        }
        joblib.dump(model_data, model_path)
        print(f"\nModel saved to {model_path}")
        
        size_mb = os.path.getsize(model_path) / (1024 * 1024)
        print(f"Model size: {size_mb:.2f} MB")
    
    def load(self, model_path='rogue_ap_anomaly_detector.pkl'):
        """Load a trained model"""
        model_data = joblib.load(model_path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.contamination = model_data['contamination']
        print(f"Model loaded from {model_path}")


def main():
    """Main training script for anomaly detection"""
    print("\n" + "=" * 60)
    print("ANOMALY DETECTION APPROACH")
    print("=" * 60)
    print("\nThis is the RIGHT approach when you only have legitimate data!")
    print("Steps:")
    print("1. Train on your legitimate beacon frames")
    print("2. Model learns 'normal' patterns")
    print("3. Later, unusual/rogue APs will be flagged as anomalies")
    print("\nNote: You still need to collect REAL rogue AP data eventually")
    print("for supervised training and validation!")
    print("=" * 60)
    
    # Train anomaly detector
    detector = AnomalyBasedRogueDetector(contamination=0.05)  # Expect 5% anomalies
    detector.train()
    detector.save()
    
    print("\n" + "=" * 60)
    print("Next Steps:")
    print("1. Use the rogue_ap_generator to create rogue AP beacons")
    print("2. Collect beacons from the simulated rogue APs")
    print("3. Test this anomaly detector on rogue data")
    print("4. Once you have labeled data, retrain with supervised learning")
    print("=" * 60)


if __name__ == '__main__':
    main()
