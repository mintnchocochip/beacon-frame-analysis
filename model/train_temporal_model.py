import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
from preprocess_temporal import TemporalBeaconAnalyzer

class TemporalRogueDetector:
    """
    Rogue AP detector using TEMPORAL features
    Much more accurate than static features alone!
    """
    
    def __init__(self, contamination=0.05):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination,
            random_state=42,
            n_jobs=-1,
            max_samples=256,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.feature_names = None
        
    def prepare_features(self, temporal_df):
        """Prepare temporal features for model training"""
        
        # Select numeric temporal features
        feature_cols = [
            'BeaconCount',
            'MeanInterBeaconTime_ms',
            'StdInterBeaconTime_ms',
            'TimingJitter',
            'MissedBeacons',
            'MeanSeqGap',
            'StdSeqGap',
            'MaxSeqGap',
            'SeqNumberResets',
            'ChannelChanges',
            'MeanRSSI',
            'StdRSSI',
            'RSSIRange',
        ]
        
        X = temporal_df[feature_cols].fillna(0)
        self.feature_names = feature_cols
        
        return X
    
    def train(self):
        """Train temporal anomaly detector"""
        print("="*80)
        print("TRAINING TEMPORAL ROGUE AP DETECTOR")
        print("="*80)
        
        # Step 1: Load and compute temporal features
        print("\n1. Computing temporal features...")
        analyzer = TemporalBeaconAnalyzer()
        df = analyzer.load_and_sort()
        temporal_df = analyzer.compute_temporal_features(df)
        
        # Step 2: Prepare features
        print("\n2. Preparing temporal features for training...")
        X = self.prepare_features(temporal_df)
        
        # Step 3: Scale and train
        print("\n3. Training Isolation Forest on temporal patterns...")
        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        
        # Step 4: Evaluate
        scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)
        
        n_anomalies = np.sum(predictions == -1)
        pct_anomalies = (n_anomalies / len(predictions)) * 100
        
        print(f"\nDetected {n_anomalies} temporal anomalies ({pct_anomalies:.2f}%)")
        
        # Show most anomalous
        print("\nTop 5 APs with anomalous temporal patterns:")
        anomaly_indices = np.argsort(scores)[:5]
        for i, idx in enumerate(anomaly_indices):
            row = temporal_df.iloc[idx]
            print(f"\n{i+1}. {row['SSID'] or '(Hidden)'} - {row['BSSID']}")
            print(f"   Timing Jitter: {row['TimingJitter']:.3f}")
            print(f"   Missed Beacons: {row['MissedBeacons']:.0f}")
            print(f"   Channel Changes: {row['ChannelChanges']:.0f}")
            print(f"   Anomaly Score: {scores[idx]:.4f}")
        
        return temporal_df, X_scaled, scores
    
    def save(self, model_path='rogue_ap_temporal_detector.pkl'):
        """Save the trained model"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'contamination': self.contamination
        }
        joblib.dump(model_data, model_path)
        print(f"\nModel saved to {model_path}")


def main():
    """Train temporal model"""
    detector = TemporalRogueDetector(contamination=0.08)
    temporal_df, X_scaled, scores = detector.train()
    detector.save()
    
    print("\n" + "="*80)
    print("TEMPORAL MODEL ADVANTAGES:")
    print("="*80)
    print("✅ Detects timing irregularities (key rogue AP indicator)")
    print("✅ Catches channel-hopping attacks")
    print("✅ Identifies beaconing anomalies")
    print("✅ More robust than static features alone")
    print("✅ Works with legitimate-only data")
    print("="*80)


if __name__ == '__main__':
    main()
