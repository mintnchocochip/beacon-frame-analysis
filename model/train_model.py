import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
import joblib
import os
import glob

class RogueAPDetector:
    """
    Lightweight Rogue AP Detector using Random Forest
    Optimized for minimal power consumption during inference
    """
    
    def __init__(self, model_type='random_forest', max_depth=10, n_estimators=50):
        """
        Initialize the detector
        
        Args:
            model_type: 'random_forest' or 'decision_tree' (decision_tree is lighter)
            max_depth: Maximum depth of trees (lower = faster inference)
            n_estimators: Number of trees for RF (lower = faster inference)
        """
        self.model_type = model_type
        self.max_depth = max_depth
        self.n_estimators = n_estimators
        
        if model_type == 'decision_tree':
            self.model = DecisionTreeClassifier(max_depth=max_depth, random_state=42)
        else:
            self.model = RandomForestClassifier(
                n_estimators=n_estimators,
                max_depth=max_depth,
                random_state=42,
                n_jobs=-1
            )
        
        self.scaler = StandardScaler()
        self.label_encoders = {}
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
        
        if not dfs:
            raise ValueError("No valid CSV files could be loaded")
        
        data = pd.concat(dfs, ignore_index=True)
        print(f"Loaded {len(data)} beacon frames")
        return data
    
    def engineer_features(self, df):
        """
        Engineer features for rogue AP detection
        Focus on features that are lightweight to compute
        """
        features = df.copy()
        
        # Numeric features (already available)
        numeric_features = ['RSSI', 'Channel', 'SequenceNumber', 'BeaconInterval', 
                           'RateCount', 'ExtRateCount', 'FrameLength']
        
        # Binary features
        binary_features = ['Privacy', 'ShortPreamble', 'ShortSlot', 'HasHT', 
                          'HTStreams', 'HasExtCap', 'IsHidden']
        
        # Categorical features that need encoding
        categorical_features = ['Encryption', 'HTChannelWidth']
        
        # Feature: SSID length (measure of suspicious names)
        features['SSID_Length'] = features['SSID'].fillna('').str.len()
        
        # Feature: BSSID is locally administered (potential spoofing)
        features['BSSID_LocalAdmin'] = features['BSSID'].apply(
            lambda x: int(x.split(':')[0], 16) & 2 if pd.notna(x) else 0
        )
        
        # Feature: Beacon timestamp variance (irregular beaconing)
        features['Timestamp_Ratio'] = features['BeaconTimestamp'] / (features['Timestamp_ms'] + 1)
        
        # Feature: Unusual channel (outside common 1, 6, 11)
        features['UnusualChannel'] = features['Channel'].apply(
            lambda x: 0 if x in [1, 6, 11] else 1
        )
        
        # Feature: Empty or hidden SSID
        features['EmptySSID'] = (features['SSID'].isna() | (features['SSID'] == '')).astype(int)
        
        # Encode categorical features
        for col in categorical_features:
            if col in features.columns:
                le = LabelEncoder()
                features[f'{col}_Encoded'] = le.fit_transform(features[col].fillna('Unknown').astype(str))
                self.label_encoders[col] = le
        
        # Select final features (lightweight set)
        final_features = (
            numeric_features + 
            binary_features + 
            ['SSID_Length', 'BSSID_LocalAdmin', 'Timestamp_Ratio', 
             'UnusualChannel', 'EmptySSID'] +
            [f'{col}_Encoded' for col in categorical_features if col in features.columns]
        )
        
        # Fill missing values
        X = features[final_features].fillna(0)
        self.feature_names = final_features
        
        return X
    
    def create_labels(self, df):
        """
        Create labels for rogue AP detection
        
        Note: This is a placeholder. In real scenarios, you need labeled data.
        Here we use heuristics to create pseudo-labels for demonstration.
        """
        # Heuristic-based labeling (REPLACE WITH ACTUAL LABELS)
        # This is just for demonstration purposes
        
        labels = np.zeros(len(df))
        
        # Mark as rogue if:
        # 1. Hidden SSID with weak encryption
        # 2. Locally administered BSSID (potential spoofing)
        # 3. Very weak RSSI (potential evil twin far away)
        # 4. WEP encryption (outdated, suspicious)
        
        hidden_weak = (df['IsHidden'] == 1) & (df['Encryption'].isin(['WEP', 'Open']))
        local_admin = df['BSSID'].apply(lambda x: int(x.split(':')[0], 16) & 2 if pd.notna(x) else 0)
        weak_rssi = df['RSSI'] < -90
        wep_encryption = df['Encryption'] == 'WEP'
        
        labels[(hidden_weak | (local_admin > 0) | weak_rssi | wep_encryption)] = 1
        
        print(f"Created labels: {np.sum(labels == 1)} rogue, {np.sum(labels == 0)} legitimate")
        print("Note: These are heuristic-based labels. Replace with actual labeled data for production.")
        
        return labels
    
    def train(self, dataset_dir='../dataset', test_size=0.2):
        """Train the model"""
        # Load data
        df = self.load_dataset(dataset_dir)
        
        # Engineer features
        X = self.engineer_features(df)
        y = self.create_labels(df)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Train model
        print(f"\nTraining {self.model_type} model...")
        self.model.fit(X_train_scaled, y_train)
        
        # Evaluate
        train_acc = self.model.score(X_train_scaled, y_train)
        test_acc = self.model.score(X_test_scaled, y_test)
        
        print(f"Training Accuracy: {train_acc:.4f}")
        print(f"Test Accuracy: {test_acc:.4f}")
        
        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
            feature_importance = sorted(
                zip(self.feature_names, importances),
                key=lambda x: x[1],
                reverse=True
            )
            print("\nTop 10 Important Features:")
            for feat, imp in feature_importance[:10]:
                print(f"  {feat}: {imp:.4f}")
        
        return train_acc, test_acc
    
    def save(self, model_path='rogue_ap_detector.pkl'):
        """Save the trained model"""
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoders': self.label_encoders,
            'feature_names': self.feature_names,
            'model_type': self.model_type,
            'max_depth': self.max_depth,
            'n_estimators': self.n_estimators
        }
        joblib.dump(model_data, model_path)
        print(f"\nModel saved to {model_path}")
        
        # Print model size
        size_mb = os.path.getsize(model_path) / (1024 * 1024)
        print(f"Model size: {size_mb:.2f} MB")
    
    def load(self, model_path='rogue_ap_detector.pkl'):
        """Load a trained model"""
        model_data = joblib.load(model_path)
        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.label_encoders = model_data['label_encoders']
        self.feature_names = model_data['feature_names']
        self.model_type = model_data['model_type']
        self.max_depth = model_data['max_depth']
        self.n_estimators = model_data.get('n_estimators', 50)
        print(f"Model loaded from {model_path}")
    
    def predict(self, beacon_data):
        """
        Predict if a beacon frame is from a rogue AP
        
        Args:
            beacon_data: DataFrame or dict with beacon frame features
        
        Returns:
            prediction: 0 (legitimate) or 1 (rogue)
            probability: probability of being rogue
        """
        if isinstance(beacon_data, dict):
            beacon_data = pd.DataFrame([beacon_data])
        
        X = self.engineer_features(beacon_data)
        X_scaled = self.scaler.transform(X)
        
        prediction = self.model.predict(X_scaled)[0]
        probability = self.model.predict_proba(X_scaled)[0][1]
        
        return prediction, probability


def main():
    """Main training script"""
    print("=" * 60)
    print("Rogue AP Detection Model Training")
    print("Optimized for Low Power Consumption")
    print("=" * 60)
    
    # Option 1: Decision Tree (Fastest inference, lowest power)
    print("\n--- Training Decision Tree Model ---")
    dt_detector = RogueAPDetector(model_type='decision_tree', max_depth=8)
    dt_train_acc, dt_test_acc = dt_detector.train()
    dt_detector.save('rogue_ap_model_dt.pkl')
    
    # Option 2: Random Forest (Better accuracy, slightly higher power)
    print("\n--- Training Random Forest Model ---")
    rf_detector = RogueAPDetector(model_type='random_forest', max_depth=8, n_estimators=20)
    rf_train_acc, rf_test_acc = rf_detector.train()
    rf_detector.save('rogue_ap_model_rf.pkl')
    
    print("\n" + "=" * 60)
    print("Training Complete!")
    print(f"Decision Tree - Test Accuracy: {dt_test_acc:.4f}")
    print(f"Random Forest - Test Accuracy: {rf_test_acc:.4f}")
    print("\nRecommendation: Use Decision Tree for minimal power consumption")
    print("=" * 60)


if __name__ == '__main__':
    main()
