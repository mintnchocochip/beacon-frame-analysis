import pandas as pd
import numpy as np
import joblib
import time

class RogueAPInference:
    """
    Lightweight inference engine for rogue AP detection
    Optimized for minimal power consumption
    """
    
    def __init__(self, model_path='rogue_ap_model_dt.pkl'):
        """Load the trained model"""
        print(f"Loading model from {model_path}...")
        self.model_data = joblib.load(model_path)
        self.model = self.model_data['model']
        self.scaler = self.model_data['scaler']
        self.label_encoders = self.model_data['label_encoders']
        self.feature_names = self.model_data['feature_names']
        print("Model loaded successfully")
        
    def preprocess_beacon(self, beacon):
        """
        Preprocess a single beacon frame
        
        Args:
            beacon: dict with beacon frame data
        
        Returns:
            feature vector ready for inference
        """
        # Create DataFrame from single beacon
        df = pd.DataFrame([beacon])
        
        # Engineer features (same as training)
        features = df.copy()
        
        # SSID length
        features['SSID_Length'] = features['SSID'].fillna('').str.len()
        
        # BSSID locally administered
        features['BSSID_LocalAdmin'] = features['BSSID'].apply(
            lambda x: int(x.split(':')[0], 16) & 2 if pd.notna(x) else 0
        )
        
        # Timestamp ratio
        features['Timestamp_Ratio'] = features['BeaconTimestamp'] / (features['Timestamp_ms'] + 1)
        
        # Unusual channel
        features['UnusualChannel'] = features['Channel'].apply(
            lambda x: 0 if x in [1, 6, 11] else 1
        )
        
        # Empty SSID
        features['EmptySSID'] = (features['SSID'].isna() | (features['SSID'] == '')).astype(int)
        
        # Encode categorical features
        for col, le in self.label_encoders.items():
            if col in features.columns:
                try:
                    features[f'{col}_Encoded'] = le.transform(features[col].fillna('Unknown').astype(str))
                except ValueError:
                    # Handle unseen categories
                    features[f'{col}_Encoded'] = 0
        
        # Select final features
        X = features[self.feature_names].fillna(0)
        
        return X.values[0]
    
    def predict(self, beacon, return_proba=True):
        """
        Predict if beacon is from rogue AP
        
        Args:
            beacon: dict with beacon frame data
            return_proba: if True, return probability
        
        Returns:
            is_rogue: bool, True if rogue AP detected
            confidence: float, confidence score (0-1)
            inference_time: float, time taken in ms
        """
        start_time = time.time()
        
        # Preprocess
        X = self.preprocess_beacon(beacon)
        
        # Scale
        X_scaled = self.scaler.transform([X])
        
        # Predict
        prediction = self.model.predict(X_scaled)[0]
        
        if return_proba:
            proba = self.model.predict_proba(X_scaled)[0]
            confidence = proba[1] if prediction == 1 else proba[0]
        else:
            confidence = 1.0
        
        inference_time = (time.time() - start_time) * 1000  # ms
        
        is_rogue = bool(prediction)
        
        return is_rogue, confidence, inference_time
    
    def predict_batch(self, beacons):
        """
        Predict for multiple beacons (more efficient)
        
        Args:
            beacons: list of dict with beacon frame data
        
        Returns:
            results: list of (is_rogue, confidence, inference_time) tuples
        """
        start_time = time.time()
        
        # Preprocess all beacons
        X_list = [self.preprocess_beacon(b) for b in beacons]
        X = np.array(X_list)
        
        # Scale
        X_scaled = self.scaler.transform(X)
        
        # Predict
        predictions = self.model.predict(X_scaled)
        probabilities = self.model.predict_proba(X_scaled)
        
        total_time = (time.time() - start_time) * 1000
        avg_time = total_time / len(beacons)
        
        results = []
        for pred, proba in zip(predictions, probabilities):
            is_rogue = bool(pred)
            confidence = proba[1] if pred == 1 else proba[0]
            results.append((is_rogue, confidence, avg_time))
        
        return results


def demo_inference():
    """Demonstrate inference on sample data"""
    print("=" * 60)
    print("Rogue AP Detection - Inference Demo")
    print("=" * 60)
    
    # Load model
    detector = RogueAPInference('rogue_ap_model_dt.pkl')
    
    # Sample beacon frames (from your data)
    sample_beacons = [
        {
            'SSID': 'Satz',
            'BSSID': '10:27:F5:5C:C6:A3',
            'RSSI': -75,
            'Channel': 2,
            'SequenceNumber': 2089,
            'BeaconInterval': 100,
            'BeaconTimestamp': 803444326790,
            'Timestamp_ms': 1715,
            'Encryption': 'WPA2',
            'Privacy': 1,
            'ShortPreamble': 0,
            'ShortSlot': 1,
            'RateCount': 8,
            'ExtRateCount': 4,
            'HasHT': 1,
            'HTChannelWidth': 40,
            'HTStreams': 2,
            'HasExtCap': 1,
            'IsHidden': 0,
            'FrameLength': 254
        },
        {
            'SSID': '',
            'BSSID': 'FE:7A:58:1B:1B:9A',  # Locally administered
            'RSSI': -91,
            'Channel': 6,
            'SequenceNumber': 2849,
            'BeaconInterval': 100,
            'BeaconTimestamp': 543995906376,
            'Timestamp_ms': 9568,
            'Encryption': 'WEP',
            'Privacy': 1,
            'ShortPreamble': 0,
            'ShortSlot': 1,
            'RateCount': 0,
            'ExtRateCount': 0,
            'HasHT': 0,
            'HTChannelWidth': 0,
            'HTStreams': 0,
            'HasExtCap': 0,
            'IsHidden': 0,
            'FrameLength': 320
        }
    ]
    
    print("\nSingle Beacon Inference:")
    print("-" * 60)
    for i, beacon in enumerate(sample_beacons):
        is_rogue, confidence, inf_time = detector.predict(beacon)
        status = "ROGUE" if is_rogue else "LEGITIMATE"
        print(f"\nBeacon {i+1}: {beacon['SSID'] or '(Hidden)'}")
        print(f"  BSSID: {beacon['BSSID']}")
        print(f"  Status: {status}")
        print(f"  Confidence: {confidence:.2%}")
        print(f"  Inference Time: {inf_time:.3f} ms")
    
    print("\n" + "=" * 60)
    print("Batch Inference (More Efficient):")
    print("-" * 60)
    results = detector.predict_batch(sample_beacons)
    print(f"Processed {len(sample_beacons)} beacons")
    print(f"Average inference time: {results[0][2]:.3f} ms per beacon")
    print(f"Total power-efficient batch processing!")
    print("=" * 60)


if __name__ == '__main__':
    demo_inference()
