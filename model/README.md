# Rogue AP Detection - Model Training Guide

## Current Situation

Your dataset currently contains **ONLY legitimate beacon frames** (no rogue APs yet). This means:
- ❌ Supervised learning will overfit (100% accuracy on fake labels)
- ✅ Anomaly detection is the RIGHT approach for now

## Two Approaches Based on Your Data

### Option 1: Anomaly Detection (Use Now) ⭐ RECOMMENDED

**Use this when you only have legitimate data**

```bash
python train_anomaly_detector.py
```

**How it works:**
1. Learns what "normal" legitimate APs look like
2. Flags unusual patterns as potential rogues
3. No labels needed!

**Pros:**
- Works with your current dataset
- No overfitting
- Real-world applicable

**Cons:**
- Less accurate than supervised learning
- Will flag unusual legitimate APs too

---

### Option 2: Supervised Learning (Use After Data Collection)

**Only use after collecting REAL rogue AP beacons**

```bash
python train_model.py
```

**Requirements:**
1. Collect rogue AP beacons using `rogue_ap_generator`
2. Label your CSV files with `is_rogue` column (0 or 1)
3. Have both legitimate AND rogue samples

---

## Next Steps

### Step 1: Use Anomaly Detection Now
```bash
cd model
python train_anomaly_detector.py
python inference_anomaly.py
```

### Step 2: Generate Rogue AP Data

Use your `rogue_ap_generator` to create rogue APs:
```bash
cd ../rogue_ap_generator
# Run your ESP32 rogue AP generator
# Capture beacons from these rogue APs
```

### Step 3: Once You Have Rogue Data

1. Label your CSVs:
   ```python
   # Add column to legitimate beacons
   df['is_rogue'] = 0
   
   # Add column to rogue beacons  
   df['is_rogue'] = 1
   ```

2. Retrain with supervised learning:
   ```bash
   python train_model.py
   ```

---

## Why Your Current Model Overfits

The current `train_model.py` uses **heuristic labels**:
- Hidden SSID + WEP = labeled as rogue
- Locally administered BSSID = labeled as rogue
- RSSI < -90 = labeled as rogue

**Problem:** These heuristics don't match real rogue APs, causing:
- 100% accuracy (too good to be true!)
- Wrong predictions on real data
- Model memorizes patterns instead of learning

---

## Comparison

| Feature | Anomaly Detection | Supervised Learning |
|---------|------------------|---------------------|
| **Data Needed** | Legitimate only | Legitimate + Rogue |
| **Accuracy** | 70-85% | 90-98% |
| **Overfitting Risk** | Low | High (if data limited) |
| **Use Case** | Detection | Classification |
| **Inference Speed** | Fast (~5ms) | Faster (~2ms) |

---

## Files

- `train_anomaly_detector.py` ⭐ Use this now
- `inference_anomaly.py` - Inference for anomaly detection
- `train_model.py` - Use after collecting rogue data
- `inference.py` - Inference for supervised model

---

## Important Notes

⚠️ **Anomaly detection will flag:**
- Real rogue APs ✅
- Unusual legitimate APs ⚠️ (false positives)
- Data quality issues ⚠️

💡 **To reduce false positives:**
1. Ensure your legitimate data is clean
2. Adjust `contamination` parameter (currently 0.05 = 5%)
3. Set threshold on anomaly score
4. Eventually move to supervised learning

---

## Power Consumption

Both approaches are optimized for low power:
- Isolation Forest: ~5-10ms inference
- Decision Tree: ~1-2ms inference (after you have rogue data)

The anomaly detector is slightly slower but still very efficient for embedded systems.
