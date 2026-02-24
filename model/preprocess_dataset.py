"""
Rogue AP Dataset Preprocessor
================================
Reads all beacon frame CSVs from the dataset/ folder recursively,
generates synthetic rogue AP variants, labels everything with is_rogue,
and saves a balanced, clean processed CSV for model training.

Rogue AP Types Simulated:
  1. Evil Twin       - Same SSID, slightly modified BSSID (same OUI prefix)
  2. OUI Spoof       - Same SSID, completely different/random BSSID OUI
  3. Security Downgrade - WEP / Open encryption clone of a WPA2 AP
  4. Hidden SSID     - Legitimate AP with SSID blanked out (IsHidden=1)
  5. TSF Reset       - Same SSID/BSSID but BeaconTimestamp reset to near-zero
  6. Channel Shift   - AP suddenly broadcast on a different channel
  7. Local Admin BSSID - Locally administered MAC (bit 1 of first octet set)

Output: dataset/processed/rogue_processed.csv
"""

import os
import glob
import random
import pandas as pd
import numpy as np

# ── Config ──────────────────────────────────────────────────────────────────
DATASET_DIR   = os.path.join(os.path.dirname(__file__), '..', 'dataset')
OUTPUT_DIR    = os.path.join(DATASET_DIR, 'processed')
OUTPUT_FILE   = os.path.join(OUTPUT_DIR, 'rogue_processed.csv')
RANDOM_SEED   = 42

# How many rogue rows to generate per type (as fraction of legit count)
ROGUE_FRACTION_PER_TYPE = 0.18   # 7 types × 0.18 ≈ 1.26× legit → ~56% rogue

np.random.seed(RANDOM_SEED)
random.seed(RANDOM_SEED)

# ── Helpers ──────────────────────────────────────────────────────────────────

def random_oui() -> str:
    """Return a random OUI (3 hex octets)."""
    octs = [random.randint(0, 255) for _ in range(3)]
    return ':'.join(f'{o:02X}' for o in octs)


def local_admin_bssid(bssid: str) -> str:
    """Flip the locally-administered bit (bit 1) in the first octet."""
    parts = bssid.split(':')
    first = int(parts[0], 16) | 0x02          # set bit 1
    parts[0] = f'{first:02X}'
    return ':'.join(parts)


def spoof_bssid_last_octet(bssid: str) -> str:
    """Keep OUI, randomise last octet (simple evil-twin spoof)."""
    parts = bssid.split(':')
    parts[-1] = f'{random.randint(0, 255):02X}'
    return ':'.join(parts)


def full_spoof_bssid(bssid: str) -> str:
    """Replace OUI entirely; keep NIC-specific part."""
    parts   = bssid.split(':')
    new_oui = random_oui().split(':')
    return ':'.join(new_oui + parts[3:])


def reset_tsf(row: pd.Series) -> float:
    """Return a low TSF value (< 10 seconds of uptime in microseconds)."""
    return float(np.random.randint(100_000, 9_999_999))


def jitter_seq(seq: int) -> int:
    """Return a severely jumped sequence number (rogue restart indicator)."""
    jump = random.choice([-500, -300, 1000, 2000, 3000])
    return max(0, (seq + jump) % 4096)


# ── Load data ────────────────────────────────────────────────────────────────

def load_all_csvs(dataset_dir: str) -> pd.DataFrame:
    pattern = os.path.join(dataset_dir, '**', '*.csv')
    files   = glob.glob(pattern, recursive=True)
    # Exclude anything already in processed/
    files   = [f for f in files if 'processed' not in f.replace('\\', '/')]

    if not files:
        raise FileNotFoundError(f"No CSV files found under {dataset_dir}")

    print(f"\n[+] Found {len(files)} dataset file(s):")
    dfs = []
    for f in files:
        rel = os.path.relpath(f, dataset_dir)
        try:
            df = pd.read_csv(f, low_memory=False)
            df['_source_file'] = rel
            dfs.append(df)
            print(f"    {rel:40s} → {len(df):,} rows")
        except Exception as exc:
            print(f"    [WARN] Could not read {rel}: {exc}")

    combined = pd.concat(dfs, ignore_index=True)
    print(f"\n[+] Total rows loaded: {len(combined):,}")
    return combined


# ── Clean data ───────────────────────────────────────────────────────────────

def clean_data(df: pd.DataFrame) -> pd.DataFrame:
    required = ['SSID', 'BSSID', 'RSSI', 'Channel', 'SequenceNumber',
                'BeaconInterval', 'BeaconTimestamp', 'Encryption',
                'Privacy', 'FrameLength']
    before = len(df)

    # Drop rows missing critical fields
    df = df.dropna(subset=['BSSID', 'Channel', 'RSSI'])

    # Normalise types
    df['RSSI']            = pd.to_numeric(df['RSSI'],            errors='coerce')
    df['Channel']         = pd.to_numeric(df['Channel'],         errors='coerce')
    df['SequenceNumber']  = pd.to_numeric(df['SequenceNumber'],  errors='coerce')
    df['BeaconInterval']  = pd.to_numeric(df['BeaconInterval'],  errors='coerce')
    df['BeaconTimestamp'] = pd.to_numeric(df['BeaconTimestamp'], errors='coerce')
    df['FrameLength']     = pd.to_numeric(df['FrameLength'],     errors='coerce')
    df['Privacy']         = pd.to_numeric(df['Privacy'],         errors='coerce').fillna(0).astype(int)
    df['IsHidden']        = pd.to_numeric(df['IsHidden'],        errors='coerce').fillna(0).astype(int)
    df['HasHT']           = pd.to_numeric(df['HasHT'],           errors='coerce').fillna(0).astype(int)
    df['ShortPreamble']   = pd.to_numeric(df['ShortPreamble'],   errors='coerce').fillna(0).astype(int)
    df['ShortSlot']       = pd.to_numeric(df['ShortSlot'],       errors='coerce').fillna(0).astype(int)
    df['HasExtCap']       = pd.to_numeric(df['HasExtCap'],       errors='coerce').fillna(0).astype(int)
    df['RateCount']       = pd.to_numeric(df['RateCount'],       errors='coerce').fillna(0)
    df['ExtRateCount']    = pd.to_numeric(df['ExtRateCount'],    errors='coerce').fillna(0)
    df['HTChannelWidth']  = pd.to_numeric(df['HTChannelWidth'],  errors='coerce').fillna(0)
    df['HTStreams']       = pd.to_numeric(df['HTStreams'],        errors='coerce').fillna(0)

    # Fill text columns
    df['SSID']       = df['SSID'].fillna('').astype(str)
    df['Encryption'] = df['Encryption'].fillna('Unknown').astype(str)
    df['BSSID']      = df['BSSID'].fillna('00:00:00:00:00:00').astype(str)
    df['CountryCode']= df.get('CountryCode', pd.Series([''] * len(df), index=df.index)).fillna('').astype(str)
    df['OUI']        = df.get('OUI',         pd.Series([''] * len(df), index=df.index)).fillna('').astype(str)
    df['VendorName'] = df.get('VendorName',  pd.Series(['Unknown'] * len(df), index=df.index)).fillna('Unknown').astype(str)

    # Drop remaining NaN in numeric columns
    df = df.dropna(subset=['RSSI', 'Channel', 'SequenceNumber',
                            'BeaconTimestamp', 'FrameLength'])

    print(f"[+] After cleaning: {len(df):,} rows  (dropped {before - len(df):,})")
    return df.reset_index(drop=True)


# ── Rogue generation ─────────────────────────────────────────────────────────

def sample_legit(df: pd.DataFrame, n: int) -> pd.DataFrame:
    """Sample n rows from legitimate data with replacement if needed."""
    if n <= len(df):
        return df.sample(n=n, random_state=RANDOM_SEED).copy()
    return df.sample(n=n, replace=True, random_state=RANDOM_SEED).copy()


def gen_evil_twin_last_octet(legit: pd.DataFrame, n: int) -> pd.DataFrame:
    """Evil twin: same SSID, BSSID last-octet changed, slight RSSI variation."""
    rows = sample_legit(legit, n)
    rows['BSSID']           = rows['BSSID'].apply(spoof_bssid_last_octet)
    rows['OUI']             = rows['BSSID'].apply(lambda b: ':'.join(b.split(':')[:3]))
    rows['VendorName']      = 'Unknown'
    rows['RSSI']            = rows['RSSI'] + np.random.randint(-6, 6, size=len(rows))
    rows['SequenceNumber']  = rows['SequenceNumber'].apply(jitter_seq)
    rows['BeaconTimestamp'] = rows.apply(lambda r: reset_tsf(r), axis=1)
    rows['_rogue_type']     = 'evil_twin_last_octet'
    return rows


def gen_evil_twin_full_oui(legit: pd.DataFrame, n: int) -> pd.DataFrame:
    """Evil twin: same SSID, completely different OUI."""
    rows = sample_legit(legit, n)
    rows['BSSID']           = rows['BSSID'].apply(full_spoof_bssid)
    rows['OUI']             = rows['BSSID'].apply(lambda b: ':'.join(b.split(':')[:3]))
    rows['VendorName']      = 'Unknown'
    rows['SequenceNumber']  = rows['SequenceNumber'].apply(jitter_seq)
    rows['BeaconTimestamp'] = rows.apply(lambda r: reset_tsf(r), axis=1)
    rows['_rogue_type']     = 'evil_twin_full_oui'
    return rows


def gen_security_downgrade(legit: pd.DataFrame, n: int) -> pd.DataFrame:
    """Same SSID, BSSID spoofed, encryption downgraded to WEP or Open."""
    # Only target WPA2 APs for this attack (more realistic)
    pool = legit[legit['Encryption'] == 'WPA2']
    if len(pool) < 10:
        pool = legit
    rows = sample_legit(pool, n)
    rows['BSSID']           = rows['BSSID'].apply(spoof_bssid_last_octet)
    rows['OUI']             = rows['BSSID'].apply(lambda b: ':'.join(b.split(':')[:3]))
    rows['Encryption']      = np.random.choice(['WEP', 'Open'], size=len(rows))
    rows['Privacy']         = rows['Encryption'].apply(lambda e: 1 if e == 'WEP' else 0)
    rows['BeaconTimestamp'] = rows.apply(lambda r: reset_tsf(r), axis=1)
    rows['SequenceNumber']  = rows['SequenceNumber'].apply(jitter_seq)
    rows['_rogue_type']     = 'security_downgrade'
    return rows


def gen_hidden_ssid(legit: pd.DataFrame, n: int) -> pd.DataFrame:
    """Clone AP but hide the SSID (empty SSID + IsHidden=1)."""
    rows = sample_legit(legit, n)
    rows['BSSID']           = rows['BSSID'].apply(spoof_bssid_last_octet)
    rows['OUI']             = rows['BSSID'].apply(lambda b: ':'.join(b.split(':')[:3]))
    rows['SSID']            = ''
    rows['IsHidden']        = 1
    rows['BeaconTimestamp'] = rows.apply(lambda r: reset_tsf(r), axis=1)
    rows['SequenceNumber']  = rows['SequenceNumber'].apply(jitter_seq)
    rows['_rogue_type']     = 'hidden_ssid'
    return rows


def gen_tsf_reset(legit: pd.DataFrame, n: int) -> pd.DataFrame:
    """Same SSID/BSSID but TSF reset (recently started rogue AP)."""
    rows = sample_legit(legit, n)
    rows['BeaconTimestamp'] = rows.apply(lambda r: reset_tsf(r), axis=1)
    rows['SequenceNumber']  = rows['SequenceNumber'].apply(
        lambda s: int(np.random.randint(0, 50))   # near-zero seq
    )
    rows['_rogue_type']     = 'tsf_reset'
    return rows


def gen_channel_shift(legit: pd.DataFrame, n: int) -> pd.DataFrame:
    """AP broadcasting on unexpected / different channel."""
    rows = sample_legit(legit, n)
    valid_channels = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 36, 40, 44, 48]
    rows['Channel'] = rows['Channel'].apply(
        lambda c: random.choice([ch for ch in valid_channels if ch != c] or valid_channels)
    )
    rows['BSSID']           = rows['BSSID'].apply(spoof_bssid_last_octet)
    rows['BeaconTimestamp'] = rows.apply(lambda r: reset_tsf(r), axis=1)
    rows['_rogue_type']     = 'channel_shift'
    return rows


def gen_local_admin_bssid(legit: pd.DataFrame, n: int) -> pd.DataFrame:
    """Locally-administered BSSID (a strong rogue indicator)."""
    rows = sample_legit(legit, n)
    rows['BSSID']           = rows['BSSID'].apply(local_admin_bssid)
    rows['OUI']             = rows['BSSID'].apply(lambda b: ':'.join(b.split(':')[:3]))
    rows['VendorName']      = 'Unknown'
    rows['BeaconTimestamp'] = rows.apply(lambda r: reset_tsf(r), axis=1)
    rows['SequenceNumber']  = rows['SequenceNumber'].apply(jitter_seq)
    rows['_rogue_type']     = 'local_admin_bssid'
    return rows


# ── Feature engineering (matches train_model.py) ─────────────────────────────

def engineer_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add derived features that the model will train on."""
    df = df.copy()

    # SSID-based
    df['SSID_Length']     = df['SSID'].str.len()
    df['EmptySSID']       = (df['SSID'] == '').astype(int)

    # BSSID-based
    def is_local_admin(bssid: str) -> int:
        try:
            return int(bssid.split(':')[0], 16) & 2
        except Exception:
            return 0

    df['BSSID_LocalAdmin']  = df['BSSID'].apply(is_local_admin)

    # Timestamp ratio (legit APs have large, stable TSF vs Timestamp_ms)
    df['Timestamp_ms']      = pd.to_numeric(df.get('Timestamp_ms', 0), errors='coerce').fillna(0)
    df['Timestamp_Ratio']   = df['BeaconTimestamp'] / (df['Timestamp_ms'] + 1)

    # Channel suspicion
    df['UnusualChannel']    = df['Channel'].apply(lambda c: 0 if c in [1, 6, 11] else 1)

    # Encryption-based
    df['Is_WEP']            = (df['Encryption'] == 'WEP').astype(int)
    df['Is_Open']           = (df['Encryption'] == 'Open').astype(int)

    # Sequence number jitter flag (heuristic: very low seq on a known SSID)
    df['LowSeqNumber']      = (df['SequenceNumber'] < 100).astype(int)

    # Low TSF flag
    df['LowTSF']            = (df['BeaconTimestamp'] < 10_000_000).astype(int)

    return df


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    print("=" * 64)
    print("  Rogue AP Dataset Preprocessor")
    print("=" * 64)

    # 1. Load
    raw = load_all_csvs(DATASET_DIR)

    # 2. Clean
    legit_df = clean_data(raw)
    legit_df['is_rogue']    = 0
    legit_df['_rogue_type'] = 'legitimate'

    n_legit = len(legit_df)
    n_per_type = max(200, int(n_legit * ROGUE_FRACTION_PER_TYPE))
    print(f"\n[+] Legitimate samples : {n_legit:,}")
    print(f"[+] Rogue per type     : {n_per_type:,}")

    # 3. Generate rogue variants
    rogue_frames = [
        gen_evil_twin_last_octet(legit_df, n_per_type),
        gen_evil_twin_full_oui  (legit_df, n_per_type),
        gen_security_downgrade  (legit_df, n_per_type),
        gen_hidden_ssid         (legit_df, n_per_type),
        gen_tsf_reset           (legit_df, n_per_type),
        gen_channel_shift       (legit_df, n_per_type),
        gen_local_admin_bssid   (legit_df, n_per_type),
    ]

    for rf in rogue_frames:
        rf['is_rogue'] = 1

    rogue_df = pd.concat(rogue_frames, ignore_index=True)
    n_rogue  = len(rogue_df)

    # 4. Combine
    combined = pd.concat([legit_df, rogue_df], ignore_index=True)
    combined = combined.sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

    # 5. Feature engineering
    combined = engineer_features(combined)

    # 6. Drop internal helper columns before save
    drop_cols = ['_source_file']
    combined.drop(columns=[c for c in drop_cols if c in combined.columns],
                  inplace=True)

    # 7. Save
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    combined.to_csv(OUTPUT_FILE, index=False)

    # ── Summary ──────────────────────────────────────────────────────────
    print("\n" + "=" * 64)
    print("  Summary")
    print("=" * 64)
    print(f"  Total rows         : {len(combined):,}")
    print(f"  Legitimate (0)     : {n_legit:,}  ({n_legit/len(combined)*100:.1f}%)")
    print(f"  Rogue      (1)     : {n_rogue:,}  ({n_rogue/len(combined)*100:.1f}%)")
    print(f"\n  Rogue breakdown:")
    for g, cnt in combined[combined['is_rogue'] == 1].groupby('_rogue_type').size().items():
        print(f"    {g:30s}: {cnt:,}")
    print(f"\n  Output             : {OUTPUT_FILE}")
    print("=" * 64)

    # ── Quick feature preview ─────────────────────────────────────────────
    feature_cols = [
        'RSSI', 'Channel', 'SequenceNumber', 'BeaconInterval',
        'FrameLength', 'RateCount', 'ExtRateCount',
        'Privacy', 'ShortPreamble', 'ShortSlot', 'HasHT', 'HTStreams',
        'HasExtCap', 'IsHidden',
        'SSID_Length', 'EmptySSID', 'BSSID_LocalAdmin',
        'Timestamp_Ratio', 'UnusualChannel',
        'Is_WEP', 'Is_Open', 'LowSeqNumber', 'LowTSF',
        'is_rogue'
    ]
    available = [c for c in feature_cols if c in combined.columns]
    print(f"\n  Features available for training ({len(available)}):")
    for c in available:
        print(f"    {c}")

    print(f"\n[✓] Done! Dataset written to:\n    {OUTPUT_FILE}\n")


if __name__ == '__main__':
    main()
