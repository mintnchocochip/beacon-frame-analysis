import pandas as pd
import numpy as np
import glob
import os

class TemporalBeaconAnalyzer:
    """
    Temporal analysis of beacon frames for rogue AP detection
    
    Key insight: Rogue APs often have irregular beacon timing patterns
    - Legitimate APs: Regular, consistent beacon intervals
    - Rogue APs: Irregular timing, jitter, missed beacons
    """
    
    def __init__(self):
        self.temporal_features = []
        
    def load_and_sort(self, dataset_dir='../dataset'):
        """Load all CSV files and sort by timestamp"""
        csv_files = []
        for session_dir in glob.glob(os.path.join(dataset_dir, 'session_*')):
            csv_files.extend(glob.glob(os.path.join(session_dir, '*.csv')))
        
        print(f"Loading {len(csv_files)} CSV files...")
        dfs = []
        for file in csv_files:
            try:
                df = pd.read_csv(file)
                dfs.append(df)
            except Exception as e:
                print(f"Error loading {file}: {e}")
        
        data = pd.concat(dfs, ignore_index=True)
        
        # Sort by BSSID and timestamp - CRITICAL for temporal analysis
        data = data.sort_values(['BSSID', 'Timestamp_ms']).reset_index(drop=True)
        
        print(f"Loaded {len(data)} beacon frames")
        print(f"Unique BSSIDs: {data['BSSID'].nunique()}")
        
        return data
    
    def compute_temporal_features(self, df):
        """
        Compute temporal features for each BSSID
        
        Returns DataFrame with temporal statistics per BSSID
        """
        print("\nComputing temporal features...")
        
        temporal_stats = []
        
        # Group by BSSID (each AP has unique BSSID)
        for bssid, group in df.groupby('BSSID'):
            if len(group) < 2:
                continue  # Need at least 2 beacons for timing analysis
            
            # Sort by timestamp within group
            group = group.sort_values('Timestamp_ms')
            
            # Compute inter-beacon intervals
            time_diffs = group['Timestamp_ms'].diff().dropna()
            
            # Sequence number analysis
            seq_diffs = group['SequenceNumber'].diff().dropna()
            
            # Expected beacon interval (from beacon frame)
            expected_interval = group['BeaconInterval'].mode()[0] if len(group) > 0 else 100
            
            stats = {
                'BSSID': bssid,
                'SSID': group['SSID'].iloc[0] if pd.notna(group['SSID'].iloc[0]) else '',
                
                # Count statistics
                'BeaconCount': len(group),
                'CaptureTimeSpan_ms': group['Timestamp_ms'].max() - group['Timestamp_ms'].min(),
                
                # Timing analysis
                'MeanInterBeaconTime_ms': time_diffs.mean(),
                'StdInterBeaconTime_ms': time_diffs.std(),
                'MinInterBeaconTime_ms': time_diffs.min(),
                'MaxInterBeaconTime_ms': time_diffs.max(),
                'ExpectedBeaconInterval_TU': expected_interval,
                
                # Timing irregularity metrics
                'TimingJitter': time_diffs.std() / (time_diffs.mean() + 1e-6),  # Coefficient of variation
                'MissedBeacons': (time_diffs > expected_interval * 1.5).sum(),  # Gaps > 1.5x expected
                
                # Sequence number analysis
                'MeanSeqGap': seq_diffs.mean(),
                'StdSeqGap': seq_diffs.std(),
                'MaxSeqGap': seq_diffs.max(),
                'SeqNumberResets': (seq_diffs < 0).sum(),  # Sequence resets to 0
                
                # Channel behavior
                'ChannelChanges': (group['Channel'].diff() != 0).sum(),
                'UniqueChannels': group['Channel'].nunique(),
                
                # Signal strength patterns
                'MeanRSSI': group['RSSI'].mean(),
                'StdRSSI': group['RSSI'].std(),
                'RSSIRange': group['RSSI'].max() - group['RSSI'].min(),
                
                # Other metadata
                'Encryption': group['Encryption'].mode()[0] if len(group) > 0 else 'Unknown',
                'HasHT': group['HasHT'].mode()[0] if len(group) > 0 else 0,
            }
            
            temporal_stats.append(stats)
        
        temporal_df = pd.DataFrame(temporal_stats)
        print(f"Computed temporal features for {len(temporal_df)} BSSIDs")
        
        return temporal_df
    
    def identify_suspicious_patterns(self, temporal_df, verbose=True):
        """
        Identify suspicious temporal patterns that indicate potential rogue APs
        """
        suspicious = temporal_df.copy()
        suspicious['SuspicionScore'] = 0
        suspicious['SuspicionReasons'] = ''
        
        # Rule 1: High timing jitter (irregular beaconing)
        jitter_threshold = 0.3  # 30% coefficient of variation
        high_jitter = suspicious['TimingJitter'] > jitter_threshold
        suspicious.loc[high_jitter, 'SuspicionScore'] += 2
        suspicious.loc[high_jitter, 'SuspicionReasons'] += 'High_Jitter; '
        
        # Rule 2: Many missed beacons
        missed_threshold = 5
        many_missed = suspicious['MissedBeacons'] > missed_threshold
        suspicious.loc[many_missed, 'SuspicionScore'] += 2
        suspicious.loc[many_missed, 'SuspicionReasons'] += 'Missed_Beacons; '
        
        # Rule 3: Channel hopping (suspicious for APs)
        channel_hopping = suspicious['ChannelChanges'] > 2
        suspicious.loc[channel_hopping, 'SuspicionScore'] += 3
        suspicious.loc[channel_hopping, 'SuspicionReasons'] += 'Channel_Hopping; '
        
        # Rule 4: Sequence number anomalies
        high_seq_gap = suspicious['MaxSeqGap'] > 100
        suspicious.loc[high_seq_gap, 'SuspicionScore'] += 1
        suspicious.loc[high_seq_gap, 'SuspicionReasons'] += 'Seq_Gaps; '
        
        seq_resets = suspicious['SeqNumberResets'] > 2
        suspicious.loc[seq_resets, 'SuspicionScore'] += 2
        suspicious.loc[seq_resets, 'SuspicionReasons'] += 'Seq_Resets; '
        
        # Rule 5: Very weak or fluctuating signal
        weak_signal = suspicious['MeanRSSI'] < -85
        suspicious.loc[weak_signal, 'SuspicionScore'] += 1
        suspicious.loc[weak_signal, 'SuspicionReasons'] += 'Weak_Signal; '
        
        high_rssi_variance = suspicious['StdRSSI'] > 10
        suspicious.loc[high_rssi_variance, 'SuspicionScore'] += 1
        suspicious.loc[high_rssi_variance, 'SuspicionReasons'] += 'RSSI_Variance; '
        
        # Rule 6: Very few beacons captured (might be fleeting rogue AP)
        few_beacons = suspicious['BeaconCount'] < 5
        suspicious.loc[few_beacons, 'SuspicionScore'] += 1
        suspicious.loc[few_beacons, 'SuspicionReasons'] += 'Few_Beacons; '
        
        # Sort by suspicion score
        suspicious = suspicious.sort_values('SuspicionScore', ascending=False)
        
        if verbose:
            print("\n" + "="*80)
            print("TEMPORAL ANALYSIS RESULTS")
            print("="*80)
            
            high_suspicion = suspicious[suspicious['SuspicionScore'] >= 5]
            print(f"\nHigh suspicion APs (score >= 5): {len(high_suspicion)}")
            
            if len(high_suspicion) > 0:
                print("\nTop suspicious APs:")
                for idx, row in high_suspicion.head(10).iterrows():
                    print(f"\n{row['SSID'] or '(Hidden)'} - {row['BSSID']}")
                    print(f"  Suspicion Score: {row['SuspicionScore']}")
                    print(f"  Reasons: {row['SuspicionReasons']}")
                    print(f"  Timing Jitter: {row['TimingJitter']:.3f}")
                    print(f"  Missed Beacons: {row['MissedBeacons']:.0f}")
                    print(f"  Channel Changes: {row['ChannelChanges']:.0f}")
        
        return suspicious
    
    def create_windowed_features(self, df, window_size='10s'):
        """
        Create rolling window features for time-series analysis
        
        Args:
            df: Original beacon DataFrame
            window_size: Time window (e.g., '10s' for 10 seconds)
        
        Returns:
            DataFrame with windowed features
        """
        print(f"\nCreating windowed features (window={window_size})...")
        
        df = df.copy()
        df['datetime'] = pd.to_datetime(df['Timestamp_ms'], unit='ms')
        
        windowed_features = []
        
        for bssid, group in df.groupby('BSSID'):
            if len(group) < 2:
                continue
            
            group = group.sort_values('datetime').set_index('datetime')
            
            # Rolling window statistics
            rolling = group.rolling(window_size, min_periods=1)
            
            for timestamp, window_data in group.groupby(pd.Grouper(freq=window_size)):
                if len(window_data) == 0:
                    continue
                
                features = {
                    'BSSID': bssid,
                    'TimeWindow': timestamp,
                    'BeaconsInWindow': len(window_data),
                    'MeanRSSI': window_data['RSSI'].mean(),
                    'StdRSSI': window_data['RSSI'].std(),
                    'ChannelChanges': (window_data['Channel'].diff() != 0).sum(),
                }
                
                windowed_features.append(features)
        
        windowed_df = pd.DataFrame(windowed_features)
        print(f"Created {len(windowed_df)} time windows")
        
        return windowed_df
    
    def save_processed_data(self, temporal_df, output_path='temporal_features.csv'):
        """Save processed temporal features"""
        temporal_df.to_csv(output_path, index=False)
        print(f"\nSaved temporal features to {output_path}")


def main():
    """Main preprocessing pipeline"""
    print("="*80)
    print("TEMPORAL BEACON FRAME ANALYSIS")
    print("="*80)
    print("\nThis analyzes timing patterns to detect rogue APs")
    print("Key insight: Rogue APs often have irregular beacon timing\n")
    
    analyzer = TemporalBeaconAnalyzer()
    
    # Step 1: Load and sort data
    df = analyzer.load_and_sort()
    
    # Step 2: Compute temporal features per BSSID
    temporal_df = analyzer.compute_temporal_features(df)
    
    # Step 3: Identify suspicious patterns
    suspicious_df = analyzer.identify_suspicious_patterns(temporal_df)
    
    # Step 4: Save processed data
    analyzer.save_processed_data(suspicious_df, 'temporal_features.csv')
    
    print("\n" + "="*80)
    print("NEXT STEPS:")
    print("="*80)
    print("1. Review temporal_features.csv for suspicious APs")
    print("2. Use temporal features for anomaly detection training")
    print("3. Collect data from known rogue APs for validation")
    print("="*80)
    
    return temporal_df, suspicious_df


if __name__ == '__main__':
    temporal_df, suspicious_df = main()
