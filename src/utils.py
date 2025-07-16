# Utility functions for SmartNetIDS
# Includes CSV feature extraction for enhanced ML training

import pandas as pd
import math
import binascii


def calculate_entropy(data_bytes):
    if not data_bytes:
        return 0.0
    byte_counts = [0] * 256
    for b in data_bytes:
        byte_counts[b] += 1
    entropy = 0.0
    length = len(data_bytes)
    for count in byte_counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_enhanced_features_from_csv(input_csv, output_csv, local_ip=None, payload_col='payload', timestamp_col='timestamp'):
    """
    Process a CSV file and extract enhanced features for each row.
    Assumes columns: src_ip, dst_ip, protocol, src_port, dst_port, payload, timestamp.
    Writes a new CSV with enhanced features.
    """
    df = pd.read_csv(input_csv)
    # Ensure timestamp is datetime
    df[timestamp_col] = pd.to_datetime(df[timestamp_col])
    # Sort by timestamp for inter-arrival
    df = df.sort_values(timestamp_col).reset_index(drop=True)
    inter_arrivals = [0.0]
    for i in range(1, len(df)):
        delta = (df.loc[i, timestamp_col] - df.loc[i-1, timestamp_col]).total_seconds()
        inter_arrivals.append(delta)
    df['inter_arrival'] = inter_arrivals
    # Direction
    if local_ip:
        df['direction'] = df.apply(lambda row: 'outbound' if row['src_ip'] == local_ip else ('inbound' if row['dst_ip'] == local_ip else 'unknown'), axis=1)
    else:
        df['direction'] = 'unknown'
    # TCP flag extraction (assume a 'tcp_flags' column or set to None)
    if 'tcp_flags' in df.columns:
        flags = df['tcp_flags'].fillna('')
    else:
        flags = pd.Series([''] * len(df))
    df['tcp_flag_syn'] = flags.apply(lambda f: int('S' in str(f)))
    df['tcp_flag_fin'] = flags.apply(lambda f: int('F' in str(f)))
    df['tcp_flag_rst'] = flags.apply(lambda f: int('R' in str(f)))
    df['tcp_flag_psh'] = flags.apply(lambda f: int('P' in str(f)))
    df['tcp_flag_ack'] = flags.apply(lambda f: int('A' in str(f)))
    df['tcp_flag_urg'] = flags.apply(lambda f: int('U' in str(f)))
    # Entropy (assume payload is hex or base64 encoded string)
    def safe_entropy(payload):
        try:
            if pd.isna(payload):
                return 0.0
            # Try hex decode first
            try:
                data_bytes = binascii.unhexlify(payload)
            except Exception:
                # Try base64 decode
                import base64
                data_bytes = base64.b64decode(payload)
            return calculate_entropy(data_bytes)
        except Exception:
            return 0.0
    df['entropy'] = df[payload_col].apply(safe_entropy)
    # Save enhanced CSV
    df.to_csv(output_csv, index=False)
    print(f"Enhanced features written to {output_csv}")


if __name__ == "__main__":
    # Example usage: process a CSV and write enhanced features
    import argparse
    parser = argparse.ArgumentParser(description="Extract enhanced features from CSV for SmartNetIDS")
    parser.add_argument('input_csv', help='Input CSV file')
    parser.add_argument('output_csv', help='Output CSV file with enhanced features')
    parser.add_argument('--local_ip', type=str, default=None, help='Local IP for direction feature')
    parser.add_argument('--payload_col', type=str, default='payload', help='Column name for payload data')
    parser.add_argument('--timestamp_col', type=str, default='timestamp', help='Column name for timestamp')
    args = parser.parse_args()
    extract_enhanced_features_from_csv(args.input_csv, args.output_csv, local_ip=args.local_ip, payload_col=args.payload_col, timestamp_col=args.timestamp_col) 