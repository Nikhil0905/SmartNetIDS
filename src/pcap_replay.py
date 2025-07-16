# PCAP Replay Script for SmartNetIDS
"""
Replay a PCAP file through the SmartNetIDS detection pipeline (rule-based + ML-based).

Usage:
    python src/pcap_replay.py yourfile.pcap --local_ip <your_ip>

- Processes each packet in the PCAP file as if it were live traffic.
- Logs anomalies to the same log files as live detection.
- Supports all current detection rules and ML model.
"""

from scapy.all import rdpcap
from datetime import datetime
import collections
from feature_extractor import extract_features
from ml_model import load_model, predict
from alert_logger import log_anomaly

# Rule-based detection state (same as in dashboard)
port_scan_tracker = collections.defaultdict(list)  # src_ip -> list of (timestamp, dst_port)
dns_query_tracker = collections.defaultdict(list)  # src_ip -> list of timestamps


def rule_based_detection(features, now):
    # Port scanning
    if features.get('src_ip') and features.get('dst_port'):
        port_scan_tracker[features['src_ip']].append((now, features['dst_port']))
        port_scan_tracker[features['src_ip']] = [
            (t, p) for t, p in port_scan_tracker[features['src_ip']] if (now - t).total_seconds() < 10
        ]
        unique_ports = set(p for t, p in port_scan_tracker[features['src_ip']])
        if len(unique_ports) > 10:
            log_anomaly(
                src_ip=features['src_ip'],
                dst_ip=features['dst_ip'],
                protocol=features['protocol'],
                message="Port scan detected (rule-based)",
                extra={"unique_ports": list(unique_ports)}
            )
            port_scan_tracker[features['src_ip']] = []
    # Protocol violations (SYN+FIN)
    if features.get('tcp_flag_syn') and features.get('tcp_flag_fin'):
        if features['tcp_flag_syn'] == 1 and features['tcp_flag_fin'] == 1:
            log_anomaly(
                src_ip=features['src_ip'],
                dst_ip=features['dst_ip'],
                protocol=features['protocol'],
                message="Protocol violation: SYN+FIN set (rule-based)",
                extra={"tcp_flags": features.get('tcp_flags')}
            )
    # DNS tunneling (high query rate)
    if features.get('protocol') == 17 and features.get('dst_port') == 53 and features.get('src_ip'):
        dns_query_tracker[features['src_ip']].append(now)
        dns_query_tracker[features['src_ip']] = [
            t for t in dns_query_tracker[features['src_ip']] if (now - t).total_seconds() < 60
        ]
        if len(dns_query_tracker[features['src_ip']]) > 100:
            log_anomaly(
                src_ip=features['src_ip'],
                dst_ip=features['dst_ip'],
                protocol=features['protocol'],
                message="DNS tunneling suspected: high query rate (rule-based)",
                extra={"dns_queries_last_min": len(dns_query_tracker[features['src_ip']])}
            )
            dns_query_tracker[features['src_ip']] = []
    # Data exfiltration (large outbound packet)
    if features.get('direction') == 'outbound' and features.get('length', 0) > 1500:
        log_anomaly(
            src_ip=features['src_ip'],
            dst_ip=features['dst_ip'],
            protocol=features['protocol'],
            message="Data exfiltration suspected: large outbound packet (rule-based)",
            extra={"length": features.get('length')}
        )


def ml_based_detection(features, model):
    feature_vector = [
        features.get('length', 0),
        features.get('protocol', 0) or 0,
        features.get('src_port', 0) or 0,
        features.get('dst_port', 0) or 0,
        features.get('inter_arrival', 0.0),
        features.get('entropy', 0.0),
        features.get('tcp_flag_syn', 0),
        features.get('tcp_flag_fin', 0),
        features.get('tcp_flag_rst', 0),
        features.get('tcp_flag_psh', 0),
        features.get('tcp_flag_ack', 0),
        features.get('tcp_flag_urg', 0),
    ]
    if model:
        pred = predict(model, feature_vector)[0]
        if pred == -1:
            log_anomaly(
                src_ip=features.get('src_ip'),
                dst_ip=features.get('dst_ip'),
                protocol=features.get('protocol'),
                message="Anomaly detected (score: N/A)",
                extra={
                    'length': features.get('length'),
                    'inter_arrival': features.get('inter_arrival'),
                    'entropy': features.get('entropy'),
                    'direction': features.get('direction'),
                    'tcp_flags': features.get('tcp_flags'),
                    'src_port': features.get('src_port'),
                    'dst_port': features.get('dst_port')
                }
            )


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Replay a PCAP file through SmartNetIDS detection pipeline.")
    parser.add_argument('pcap_file', help='Input PCAP file')
    parser.add_argument('--local_ip', type=str, default=None, help='Local IP for direction feature')
    args = parser.parse_args()

    print("Loading model...")
    model = load_model()
    print(f"Reading packets from {args.pcap_file} ...")
    packets = rdpcap(args.pcap_file)
    print(f"Processing {len(packets)} packets...")
    for i, pkt in enumerate(packets):
        features = extract_features(pkt, local_ip=args.local_ip)
        now = datetime.now()
        rule_based_detection(features, now)
        ml_based_detection(features, model)
        if (i+1) % 1000 == 0:
            print(f"Processed {i+1} packets...")
    print("Replay complete.")


if __name__ == "__main__":
    main() 