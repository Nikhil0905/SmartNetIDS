# Automated Report Generation for SmartNetIDS
"""
Generate a Markdown report summarizing detection activity and analytics.

Usage:
    python src/generate_report.py

- Reads recent alerts from data/logs/.
- Outputs smartnetids_report.md with anomaly breakdowns, top IPs, flows, and time-of-day patterns.
- Convert to PDF using Pandoc, VSCode, or Typora.
"""

import os
import re
from collections import Counter
from datetime import datetime


def read_recent_alerts(log_dir='data/logs', n=500):
    # Find the latest log file
    files = [
        f for f in os.listdir(log_dir)
        if f.startswith('anomaly_log_') and f.endswith('.txt')
    ]
    if not files:
        return []
    latest = sorted(files)[-1]
    with open(os.path.join(log_dir, latest), 'r') as f:
        lines = f.readlines()[-n:]
    return lines


def main():
    alerts = read_recent_alerts()
    if not alerts:
        print("No alerts found. Run detection first.")
        return
    # Total anomalies
    total_anomalies = len(alerts)
    # Anomaly type breakdown
    type_counts = Counter()
    src_counter = Counter()
    dst_counter = Counter()
    flow_counter = Counter()
    hour_counter = Counter()
    for alert in alerts:
        if 'Anomaly detected' in alert:
            type_counts['ML-based'] += 1
        elif 'Port scan detected' in alert:
            type_counts['Port Scan'] += 1
        elif 'Protocol violation' in alert:
            type_counts['Protocol Violation'] += 1
        elif 'DNS tunneling' in alert:
            type_counts['DNS Tunneling'] += 1
        elif 'Data exfiltration' in alert:
            type_counts['Data Exfiltration'] += 1
        elif 'manual' in alert.lower():
            type_counts['Manual'] += 1
        # IPs and flows
        src_match = re.search(r"src_ip=([\d\.]+)|'src_ip': '([\d\.]+)'", alert)
        dst_match = re.search(r"dst_ip=([\d\.]+)|'dst_ip': '([\d\.]+)'", alert)
        src_ip = src_match.group(1) or src_match.group(2) if src_match else None
        dst_ip = dst_match.group(1) or dst_match.group(2) if dst_match else None
        if src_ip and src_ip != 'None':
            src_counter[src_ip] += 1
        if dst_ip and dst_ip != 'None':
            dst_counter[dst_ip] += 1
        if src_ip and dst_ip and src_ip != 'None' and dst_ip != 'None':
            flow_counter[(src_ip, dst_ip)] += 1
        # Time-of-day
        ts_match = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}):(\d{2}):(\d{2})\]", alert)
        if ts_match:
            hour = ts_match.group(1)[-2:]
            hour_counter[hour] += 1
    # Write Markdown report
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open('smartnetids_report.md', 'w') as f:
        f.write(f"# SmartNetIDS Detection Report\n\n")
        f.write(f"**Generated:** {now}\n\n")
        f.write(f"## Total Anomalies: {total_anomalies}\n\n")
        f.write(f"## Anomaly Type Breakdown\n")
        for k, v in type_counts.items():
            f.write(f"- {k}: {v}\n")
        f.write(f"\n## Top Source IPs\n")
        for ip, count in src_counter.most_common(10):
            f.write(f"- {ip}: {count}\n")
        f.write(f"\n## Top Destination IPs\n")
        for ip, count in dst_counter.most_common(10):
            f.write(f"- {ip}: {count}\n")
        f.write(f"\n## Top Flows (src_ip → dst_ip)\n")
        for (src, dst), count in flow_counter.most_common(10):
            f.write(f"- {src} → {dst}: {count}\n")
        f.write(f"\n## Anomalies by Hour of Day\n")
        for h in range(24):
            f.write(f"- {h:02d}:00: {hour_counter.get(str(h), 0)}\n")
        f.write(f"\n---\n")
        f.write("*This report was generated automatically by SmartNetIDS. You can convert this Markdown file to PDF using tools like Pandoc or by opening it in VSCode/Typora and exporting as PDF.*\n")
    print("Report written to smartnetids_report.md")


if __name__ == "__main__":
    main() 