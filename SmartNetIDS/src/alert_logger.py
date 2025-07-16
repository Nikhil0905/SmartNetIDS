# Alert logger module for SmartNetIDS
# Handles logging of anomalies and alerting to console

import os
from datetime import datetime
import socket

LOG_DIR = os.path.join('data', 'logs')
LOG_FILE_TEMPLATE = 'anomaly_log_{date}.txt'

# Syslog configuration (set these as needed)
SYSLOG_ENABLED = False
SYSLOG_SERVER = '127.0.0.1'
SYSLOG_PORT = 514


def get_log_file_path():
    """
    Returns the log file path for today's date.
    """
    date_str = datetime.now().strftime('%Y-%m-%d')
    return os.path.join(LOG_DIR, LOG_FILE_TEMPLATE.format(date=date_str))


# Syslog export function
def send_syslog_alert(message, server=SYSLOG_SERVER, port=SYSLOG_PORT):
    """
    Send an alert message to a syslog server (UDP).
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Simple syslog format: <PRI>MESSAGE
        pri = 13  # user.notice
        syslog_msg = f"<{pri}>{message}"
        sock.sendto(syslog_msg.encode('utf-8'), (server, port))
        sock.close()
    except Exception as e:
        print(f"[Syslog Error] {e}")


def log_anomaly(src_ip, dst_ip, protocol, message, extra=None):
    """
    Log an anomaly to the log file and print an alert to the console.
    :param src_ip: Source IP address
    :param dst_ip: Destination IP address
    :param protocol: Protocol number or name
    :param message: Description of the anomaly
    :param extra: Optional dictionary of extra info
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_entry = (
        f"[{timestamp}] ALERT: {src_ip} -> {dst_ip} | Protocol: {protocol} | "
        f"{message}"
    )
    if extra:
        log_entry += f" | Extra: {extra}"
    # Ensure log directory exists
    os.makedirs(LOG_DIR, exist_ok=True)
    # Write to log file
    with open(get_log_file_path(), 'a') as f:
        f.write(log_entry + '\n')
    # Print to console
    print(log_entry)
    # Send to syslog if enabled
    if SYSLOG_ENABLED:
        send_syslog_alert(log_entry)


if __name__ == "__main__":
    # Test harness: Log a sample anomaly
    print("Testing alert logger module:")
    log_anomaly(
        src_ip="192.168.1.2",
        dst_ip="192.168.1.3",
        protocol=6,
        message="Test anomaly detected: Port scan detected",
        extra={"src_port": 12345, "dst_port": 80}
    ) 