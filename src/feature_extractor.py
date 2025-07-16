# Feature extractor module for SmartNetIDS
# Extracts features from Scapy packets for ML processing

from scapy.all import Ether, IP, TCP, UDP, Raw  # type: ignore
from datetime import datetime
import math

# Global variable to store last packet time for inter-arrival calculation
_last_packet_time = None


def calculate_entropy(data):
    """
    Calculate the Shannon entropy of a byte string.
    """
    if not data:
        return 0.0
    byte_counts = [0] * 256
    for b in data:
        byte_counts[b] += 1
    entropy = 0.0
    length = len(data)
    for count in byte_counts:
        if count == 0:
            continue
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def extract_features(packet, local_ip=None):
    """
    Extract enhanced NIDS features from a Scapy packet.
    Returns a dictionary of features.
    Features: timestamp, src_ip, dst_ip, protocol, src_port, dst_port, length, tcp_flags, inter_arrival, entropy, direction
    :param local_ip: (optional) IP address of the monitored interface for direction
    """
    global _last_packet_time
    features = {}
    now = datetime.now()
    features['timestamp'] = now.strftime('%Y-%m-%d %H:%M:%S')
    if packet is None or not hasattr(packet, '__len__'):
        features['length'] = 0
        features['src_ip'] = None
        features['dst_ip'] = None
        features['protocol'] = None
        features['src_port'] = None
        features['dst_port'] = None
        features['tcp_flags'] = None
        features['tcp_flag_syn'] = 0
        features['tcp_flag_fin'] = 0
        features['tcp_flag_rst'] = 0
        features['tcp_flag_psh'] = 0
        features['tcp_flag_ack'] = 0
        features['tcp_flag_urg'] = 0
        features['entropy'] = 0.0
        features['direction'] = 'unknown'
        features['inter_arrival'] = 0.0
        return features
    features['length'] = len(packet)
    # Inter-arrival time
    if _last_packet_time is not None:
        features['inter_arrival'] = (now - _last_packet_time).total_seconds()
    else:
        features['inter_arrival'] = 0.0
    _last_packet_time = now
    if IP in packet:
        features['src_ip'] = packet[IP].src
        features['dst_ip'] = packet[IP].dst
        features['protocol'] = packet[IP].proto
        # Direction (inbound/outbound)
        if local_ip:
            if packet[IP].src == local_ip:
                features['direction'] = 'outbound'
            elif packet[IP].dst == local_ip:
                features['direction'] = 'inbound'
            else:
                features['direction'] = 'unknown'
        else:
            features['direction'] = 'unknown'
        # Default ports to None
        features['src_port'] = None
        features['dst_port'] = None
        # TCP/UDP ports and flags
        if TCP in packet:
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['tcp_flags'] = str(packet[TCP].flags)
            # TCP flag combinations (SYN, FIN, etc.)
            features['tcp_flag_syn'] = int('S' in str(packet[TCP].flags))
            features['tcp_flag_fin'] = int('F' in str(packet[TCP].flags))
            features['tcp_flag_rst'] = int('R' in str(packet[TCP].flags))
            features['tcp_flag_psh'] = int('P' in str(packet[TCP].flags))
            features['tcp_flag_ack'] = int('A' in str(packet[TCP].flags))
            features['tcp_flag_urg'] = int('U' in str(packet[TCP].flags))
        elif UDP in packet:
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
            features['tcp_flags'] = None
            features['tcp_flag_syn'] = 0
            features['tcp_flag_fin'] = 0
            features['tcp_flag_rst'] = 0
            features['tcp_flag_psh'] = 0
            features['tcp_flag_ack'] = 0
            features['tcp_flag_urg'] = 0
        else:
            features['tcp_flags'] = None
            features['tcp_flag_syn'] = 0
            features['tcp_flag_fin'] = 0
            features['tcp_flag_rst'] = 0
            features['tcp_flag_psh'] = 0
            features['tcp_flag_ack'] = 0
            features['tcp_flag_urg'] = 0
        # Payload entropy
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            features['entropy'] = calculate_entropy(payload)
        else:
            features['entropy'] = 0.0
    else:
        # Non-IP packet
        features['src_ip'] = None
        features['dst_ip'] = None
        features['protocol'] = None
        features['src_port'] = None
        features['dst_port'] = None
        features['tcp_flags'] = None
        features['tcp_flag_syn'] = 0
        features['tcp_flag_fin'] = 0
        features['tcp_flag_rst'] = 0
        features['tcp_flag_psh'] = 0
        features['tcp_flag_ack'] = 0
        features['tcp_flag_urg'] = 0
        features['entropy'] = 0.0
        features['direction'] = 'unknown'
        features['inter_arrival'] = 0.0
    return features


if __name__ == "__main__":
    # Test harness: Create a sample packet and extract features
    print("Testing enhanced feature extraction with a sample TCP packet:")
    sample_packet = Ether()/IP(src="192.168.1.2", dst="192.168.1.3")/TCP(sport=12345, dport=80, flags="S")/Raw(load=b"GET / HTTP/1.1\r\n\r\n")
    feats = extract_features(sample_packet, local_ip="192.168.1.2")
    for k, v in feats.items():
        print(f"{k}: {v}") 