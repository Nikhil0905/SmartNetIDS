# Packet sniffer module for SmartNetIDS
# Uses Scapy to capture live network packets
# Can be tested independently

from scapy.all import sniff, IP  # type: ignore
from datetime import datetime
import os


def packet_callback(packet):
    """
    Callback function to process each captured packet.
    Prints timestamp, source IP, destination IP, and protocol (if available).
    """
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    if IP in packet:
        src = packet[IP].src
        dst = packet[IP].dst
        proto = packet[IP].proto
        print(f"[{timestamp}] {src} -> {dst} | Protocol: {proto}")
    else:
        print(f"[{timestamp}] Non-IP packet captured.")


def start_sniffing(interface=None, packet_count=0):
    """
    Start sniffing packets on the specified interface.
    :param interface: Network interface to sniff on (default: None = all interfaces)
    :param packet_count: Number of packets to capture (0 = infinite)
    """
    print(f"Starting packet capture on interface: {interface or 'ALL'} (Ctrl+C to stop)")
    sniff(prn=packet_callback, iface=interface, count=packet_count, store=0)


if __name__ == "__main__":
    # Test harness: Run this file directly to test packet sniffing
    import argparse
    parser = argparse.ArgumentParser(description="SmartNetIDS Packet Sniffer Test")
    parser.add_argument('-i', '--interface', type=str, default=None, help='Network interface to sniff on (default: all)')
    parser.add_argument('-c', '--count', type=int, default=0, help='Number of packets to capture (0 = infinite)')
    args = parser.parse_args()
    try:
        start_sniffing(interface=args.interface, packet_count=args.count)
    except KeyboardInterrupt:
        print("\nPacket sniffing stopped by user.") 