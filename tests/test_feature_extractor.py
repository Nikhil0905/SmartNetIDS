# Unit tests for feature_extractor.py
from scapy.all import Ether, IP, TCP, Raw  # type: ignore
from src.feature_extractor import extract_features


def test_extract_features_tcp():
    pkt = Ether()/IP(src="1.2.3.4", dst="5.6.7.8")/TCP(sport=1234, dport=80, flags="S")/Raw(load=b"test")
    feats = extract_features(pkt, local_ip="1.2.3.4")
    assert feats['src_ip'] == "1.2.3.4"
    assert feats['dst_ip'] == "5.6.7.8"
    assert feats['src_port'] == 1234
    assert feats['dst_port'] == 80
    assert feats['tcp_flag_syn'] == 1
    assert feats['direction'] == 'outbound'
    assert feats['entropy'] >= 0.0


def test_extract_features_non_ip():
    pkt = Ether()
    feats = extract_features(pkt)
    assert feats['src_ip'] is None
    assert feats['dst_ip'] is None
    assert feats['protocol'] is None
    assert feats['direction'] == 'unknown'


def test_extract_features_empty():
    # Test with None as input
    feats = extract_features(None)
    assert isinstance(feats, dict)
    # All values should be default/None/0
    assert feats.get('src_ip') is None
    assert feats.get('dst_ip') is None
    assert feats.get('protocol') is None
    assert feats.get('direction') == 'unknown'


def test_extract_features_malformed():
    # Test with a deliberately malformed object
    class FakePacket:
        pass
    pkt = FakePacket()
    feats = extract_features(pkt)
    assert isinstance(feats, dict)
    assert feats.get('src_ip') is None
    assert feats.get('dst_ip') is None
    assert feats.get('protocol') is None
    assert feats.get('direction') == 'unknown' 