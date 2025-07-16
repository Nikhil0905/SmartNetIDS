# End-to-end integration test for SmartNetIDS
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from scapy.all import Ether, IP, TCP, Raw  # type: ignore
from src.feature_extractor import extract_features
from src.ml_model import save_model, load_model, predict
from src.alert_logger import log_anomaly, get_log_file_path
import numpy as np
import tempfile
import os
import pytest


def test_end_to_end_pipeline():
    # Create a sample packet
    pkt = Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/TCP(sport=1234, dport=80, flags="S")/Raw(load=b"test")
    feats = extract_features(pkt, local_ip="10.0.0.1")
    # Train and save a dummy model
    X = np.random.normal(0, 1, (10, 12))
    from sklearn.ensemble import IsolationForest
    model = IsolationForest(contamination=0.1, random_state=42)  # type: ignore
    model.fit(X)
    with tempfile.NamedTemporaryFile(delete=False, suffix='.joblib') as tmp:
        save_model(model, tmp.name)
        loaded = load_model(tmp.name)
        # Prepare feature vector (pad/truncate to 12 features)
        feature_vector = [
            feats.get('length', 0),
            feats.get('protocol', 0) or 0,
            feats.get('src_port', 0) or 0,
            feats.get('dst_port', 0) or 0,
            feats.get('inter_arrival', 0.0),
            feats.get('entropy', 0.0),
            feats.get('tcp_flag_syn', 0),
            feats.get('tcp_flag_fin', 0),
            feats.get('tcp_flag_rst', 0),
            feats.get('tcp_flag_psh', 0),
            feats.get('tcp_flag_ack', 0),
            feats.get('tcp_flag_urg', 0),
        ]
        feature_vector = feature_vector[:12]
        pred = predict(loaded, feature_vector)[0]
        # Log anomaly if detected
        if pred == -1:
            log_anomaly(
                src_ip=feats.get('src_ip'),
                dst_ip=feats.get('dst_ip'),
                protocol=feats.get('protocol'),
                message="Integration test anomaly",
                extra={"test": True}
            )
    os.remove(tmp.name)
    # Check log file for entry
    log_path = get_log_file_path()
    with open(log_path, 'r') as f:
        lines = f.readlines()
    assert any("Integration test anomaly" in line for line in lines) 