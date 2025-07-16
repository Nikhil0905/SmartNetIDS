# Unit tests for alert_logger.py
import sys
import os
import tempfile
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from src.alert_logger import log_anomaly, get_log_file_path


def test_log_anomaly_to_file():
    # Use a temp log directory
    temp_dir = tempfile.mkdtemp()
    orig_log_dir = os.environ.get('SMARTNETIDS_LOG_DIR')
    os.environ['SMARTNETIDS_LOG_DIR'] = temp_dir
    # Log an anomaly
    log_anomaly(
        src_ip="1.2.3.4",
        dst_ip="5.6.7.8",
        protocol=6,
        message="Test anomaly for unit test",
        extra={"test": True}
    )
    # Check log file exists and contains the message
    log_path = get_log_file_path()
    with open(log_path, 'r') as f:
        lines = f.readlines()
    assert any("Test anomaly for unit test" in line for line in lines)
    # Clean up
    for f in os.listdir(temp_dir):
        os.remove(os.path.join(temp_dir, f))
    os.rmdir(temp_dir)
    if orig_log_dir is not None:
        os.environ['SMARTNETIDS_LOG_DIR'] = orig_log_dir
    else:
        del os.environ['SMARTNETIDS_LOG_DIR'] 