# Minimal REST API for SmartNetIDS alerts
# Run with: python src/alert_api.py

from flask import Flask, jsonify, request, abort
import os
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging

API_KEY = os.environ.get('SMARTNETIDS_API_KEY', 'changeme')

def read_recent_alerts(log_dir='data/logs', n=100):
    files = [
        f for f in os.listdir(log_dir)
        if f.startswith('anomaly_log_') and f.endswith('.txt')
    ]
    if not files:
        return []
    latest = sorted(files)[-1]
    with open(os.path.join(log_dir, latest), 'r') as f:
        lines = f.readlines()[-n:]
    return [line.strip() for line in lines]

app = Flask(__name__)

# --- Rate Limiting ---
limiter = Limiter(get_remote_address, app=app, default_limits=["10 per minute"])

# --- Audit Logging ---
AUDIT_LOG = os.path.join('data', 'audit.log')
logging.basicConfig(filename=AUDIT_LOG, level=logging.INFO, format='%(asctime)s %(message)s')

def audit_log(request, status):
    ip = request.remote_addr
    endpoint = request.path
    logging.info(f"IP={ip} ENDPOINT={endpoint} STATUS={status}")

# --- API key authentication ---
def require_api_key():
    key = request.args.get('key') or request.headers.get('X-API-KEY')
    if key != API_KEY:
        audit_log(request, 401)
        abort(401, description='Invalid or missing API key.')


@app.route('/alerts', methods=['GET'])
@limiter.limit("10 per minute")
def get_alerts():
    require_api_key()
    n = int(request.args.get('n', 100))
    alerts = read_recent_alerts(n=n)
    audit_log(request, 200)
    return jsonify({"alerts": alerts})


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True) 