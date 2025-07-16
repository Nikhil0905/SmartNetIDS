# SmartNetIDS User Manual

## Overview
SmartNetIDS is a modular, research-grade Network Intrusion Detection System (NIDS) that uses machine learning and rule-based logic to detect network anomalies in real time. It features a modern web dashboard, advanced analytics, and integration with SIEMs and APIs.

---

## Setup
1. **Clone the repository and navigate to the project directory.**
2. **Create and activate a Python virtual environment:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```
3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
4. **(Optional) Set API key for REST API:**
   ```bash
   export SMARTNETIDS_API_KEY='your_api_key'
   ```
5. **Run the dashboard:**
   ```bash
   streamlit run src/dashboard.py
   ```
6. **(Optional) Run the REST API:**
   ```bash
   python src/alert_api.py
   ```

---

## Dashboard Walkthrough

### Home Tab
- **Controls Sidebar:**
  - Select network interface, enable/disable detection, set anomaly threshold.
  - Manual anomaly simulator: trigger test alerts.
  - Model management: upload new model, view model info.
  - Theme selector: switch between light/dark/cyber themes.
  - Custom alert rules: add, edit, enable/disable, delete, search/filter rules.
- **Main Area:**
  - Animated header and Lottie animation.
  - Anomaly statistics: total anomalies, live updates.
  - Timeline chart: anomalies over time.
  - Recent alerts: filter/search, view details, explainability.
  - Live geolocation map: click "Show Geolocation Map" to display, color by alert type or protocol.

### Analytics Tab
- **Anomaly Type Breakdown:** Bar chart of ML-based and rule-based detections.
- **Protocol/Port Frequency:** Bar charts for protocol and port usage in anomalies.
- **Time-of-Day Patterns:** Line chart of anomalies by hour.
- **Geolocation Map:** Click "Show Geolocation Map" to display, then choose color by alert type or protocol.
- **Session/Flow Analysis:** Top source/destination IPs and flows.
- **Export:** Download recent alerts as CSV/JSON for SIEM integration.

> _[Update screenshots to reflect the latest UI. Placeholder: "Screenshots coming soon."]_ 

---

## Model Management
- Upload new `.joblib` models from the sidebar.
- View model metadata (file, last modified, contamination, feature count).
- Retrain models using `src/trainer.py` and datasets in `datasets/`.

---

## PCAP Replay
- Run `python src/pcap_replay.py yourfile.pcap --local_ip <your_ip>` to process a PCAP file through the detection pipeline.
- Alerts are logged and appear in the dashboard and analytics.

---

## REST API Usage
- Start the API: `python src/alert_api.py`
- Access recent alerts:
  - `http://localhost:5001/alerts?key=your_api_key`
  - Or use the `X-API-KEY` header.

---

## Automated Reporting
- Run `python src/generate_report.py` to create a Markdown report of recent detection activity.
- Convert to PDF using Pandoc, VSCode, or Typora.

---

## Troubleshooting
- **Dashboard asks for password:** Password authentication has been removed. No password is required.
- **API returns 401:** Use the correct API key as a query parameter or header.
- **Geolocation map disappears when changing color:** The map now persists after color changes. Click "Show Geolocation Map" if needed.
- **Protocol coloring not working:** Ensure your alert logs contain protocol numbers (6 for TCP, 17 for UDP, etc.).
- **Tests fail with import errors:** Run with `PYTHONPATH=./ pytest tests/`.
- **Syslog not working:** Check `src/alert_logger.py` settings and your syslog server.
- **No alerts detected:** Ensure detection is enabled and traffic is present.

---

## Security & Ethical Notes
- Use only in controlled or simulated environments.
- Do not monitor unauthorized or public networks.
- No PII is collected or stored by default.
- All detection logic is transparent and documented.

---

## Developer Notes
- Add new detection rules in `DetectionThread` (`src/dashboard.py`).
- Add new features to the feature extractor (`src/feature_extractor.py`).
- Extend analytics in the dashboard as needed.
- Run and extend tests in the `tests/` directory.

---

## Contact & Support
For questions, issues, or contributions, please open an issue or pull request on the project repository. 

---

## Common Workflows

### 1. Training a New Model
- Prepare your dataset (CSV with features, or use the provided feature extraction script).
- Run the trainer:
  ```bash
  python src/trainer.py
  ```
- Select your dataset from the list.
- (Optional) Enter the label column for supervised training.
- Set the contamination parameter (proportion of anomalies).
- The model is trained and saved to `data/models/isolation_forest.joblib`.

### 2. Running Live Detection
- Start the dashboard:
  ```bash
  streamlit run src/dashboard.py
  ```
- Select the network interface and enable detection in the sidebar.
- Monitor real-time stats, alerts, and analytics.

### 3. Investigating Anomalies
- Use the Recent Alerts section to filter/search for specific IPs, ports, or keywords.
- Click on alerts to view details and top contributing features (explainability).
- Use the Analytics tab to see breakdowns, top talkers, and time-of-day patterns.

### 4. Replaying a PCAP File
- Run the PCAP replay script:
  ```bash
  python src/pcap_replay.py yourfile.pcap --local_ip <your_ip>
  ```
- Alerts from the replay will be logged and appear in the dashboard and analytics.

### 5. Exporting and Reporting
- Download recent alerts as CSV/JSON from the Analytics tab for SIEM or further analysis.
- Generate a Markdown report:
  ```bash
  python src/generate_report.py
  ```
- Convert the report to PDF using Pandoc, VSCode, or Typora.

### 6. Integrating with SIEM/API
- Enable syslog export in `src/alert_logger.py` and configure your SIEM to receive alerts.
- Start the REST API:
  ```bash
  python src/alert_api.py
  ```
- Access alerts via:
  - `http://localhost:5001/alerts?key=your_api_key`
  - Or use the `X-API-KEY` header.

--- 