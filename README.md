# SmartNetIDS

<div align="center">
  <h1>🛡️ SmartNetIDS</h1>
  <h3>A lightweight, modular, and intelligent Network Intrusion Detection System (NIDS) using machine learning</h3>
  <p><em>Real-time anomaly detection with ML-powered insights</em></p>
</div>

Designed for academic and research use, SmartNetIDS demonstrates real-time anomaly detection in network traffic with a focus on modularity, interpretability, and legal compliance.

## 🎨 Project Logo

SmartNetIDS features a dynamic Lottie animation logo that displays in the dashboard. The logo is stored locally as `assets/logo.json` and includes:
- **Animated cybersecurity icon** in the Streamlit dashboard
- **Fallback shield emoji** (🛡️) if animation fails to load
- **Consistent branding** across all project components

> **Note:** The logo appears as an animated icon in the dashboard interface, not as a static image in documentation.

## Features
- Real-time packet sniffing (Scapy)
- Feature extraction from network packets (including entropy, inter-arrival, flags, direction, etc.)
- ML-based anomaly detection (Isolation Forest)
- Detection of MITRE ATT&CK techniques (T1046, T1059, T1048, T1041)
- Logging and alerting of suspicious activities (console, file, syslog, REST API)
- **Modern web dashboard (Streamlit) with:**
  - Animated UI, Lottie, and vibrant themes
  - Advanced analytics: Sankey diagrams, geolocation maps, protocol/port stats, session/flow analysis, time-of-day patterns
  - Custom alert rule management (add, edit, enable/disable, delete, search/filter)
  - Live/auto-refresh controls, notifications, and accessibility features
  - Responsive/mobile-friendly layout
  - Theme selector (light/dark/cyber)
  - Manual anomaly simulator, PCAP replay, SIEM/export integration, automated reporting
- Model training and evaluation using open-source datasets (CIC-IDS 2017, NSL-KDD)
- REST API for alert retrieval
- Automated unit/integration tests

---

## 📸 Screenshots

Here's a glimpse of SmartNetIDS in action. All screenshots are available at: [https://github.com/Nikhil0905/SmartNetIDS/tree/main/assets/Screenshots](https://github.com/Nikhil0905/SmartNetIDS/tree/main/assets/Screenshots)

### Dashboard Home
The main dashboard provides an overview of anomaly statistics and recent alerts.
![Dashboard Home](https://github.com/Nikhil0905/SmartNetIDS/raw/main/assets/Screenshots/home.png)

### Network Flow Sankey Diagram
Visualize network traffic flow and connections, aiding in understanding data movement.
![Network Flow Diagram](https://github.com/Nikhil0905/SmartNetIDS/raw/main/assets/Screenshots/NetworkFlow.jpg)

### Analytics Overview
An in-depth look at anomaly type breakdowns, helping categorize and understand detected threats.
![Analytics Overview](https://github.com/Nikhil0905/SmartNetIDS/raw/main/assets/Screenshots/Analytics_1st.png)

### Source IP Geolocation Map
See the geographical distribution of suspicious source IPs on a world map.
![IP Geolocation Map](https://github.com/Nikhil0905/SmartNetIDS/raw/main/assets/Screenshots/IP_geoLocation.png)

### Code Snippet
A peek into the modular and well-structured codebase.
![Code Snippet](https://github.com/Nikhil0905/SmartNetIDS/raw/main/assets/Screenshots/Code.jpg)

---

## Quick Start Guide

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
5. **Run the Streamlit dashboard:**
   ```bash
   streamlit run src/dashboard.py
   ```
6. **(Optional) Run the REST API:**
   ```bash
   python src/alert_api.py
   # Access: http://localhost:5001/alerts?key=your_api_key
   ```
7. **(Optional) Run tests:**
   ```bash
   PYTHONPATH=./ pytest tests/
   ```

---

## Usage Examples

- **Packet Sniffing:**
  - Run the dashboard and enable detection to start live packet capture and anomaly detection.
- **Feature Extraction:**
  - Use `src/feature_extractor.py` or the dashboard to view extracted features for each packet.
- **Model Training:**
  - Run `python src/trainer.py` and select a dataset from the `datasets/` folder to train a new model.
- **Manual Anomaly Simulation:**
  - Use the dashboard sidebar to trigger a manual anomaly and test the alert pipeline.
- **PCAP Replay:**
  - Run `python src/pcap_replay.py yourfile.pcap --local_ip <your_ip>` to process a PCAP file through the detection pipeline.
- **Export Alerts:**
  - Download recent alerts as CSV/JSON from the Analytics tab for SIEM integration.
- **Automated Report:**
  - Run `python src/generate_report.py` to generate a Markdown report of recent detection activity.
- **Geolocation Map Controls:**
  - Click "Show Geolocation Map" in Home/Analytics, then choose color by alert type or protocol.
- **Custom Alert Rules:**
  - Use the sidebar to add, edit, enable/disable, or delete rules. Filter/search rules as needed.
- **Theme Selector & Accessibility:**
  - Switch between light/dark/cyber themes and enjoy improved accessibility and mobile support.

---

## Troubleshooting & FAQ

**Q: The dashboard asks for a password. How do I set it?**
A: Password authentication has been removed for ease of use. No password is required.

**Q: The REST API returns 401 Unauthorized.**
A: Pass your API key as a query parameter (`?key=...`) or `X-API-KEY` header. Set `SMARTNETIDS_API_KEY` in your environment.

**Q: The geolocation map disappears when changing color options.**
A: Click "Show Geolocation Map" again if needed. The map now persists after color changes.

**Q: Protocol coloring does not work.**
A: Ensure your alert logs contain protocol numbers (6 for TCP, 17 for UDP, etc.).

**Q: Tests fail with ModuleNotFoundError: No module named 'src'.**
A: Run tests with `PYTHONPATH=./ pytest tests/`.

**Q: How do I add new detection rules or features?**
A: See the `DetectionThread` class in `src/dashboard.py` and the feature extractor in `src/feature_extractor.py`.

**Q: Where are logs and models stored?**
A: Logs are in `data/logs/`, models in `data/models/`.

**Q: How do I convert the Markdown report to PDF?**
A: Use [Pandoc](https://pandoc.org/), VSCode, or Typora to export `smartnetids_report.md` as PDF.

---

## Legal & Ethical Notice
- Use only in controlled or simulated environments.
- Do not monitor unauthorized or public networks.
- No PII is collected or stored by default.

---
For more details, see the user manual in `docs/USER_MANUAL.md`.

## 🚀 Docker Usage

You can run SmartNetIDS in Docker for easy deployment. The container supports both the Streamlit dashboard and the Flask alert API.

### 1. Build the Docker image

```bash
docker build -t smartnetids .
```

### 2. Run the Streamlit Dashboard (default)

```bash
docker run -p 8501:8501 smartnetids
```

### 3. Run the Flask Alert API

```bash
docker run -e SERVICE=api -p 5001:5001 smartnetids
```

- The dashboard will be available at http://localhost:8501
- The API will be available at http://localhost:5001

You can mount your data directory for persistence:

```bash
docker run -p 8501:8501 -v $PWD/data:/app/data smartnetids
```

--- 
