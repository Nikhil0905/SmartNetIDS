# Streamlit dashboard module for SmartNetIDS
# Provides a web-based interface for monitoring and control

import streamlit as st
import os
from datetime import datetime
import threading
import time
from collections import Counter
import pandas as pd
from scapy.all import get_if_list
from feature_extractor import extract_features
from ml_model import load_model, predict
from alert_logger import log_anomaly
import collections
import re
import requests
import json
import tempfile
import joblib
import psutil
import plotly.graph_objects as go
from streamlit_extras.stylable_container import stylable_container
from streamlit_option_menu import option_menu
from streamlit_modal import Modal
from streamlit_lottie import st_lottie

# --- Ensure session state keys are initialized ---
if 'model' not in st.session_state:
    st.session_state['model'] = None

# --- Shared color palettes for anomaly types and protocols ---
ANOMALY_TYPE_COLORS = {
    'ML-based': '#00bfff',
    'Port Scan': '#ff512f',
    'Protocol Violation': '#f7971e',
    'DNS Tunneling': '#36d1c4',
    'Data Exfiltration': '#dd2476',
    'Manual': '#43e97b',
}
PROTOCOL_COLORS = {
    '6': '#5b86e5',  # TCP
    '17': '#43e97b',  # UDP
    '1': '#ffd200',  # ICMP
}

def load_lottie_url(url):
    r = requests.get(url)
    if r.status_code == 200:
        return r.json()
    return None

def load_lottie_file(file_path):
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except Exception:
        return None

# --- Alert log reading utility ---
LOG_DIR = os.path.join('data', 'logs')
LOG_FILE_TEMPLATE = 'anomaly_log_{date}.txt'

def get_log_file_path():
    date_str = datetime.now().strftime('%Y-%m-%d')
    return os.path.join(LOG_DIR, LOG_FILE_TEMPLATE.format(date=date_str))


def read_recent_alerts(n=20):
    log_path = get_log_file_path()
    if not os.path.exists(log_path):
        return ["No alerts logged yet."]
    with open(log_path, 'r') as f:
        lines = f.readlines()
    return lines[-n:] if lines else ["No alerts logged yet."]


# --- Anomaly statistics and timeline ---
def parse_alert_timestamps():
    log_path = get_log_file_path()
    if not os.path.exists(log_path):
        return []
    timestamps = []
    with open(log_path, 'r') as f:
        for line in f:
            if line.startswith('['):
                try:
                    ts_str = line.split(']')[0][1:]
                    ts = datetime.strptime(ts_str, '%Y-%m-%d %H:%M:%S')
                    timestamps.append(ts)
                except Exception:
                    continue
    return timestamps


def get_anomaly_stats():
    timestamps = parse_alert_timestamps()
    total = len(timestamps)
    if not timestamps:
        return 0, pd.Series(dtype=int)
    minute_bins = [ts.replace(second=0) for ts in timestamps]
    counts = Counter(minute_bins)
    series = pd.Series(counts).sort_index()
    return total, series


# --- Live Detection Thread Management ---
class DetectionThread(threading.Thread):
    def __init__(self, interface, threshold, model, local_ip=None):
        super().__init__()
        self.interface = interface
        self.threshold = threshold
        self.model = model
        self.local_ip = local_ip
        self._stop_event = threading.Event()
        # State for rule-based detection
        self.port_scan_tracker = collections.defaultdict(list)  # src_ip -> list of (timestamp, dst_port)
        self.dns_query_tracker = collections.defaultdict(list)  # src_ip -> list of timestamps
        self.custom_rule_state = {}

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()

    def packet_callback(self, packet):
        features = extract_features(packet, local_ip=self.local_ip)
        now = datetime.now()
        # --- Rule-based: Port Scanning (MITRE T1046) ---
        if features.get('src_ip') and features.get('dst_port'):
            self.port_scan_tracker[features['src_ip']].append((now, features['dst_port']))
            self.port_scan_tracker[features['src_ip']] = [
                (t, p) for t, p in self.port_scan_tracker[features['src_ip']] if (now - t).total_seconds() < 10
            ]
            unique_ports = set(p for t, p in self.port_scan_tracker[features['src_ip']])
            if len(unique_ports) > 10:  # Heuristic: >10 ports in 10s
                log_anomaly(
                    src_ip=features['src_ip'],
                    dst_ip=features['dst_ip'],
                    protocol=features['protocol'],
                    message="Port scan detected (rule-based, MITRE T1046)",
                    extra={"unique_ports": list(unique_ports), "mitre_id": "T1046"}
                )
                self.port_scan_tracker[features['src_ip']] = []
        # --- Rule-based: Protocol Violations (SYN+FIN, MITRE T1059) ---
        if features.get('tcp_flag_syn') and features.get('tcp_flag_fin'):
            if features['tcp_flag_syn'] == 1 and features['tcp_flag_fin'] == 1:
                log_anomaly(
                    src_ip=features['src_ip'],
                    dst_ip=features['dst_ip'],
                    protocol=features['protocol'],
                    message="Protocol violation: SYN+FIN set (rule-based, MITRE T1059)",
                    extra={"tcp_flags": features.get('tcp_flags'), "mitre_id": "T1059"}
                )
        # --- Rule-based: DNS Tunneling (MITRE T1048) ---
        if features.get('protocol') == 17 and features.get('dst_port') == 53 and features.get('src_ip'):
            self.dns_query_tracker[features['src_ip']].append(now)
            self.dns_query_tracker[features['src_ip']] = [
                t for t in self.dns_query_tracker[features['src_ip']] if (now - t).total_seconds() < 60
            ]
            if len(self.dns_query_tracker[features['src_ip']]) > 100:  # Heuristic: >100 DNS queries/min
                log_anomaly(
                    src_ip=features['src_ip'],
                    dst_ip=features['dst_ip'],
                    protocol=features['protocol'],
                    message="DNS tunneling suspected: high query rate (rule-based, MITRE T1048)",
                    extra={"dns_queries_last_min": len(self.dns_query_tracker[features['src_ip']]), "mitre_id": "T1048"}
                )
                self.dns_query_tracker[features['src_ip']] = []
        # --- Rule-based: Data Exfiltration (MITRE T1041) ---
        if features.get('direction') == 'outbound' and features.get('length', 0) > 1500:
            log_anomaly(
                src_ip=features['src_ip'],
                dst_ip=features['dst_ip'],
                protocol=features['protocol'],
                message="Data exfiltration suspected: large outbound packet (rule-based, MITRE T1041)",
                extra={"length": features.get('length'), "mitre_id": "T1041"}
            )
        # --- ML-based detection ---
        feature_vector = [
            features.get('length', 0),
            features.get('protocol', 0) or 0,
            features.get('src_port', 0) or 0,
            features.get('dst_port', 0) or 0,
            features.get('inter_arrival', 0.0),
            features.get('entropy', 0.0),
            features.get('tcp_flag_syn', 0),
            features.get('tcp_flag_fin', 0),
            features.get('tcp_flag_rst', 0),
            features.get('tcp_flag_psh', 0),
            features.get('tcp_flag_ack', 0),
            features.get('tcp_flag_urg', 0),
        ]
        if self.model:
            pred = predict(self.model, feature_vector)[0]
            if pred == -1:
                log_anomaly(
                    src_ip=features.get('src_ip'),
                    dst_ip=features.get('dst_ip'),
                    protocol=features.get('protocol'),
                    message=f"Anomaly detected (score: N/A)",
                    extra={
                        'length': features.get('length'),
                        'inter_arrival': features.get('inter_arrival'),
                        'entropy': features.get('entropy'),
                        'direction': features.get('direction'),
                        'tcp_flags': features.get('tcp_flags'),
                        'src_port': features.get('src_port'),
                        'dst_port': features.get('dst_port')
                    }
                )

        # --- Custom Rule Evaluation ---
        custom_alerts = evaluate_custom_rules(features, now, self.custom_rule_state)
        for msg in custom_alerts:
            log_anomaly(src_ip=features.get('src_ip'), dst_ip=features.get('dst_ip'), protocol=features.get('protocol'), message=msg, extra={'custom_rule':True})

    def run(self):
        from scapy.all import sniff
        sniff(prn=self.packet_callback, iface=self.interface, store=0, stop_filter=lambda x: self.stopped())

# Helper for explainability
FEATURE_NAMES = [
    'length', 'protocol', 'src_port', 'dst_port', 'inter_arrival', 'entropy',
    'tcp_flag_syn', 'tcp_flag_fin', 'tcp_flag_rst', 'tcp_flag_psh', 'tcp_flag_ack', 'tcp_flag_urg'
]

def explain_anomaly(alert_line, model):
    """
    Extract feature values from alert line and return top contributing features.
    Uses Isolation Forest feature_importances_ if available, else largest absolute value.
    """
    # Try to extract feature values from the alert line (simple regex for key: value)
    features = {}
    for fname in FEATURE_NAMES:
        match = re.search(rf"'{fname}': ([^,}}]+)", alert_line)
        if match:
            try:
                features[fname] = float(match.group(1))
            except Exception:
                continue
    if not features:
        return None
    # Use model feature_importances_ if available
    if hasattr(model, 'feature_importances_'):
        importances = model.feature_importances_
        sorted_feats = sorted(zip(FEATURE_NAMES, importances), key=lambda x: -x[1])
        top_feats = [f"{name} (importance: {imp:.2f})" for name, imp in sorted_feats[:3]]
        return top_feats

# --- Streamlit UI ---
st.set_page_config(page_title="SmartNetIDS Dashboard", layout="wide")

# (Password authentication removed)

# Tabs for Home and Analytics
home_tab, analytics_tab = st.tabs(["Home", "Analytics"])

# --- Responsive CSS for mobile/tablet ---
st.markdown('''
<style>
@media (max-width: 900px) {
    .rule-card, .stColumn, .stDataFrame, .stPlotlyChart, .stButton>button, .stDownloadButton>button {
        width: 100% !important;
        min-width: 0 !important;
        max-width: 100vw !important;
        font-size: 1em !important;
    }
    .rule-card {
        padding: 0.7rem 0.7rem 0.7rem 0.7rem;
    }
    .stSidebar, .sidebar-content {
        width: 100vw !important;
        min-width: 0 !important;
    }
    .stApp {
        padding: 0 !important;
    }
    .stTabs {
        flex-direction: column !important;
    }
}
@media (max-width: 600px) {
    .rule-card, .stColumn, .stDataFrame, .stPlotlyChart {
        font-size: 0.95em !important;
    }
    .stButton>button, .stDownloadButton>button {
        font-size: 1.1em !important;
        padding: 0.7em 1.2em !important;
    }
}
</style>
''', unsafe_allow_html=True)

with home_tab:
    # Sidebar controls and main dashboard (existing code)
    st.sidebar.title("SmartNetIDS Controls")
    # --- Project Title and Animation ---
    col_logo, col_title = st.columns([1, 6])
    with col_logo:
        # Try local logo first, fallback to external URL
        lottie_cyber = load_lottie_file("assets/logo.json")
        if lottie_cyber is None:
            lottie_cyber = load_lottie_url("https://assets2.lottiefiles.com/packages/lf20_4kx2q32n.json")
        if lottie_cyber is not None:
            st_lottie(lottie_cyber, height=80, key="cyber_lottie_home")
        else:
            st.markdown("<span style='font-size:2.5em;'>🛡️</span>", unsafe_allow_html=True)
    with col_title:
        st.markdown("<h1 style='margin-bottom:0;'>SmartNetIDS <span style='color:#00bfff;'>Dashboard</span></h1>", unsafe_allow_html=True)
        st.caption("Network Intrusion Detection & Analytics Platform")
    # --- Improved SmartNetIDS Controls Sidebar ---
    st.sidebar.markdown("""
<style>
.control-section-title {
    font-size: 1.1em;
    font-weight: 700;
    margin-top: 1.2em;
    margin-bottom: 0.3em;
    color: #00bfff;
    letter-spacing: 0.5px;
    display: flex;
    align-items: center;
    gap: 0.5em;
}
.status-badge {
    display: inline-block;
    border-radius: 8px;
    padding: 0.2em 0.8em;
    font-size: 0.95em;
    font-weight: 600;
    background: linear-gradient(90deg, #43e97b 0%, #38f9d7 100%);
    color: #222;
    margin-left: 0.5em;
}
.status-badge.inactive {
    background: linear-gradient(90deg, #f7971e 0%, #ffd200 100%);
    color: #222;
}
</style>
""", unsafe_allow_html=True)

    st.sidebar.markdown('<div class="control-section-title">🛡️ Detection Controls</div>', unsafe_allow_html=True)
    interfaces = get_if_list()
    interface = st.sidebar.selectbox("Select Interface", interfaces, help="Choose the network interface to monitor.")
    detection_enabled = st.sidebar.checkbox("Enable Detection", value=False, help="Toggle real-time anomaly detection on/off.")
    if detection_enabled:
        st.sidebar.markdown('<span class="status-badge">ACTIVE</span>', unsafe_allow_html=True)
    else:
        st.sidebar.markdown('<span class="status-badge inactive">INACTIVE</span>', unsafe_allow_html=True)
    threshold = st.sidebar.slider("Anomaly Threshold", min_value=0.0, max_value=1.0, value=0.5, step=0.01, help="Adjust the sensitivity of anomaly detection.")
    local_ip = st.sidebar.text_input("Local IP (for direction)", value="", help="Specify your local IP to help classify traffic direction.")

    st.sidebar.markdown('<div class="control-section-title">🧠 Model Management</div>', unsafe_allow_html=True)
    if st.sidebar.button("Load Model", help="Load the current ML model for detection."):
        st.sidebar.success("Model loaded (placeholder)")
    uploaded_model = st.sidebar.file_uploader("Upload New Model (.joblib)", type=["joblib"], help="Upload a new trained model file.")
    if uploaded_model is not None:
        with st.spinner("Loading new model..."):
            with tempfile.NamedTemporaryFile(delete=False, suffix=".joblib") as tmp:
                tmp.write(uploaded_model.read())
                tmp_path = tmp.name
            try:
                new_model = joblib.load(tmp_path)
                st.session_state['model'] = new_model
                st.sidebar.success("New model loaded and in use!")
                joblib.dump(new_model, os.path.join('data', 'models', 'isolation_forest.joblib'))
            except Exception as e:
                st.sidebar.error(f"Failed to load model: {e}")
            os.remove(tmp_path)
    model_path = os.path.join('data', 'models', 'isolation_forest.joblib')
    st.sidebar.markdown("**Current Model Info:**")
    if os.path.exists(model_path):
        st.sidebar.write(f"File: isolation_forest.joblib")
        st.sidebar.write(f"Last Modified: {os.path.getmtime(model_path):.0f}")
        try:
            model = joblib.load(model_path)
            if hasattr(model, 'contamination'):
                st.sidebar.write(f"Contamination: {model.contamination}")
            if hasattr(model, 'n_features_in_'):
                st.sidebar.write(f"Feature Count: {model.n_features_in_}")
        except Exception:
            st.sidebar.write("(Could not read model metadata)")
    else:
        st.sidebar.write("No model file found.")

    st.sidebar.markdown('<div class="control-section-title">⚡ Manual Anomaly Simulator</div>', unsafe_allow_html=True)
    sim_src_ip = st.sidebar.text_input("Simulated Src IP", value="192.168.1.100", help="Source IP for manual anomaly.")
    sim_dst_ip = st.sidebar.text_input("Simulated Dst IP", value="8.8.8.8", help="Destination IP for manual anomaly.")
    sim_protocol = st.sidebar.selectbox("Simulated Protocol", [6, 17], format_func=lambda x: f"{x} (TCP)" if x==6 else f"{x} (UDP)", help="Protocol for manual anomaly.")
    sim_message = st.sidebar.text_input("Alert Message", value="Manual anomaly simulation", help="Message for the manual anomaly alert.")
    if st.sidebar.button("Trigger Manual Anomaly", help="Log a manual anomaly event."):
        log_anomaly(
            src_ip=sim_src_ip,
            dst_ip=sim_dst_ip,
            protocol=sim_protocol,
            message=sim_message,
            extra={"manual": True}
        )
        st.sidebar.success("Manual anomaly triggered! Check Recent Alerts.")

    st.sidebar.markdown('<div class="control-section-title">🖥️ Resource Usage</div>', unsafe_allow_html=True)
    cpu = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    st.sidebar.metric('CPU Usage (%)', f'{cpu:.1f}')
    st.sidebar.metric('Memory Usage (%)', f'{mem.percent:.1f}')
    # Main dashboard (existing code)
    col1, col2 = st.columns(2)
    total_anomalies, timeline_series = get_anomaly_stats()
    with col1:
        st.header("Anomaly Statistics")
        # Animated counter for Total Anomalies Today
        anomaly_placeholder = st.empty()
        for i in range(total_anomalies + 1):
            anomaly_placeholder.metric("Total Anomalies Today", i)
            time.sleep(0.02)
        st.caption("Updates live as new anomalies are detected.")
    with col2:
        st.header("Timeline Chart")
        if not timeline_series.empty:
            st.line_chart(timeline_series)
        else:
            st.info("No anomalies detected yet today.")
    st.header("Recent Alerts")
    search_term = st.text_input("Search/Filter Alerts", value="", help="Filter alerts by IP, port, protocol, or keyword.")
    recent_alerts = read_recent_alerts(100)
    filtered_alerts = [a for a in recent_alerts if search_term.lower() in a.lower()]
    first_five = filtered_alerts[:5]
    rest = filtered_alerts[5:]
    if first_five:
        for alert in first_five:
            st.code(alert, language=None)
            if 'Anomaly detected' in alert:
                top_feats = explain_anomaly(alert, st.session_state['model'])
                if top_feats:
                    st.caption(f"Top contributing features: {', '.join(top_feats)}")
    if rest:
        with st.expander("Show more alerts", expanded=False):
            for alert in rest:
                st.code(alert, language=None)
                if 'Anomaly detected' in alert:
                    top_feats = explain_anomaly(alert, st.session_state['model'])
                    if top_feats:
                        st.caption(f"Top contributing features: {', '.join(top_feats)}")
    if not filtered_alerts:
        st.info("No alerts match your search.")
    st.markdown("---")
    st.markdown("Developed for academic and research use. See README for details.")

    # --- Home Tab: Live Geolocation Map for Recent Alerts ---
    st.header("Live Source IP Geolocation Map")
    show_map = st.button("Show Geolocation Map", key="show_home_map")
    if show_map:
        with st.spinner("Loading live geolocation map..."):
            live_geo_points = []
            live_src_ips = set()
            live_alert_info = {}
            for alert in recent_alerts[-30:]:
                match = re.search(r"src_ip=([\d\.]+)|'src_ip': '([\d\.]+)'", alert)
                proto_match = re.search(r"protocol: ([0-9]+)", alert, re.IGNORECASE)
                type_label = None
                if 'Anomaly detected' in alert:
                    type_label = 'ML-based'
                elif 'Port scan detected' in alert:
                    type_label = 'Port Scan'
                elif 'Protocol violation' in alert:
                    type_label = 'Protocol Violation'
                elif 'DNS tunneling' in alert:
                    type_label = 'DNS Tunneling'
                elif 'Data exfiltration' in alert:
                    type_label = 'Data Exfiltration'
                elif 'manual' in alert.lower():
                    type_label = 'Manual'
                if match:
                    ip = match.group(1) or match.group(2)
                    if ip and ip != 'None':
                        live_src_ips.add(ip)
                        live_alert_info[ip] = {
                            'type': type_label or 'Unknown',
                            'protocol': proto_match.group(1) if proto_match else 'Unknown',
                            'alert': alert.strip()
                        }
            live_src_ips = list(live_src_ips)[:30]
            live_geo_cache = {}
            for ip in live_src_ips:
                if ip in live_geo_cache:
                    lat, lon = live_geo_cache[ip]
                else:
                    try:
                        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
                        data = resp.json()
                        if data['status'] == 'success':
                            lat, lon = data['lat'], data['lon']
                            live_geo_cache[ip] = (lat, lon)
                        else:
                            continue
                    except Exception:
                        continue
                info = live_alert_info.get(ip, {})
                color = ANOMALY_TYPE_COLORS.get(info.get('type'), '#00bfff')
                hover = f"<b>{ip}</b><br>Type: {info.get('type')}<br>Protocol: {info.get('protocol')}<br><span style='font-size:0.9em;'>{info.get('alert','')}</span>"
                live_geo_points.append({'ip': ip, 'lat': lat, 'lon': lon, 'color': color, 'hover': hover})
            if live_geo_points:
                fig = go.Figure(go.Scattermapbox(
                    lat=[p['lat'] for p in live_geo_points],
                    lon=[p['lon'] for p in live_geo_points],
                    mode='markers',
                    marker=go.scattermapbox.Marker(size=13, color=[p['color'] for p in live_geo_points]),
                    text=[p['hover'] for p in live_geo_points],
                    hoverinfo='text',
                ))
                fig.update_layout(
                    mapbox_style="open-street-map",
                    mapbox_zoom=1.2,
                    mapbox_center={"lat": 20, "lon": 0},
                    margin={"r":0,"t":0,"l":0,"b":0},
                    paper_bgcolor="#232526",
                    plot_bgcolor="#232526"
                )
                st.plotly_chart(fig, use_container_width=True)
                st.caption("Live map of source IPs from recent alerts, color-coded by alert type (max 30, demo only, uses ip-api.com)")
            else:
                st.info("No geolocatable source IPs found in recent alerts.")

with analytics_tab:
    st.write("Analytics tab loaded")
    # --- Animated Title and Lottie Animation (Analytics) ---
    st.markdown("<style>.lottie-container {display: flex; align-items: center; justify-content: flex-start; gap: 1rem;}</style>", unsafe_allow_html=True)
    col_logo, col_title = st.columns([1, 6])
    with col_logo:
        # Try local logo first, fallback to external URL
        lottie_cyber = load_lottie_file("assets/logo.json")
        if lottie_cyber is None:
            lottie_cyber = load_lottie_url("https://assets2.lottiefiles.com/packages/lf20_4kx2q32n.json")
        if lottie_cyber is not None:
            st_lottie(
                lottie_cyber,
                height=80,
                key="cyber_lottie_analytics"
            )
        else:
            st.markdown("<span style='font-size:2.5em;'>🛡️</span>", unsafe_allow_html=True)
    with col_title:
        st.markdown("<h1 style='margin-bottom:0;'>SmartNetIDS: <span style='color:#00bfff;'>Analytics</span></h1>", unsafe_allow_html=True)
        st.caption("Deep dive into anomaly types, flows, and geolocation patterns.")
    # --- Add custom color palettes for charts ---
    # ANOMALY_TYPE_COLORS and PROTOCOL_COLORS are now defined globally

    # --- Improved bar chart for anomaly types ---
    st.header("Anomaly Type Breakdown")
    recent_alerts = read_recent_alerts(500)
    type_counts = {
        'ML-based': 0,
        'Port Scan': 0,
        'Protocol Violation': 0,
        'DNS Tunneling': 0,
        'Data Exfiltration': 0,
        'Manual': 0
    }
    for alert in recent_alerts:
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
    # Custom color bar chart
    import plotly.graph_objects as go
    fig = go.Figure(data=[go.Bar(
        x=list(type_counts.keys()),
        y=list(type_counts.values()),
        marker_color=[ANOMALY_TYPE_COLORS[k] for k in type_counts.keys()]
    )])
    fig.update_layout(
        xaxis_title="Anomaly Type",
        yaxis_title="Count",
        plot_bgcolor="#232526",
        paper_bgcolor="#232526",
        font_color="#fff",
        margin=dict(l=10, r=10, t=30, b=10)
    )
    st.plotly_chart(fig, use_container_width=True)
    st.caption("Breakdown of anomaly types detected in recent alerts.")
    st.header("Protocol Frequency in Anomalies")
    protocol_counts = {}
    for alert in recent_alerts:
        # Protocol extraction
        proto_match = re.search(r"protocol: ([0-9]+)", alert, re.IGNORECASE)
        if proto_match:
            proto = proto_match.group(1)
            protocol_counts[proto] = protocol_counts.get(proto, 0) + 1
    if protocol_counts:
        st.bar_chart(protocol_counts)
    else:
        st.info("No protocol data found in recent alerts.")
    st.header("Destination Port Frequency in Anomalies")
    port_counts = {}
    for alert in recent_alerts:
        # Port extraction (dst_port preferred)
        port_match = re.search(r"dst_port': ([0-9]+)", alert)
        if port_match:
            port = port_match.group(1)
            port_counts[port] = port_counts.get(port, 0) + 1
    if port_counts:
        st.bar_chart(port_counts)
    else:
        st.info("No port data found in recent alerts.")

    # --- Time-of-Day Anomaly Pattern ---
    st.header("Anomalies by Hour of Day")
    hour_counts = {str(h): 0 for h in range(24)}
    for alert in recent_alerts:
        # Extract timestamp in format [YYYY-MM-DD HH:MM:SS]
        ts_match = re.match(r"\[(\d{4}-\d{2}-\d{2} \d{2}):(\d{2}):(\d{2})\]", alert)
        if ts_match:
            hour = ts_match.group(1)[-2:]
            hour_counts[hour] = hour_counts.get(hour, 0) + 1
    st.line_chart([hour_counts[str(h)] for h in range(24)])
    st.caption("Number of anomalies detected per hour of the day (from recent alerts).")

    # --- Sankey Diagram for Flows ---
    st.header("Network Flow Sankey Diagram")
    flow_counter = Counter()
    for alert in recent_alerts:
        src_match = re.search(r"src_ip=([\d\.]+)|'src_ip': '([\d\.]+)'", alert)
        dst_match = re.search(r"dst_ip=([\d\.]+)|'dst_ip': '([\d\.]+)'", alert)
        src_ip = src_match.group(1) or src_match.group(2) if src_match else None
        dst_ip = dst_match.group(1) or dst_match.group(2) if dst_match else None
        if src_ip and dst_ip and src_ip != 'None' and dst_ip != 'None':
            flow_counter[(src_ip, dst_ip)] += 1
    if flow_counter:
        src_ips = [src for (src, dst) in flow_counter.keys()]
        dst_ips = [dst for (src, dst) in flow_counter.keys()]
        all_ips = list(set(src_ips + dst_ips))
        label_map = {ip: i for i, ip in enumerate(all_ips)}
        sankey_data = dict(
            type='sankey',
            node=dict(
                pad=15,
                thickness=20,
                line=dict(color="black", width=0.5),
                label=all_ips
            ),
            link=dict(
                source=[label_map[src] for (src, dst) in flow_counter.keys()],
                target=[label_map[dst] for (src, dst) in flow_counter.keys()],
                value=list(flow_counter.values())
            )
        )
        fig = go.Figure(data=[sankey_data])
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No flow data available for Sankey diagram.")
    # --- Analytics Tab: Enhanced Geolocation Map ---
    st.header("Source IP Geolocation Map (Plotly)")
    if st.button("Show Geolocation Map", key="show_analytics_map_btn"):
        st.session_state['show_analytics_map'] = True

    if st.session_state.get('show_analytics_map', False):
        with st.spinner("Loading analytics geolocation map..."):
            st.radio("Color markers by:", ["Alert Type", "Protocol"], key="geo_color_by", horizontal=True)
            geo_points = []
            src_ips = set()
            alert_info = {}
            protocol_debug = []  # Debug: collect protocol values
            for alert in recent_alerts:
                match = re.search(r"src_ip=([\d\.]+)|'src_ip': '([\d\.]+)'", alert)
                # Robust protocol extraction
                proto_match = re.search(r"protocol[:=']? ?([0-9]+)", alert, re.IGNORECASE)
                protocol_str = proto_match.group(1) if proto_match else 'Unknown'
                protocol_debug.append(protocol_str)  # Debug: collect protocol
                type_label = None
                if 'Anomaly detected' in alert:
                    type_label = 'ML-based'
                elif 'Port scan detected' in alert:
                    type_label = 'Port Scan'
                elif 'Protocol violation' in alert:
                    type_label = 'Protocol Violation'
                elif 'DNS tunneling' in alert:
                    type_label = 'DNS Tunneling'
                elif 'Data exfiltration' in alert:
                    type_label = 'Data Exfiltration'
                elif 'manual' in alert.lower():
                    type_label = 'Manual'
                if match:
                    ip = match.group(1) or match.group(2)
                    if ip and ip != 'None':
                        src_ips.add(ip)
                        alert_info[ip] = {
                            'type': type_label or 'Unknown',
                            'protocol': protocol_str,
                            'alert': alert.strip()
                        }
            src_ips = list(src_ips)[:50]
            geo_cache = {}
            for ip in src_ips:
                if ip in geo_cache:
                    lat, lon = geo_cache[ip]
                else:
                    try:
                        resp = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
                        data = resp.json()
                        if data['status'] == 'success':
                            lat, lon = data['lat'], data['lon']
                            geo_cache[ip] = (lat, lon)
                        else:
                            continue
                    except Exception:
                        continue
                info = alert_info.get(ip, {})
                if st.session_state.get('geo_color_by', 'Alert Type') == 'Protocol':
                    proto_str = str(info.get('protocol', ''))
                    color = PROTOCOL_COLORS.get(proto_str, '#5b86e5')
                else:
                    color = ANOMALY_TYPE_COLORS.get(info.get('type'), '#00bfff')
                hover = f"<b>{ip}</b><br>Type: {info.get('type')}<br>Protocol: {info.get('protocol')}<br><span style='font-size:0.9em;'>{info.get('alert','')}</span>"
                geo_points.append({'ip': ip, 'lat': lat, 'lon': lon, 'color': color, 'hover': hover})
            # Remove debug output
            # st.write('Extracted protocol values:', protocol_debug)
            # st.write('geo_points:', geo_points)
            # if not geo_points:
            #     st.warning('No geo_points generated! Check protocol extraction and IP geolocation.')
            if geo_points:
                fig = go.Figure(go.Scattermapbox(
                    lat=[p['lat'] for p in geo_points],
                    lon=[p['lon'] for p in geo_points],
                    mode='markers',
                    marker=go.scattermapbox.Marker(size=13, color=[p['color'] for p in geo_points]),
                    text=[p['hover'] for p in geo_points],
                    hoverinfo='text',
                ))
                fig.update_layout(
                    mapbox_style="open-street-map",
                    mapbox_zoom=1.2,
                    mapbox_center={"lat": 20, "lon": 0},
                    margin={"r":0,"t":0,"l":0,"b":0},
                    paper_bgcolor="#232526",
                    plot_bgcolor="#232526"
                )
                st.plotly_chart(fig, use_container_width=True)
                st.caption("Map of source IPs from recent anomalies, color-coded by alert type or protocol (max 50, demo only, uses ip-api.com)")
            else:
                st.info("No geolocatable source IPs found in recent alerts.")

    # --- Session/Flow Analysis ---
    st.header("Session/Flow Analysis")
    src_counter = Counter()
    dst_counter = Counter()
    flow_counter = Counter()
    for alert in recent_alerts:
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
    # Top 10 source IPs
    st.subheader("Top Source IPs (by anomaly count)")
    if src_counter:
        st.dataframe(
            {"Source IP": [ip for ip, _ in src_counter.most_common(10)],
             "Anomaly Count": [count for _, count in src_counter.most_common(10)]}
        )
    else:
        st.info("No source IPs found in recent alerts.")
    # Top 10 destination IPs
    st.subheader("Top Destination IPs (by anomaly count)")
    if dst_counter:
        st.dataframe(
            {"Destination IP": [ip for ip, _ in dst_counter.most_common(10)],
             "Anomaly Count": [count for _, count in dst_counter.most_common(10)]}
        )
    else:
        st.info("No destination IPs found in recent alerts.")
    # Top 10 flows
    st.subheader("Top Flows (src_ip → dst_ip, by anomaly count)")
    if flow_counter:
        st.dataframe(
            {"Source IP": [src for (src, dst), _ in flow_counter.most_common(10)],
             "Destination IP": [dst for (src, dst), _ in flow_counter.most_common(10)],
             "Anomaly Count": [count for _, count in flow_counter.most_common(10)]}
        )
    else:
        st.info("No flows found in recent alerts.")

    # --- Export Alerts as CSV/JSON ---
    st.header("Export Recent Alerts")
    # Parse recent alerts into a DataFrame (split on | and key: value pairs)
    alert_records = []
    for alert in recent_alerts:
        record = {"raw": alert.strip()}
        # Try to extract key-value pairs
        for match in re.finditer(r"(\w+): ([^|]+)", alert):
            k, v = match.group(1), match.group(2).strip()
            record[k] = v
        alert_records.append(record)
    df_alerts = pd.DataFrame(alert_records)
    # Download as CSV
    csv_bytes = df_alerts.to_csv(index=False).encode('utf-8')
    st.download_button("Download Alerts as CSV", data=csv_bytes, file_name="smartnetids_alerts.csv", mime="text/csv")
    # Download as JSON
    json_bytes = json.dumps(alert_records, indent=2).encode('utf-8')
    st.download_button("Download Alerts as JSON", data=json_bytes, file_name="smartnetids_alerts.json", mime="application/json")
    st.caption("Download recent alerts for SIEM integration or further analysis.")

# --- Custom Rule Evaluation ---
def evaluate_custom_rules(features, now, rule_state):
    alerts = []
    rules = st.session_state.get('custom_rules', [])
    for rule in rules:
        if not rule.get('enabled', True):
            continue
        t = rule['type']
        p = rule['params']
        if t == "Packet Count Threshold":
            key = (p.get('src_ip') or features.get('src_ip'),)
            if key not in rule_state:
                rule_state[key] = []
            rule_state[key].append(now)
            # Remove old
            rule_state[key] = [t0 for t0 in rule_state[key] if (now-t0).total_seconds() < p.get('window',10)]
            if len(rule_state[key]) > p.get('count',10):
                alerts.append(f"Custom Rule Triggered: {rule['name']}")
                rule_state[key] = []
        elif t == "Port Scan":
            key = (p.get('src_ip') or features.get('src_ip'),)
            if key not in rule_state:
                rule_state[key] = []
            rule_state[key].append(features.get('dst_port'))
            # Remove old ports if needed (not time-based for simplicity)
            unique_ports = set(rule_state[key])
            if len(unique_ports) > p.get('unique_ports',10):
                alerts.append(f"Custom Rule Triggered: {rule['name']}")
                rule_state[key] = []
        elif t == "Protocol Violation":
            flags = p.get('tcp_flags','')
            if flags and all(f in str(features.get('tcp_flags','')) for f in flags.split('+')):
                alerts.append(f"Custom Rule Triggered: {rule['name']}")
        elif t == "Port/Protocol Trigger":
            if (not p.get('dst_port') or str(features.get('dst_port')) == p.get('dst_port')) and \
               (not p.get('protocol') or str(features.get('protocol')) == p.get('protocol')):
                alerts.append(f"Custom Rule Triggered: {rule['name']}")
        elif t == "Payload Match":
            if p.get('content') and p['content'] in str(features.get('payload','')):
                alerts.append(f"Custom Rule Triggered: {rule['name']}")
        elif t == "Custom Expression":
            try:
                f = features
                if eval(p.get('expression',''), {"__builtins__":{}}, {"f":f}):
                    alerts.append(f"Custom Rule Triggered: {rule['name']}")
            except Exception:
                continue
    return alerts

# --- Custom Rule UI ---
CUSTOM_RULES_FILE = os.path.join('data', 'custom_rules.json')
def load_custom_rules():
    if os.path.exists(CUSTOM_RULES_FILE):
        with open(CUSTOM_RULES_FILE, 'r') as f:
            return json.load(f)
    return []
def save_custom_rules(rules):
    os.makedirs(os.path.dirname(CUSTOM_RULES_FILE), exist_ok=True)
    with open(CUSTOM_RULES_FILE, 'w') as f:
        json.dump(rules, f, indent=2)

# --- Custom Rule UI ---
if 'custom_rules' not in st.session_state:
    st.session_state['custom_rules'] = load_custom_rules()
if 'rule_search' not in st.session_state:
    st.session_state['rule_search'] = ''
if 'edit_rule_idx' not in st.session_state:
    st.session_state['edit_rule_idx'] = None

st.sidebar.markdown('---')
st.sidebar.subheader('Custom Alert Rules')
st.sidebar.text_input('Search/filter rules', key='rule_search', help='Filter rules by name or type')
search = st.session_state['rule_search'].lower()
modal = Modal(title="Edit Rule", key="edit_rule_modal")
# Add or update vibrant CSS for cards, badges, and tags at the top of the Streamlit UI section
st.markdown('''
<style>
.rule-card {
    background: linear-gradient(90deg, #232526 0%, #414345 100%);
    border-radius: 14px;
    padding: 1.1rem 1.5rem 1.1rem 1.5rem;
    margin-bottom: 1.1rem;
    box-shadow: 0 2px 12px 0 rgba(0,0,0,0.12);
    border: 2px solid #00bfff33;
    transition: box-shadow 0.3s;
}
.rule-card:hover {
    box-shadow: 0 4px 24px 0 #00bfff55;
    border-color: #00bfff;
}
.badge {
    display: inline-block;
    background: linear-gradient(90deg, #ff512f 0%, #dd2476 100%);
    color: #fff;
    border-radius: 8px;
    padding: 0.2em 0.7em;
    font-size: 0.95em;
    font-weight: 600;
    margin-right: 0.5em;
    letter-spacing: 0.5px;
    box-shadow: 0 1px 4px 0 #dd247655;
}
.tag-enabled {
    background: linear-gradient(90deg, #43e97b 0%, #38f9d7 100%);
    color: #222;
    border-radius: 6px;
    padding: 0.15em 0.6em;
    font-size: 0.85em;
    font-weight: 600;
    margin-right: 0.3em;
    box-shadow: 0 1px 4px 0 #38f9d755;
}
.tag-disabled {
    background: linear-gradient(90deg, #f7971e 0%, #ffd200 100%);
    color: #222;
    border-radius: 6px;
    padding: 0.15em 0.6em;
    font-size: 0.85em;
    font-weight: 600;
    margin-right: 0.3em;
    box-shadow: 0 1px 4px 0 #ffd20055;
}
.param-tag {
    display: inline-block;
    background: linear-gradient(90deg, #36d1c4 0%, #5b86e5 100%);
    color: #fff;
    border-radius: 6px;
    padding: 0.13em 0.5em;
    font-size: 0.82em;
    font-weight: 500;
    margin: 0.1em 0.2em 0.1em 0;
    box-shadow: 0 1px 4px 0 #5b86e555;
}
</style>
''', unsafe_allow_html=True)
# List rules with filter and colored cards
for i, rule in enumerate([r for r in st.session_state['custom_rules'] if search in r['name'].lower() or search in r['type'].lower()]):
    card_color = theme['enabled'] if rule['enabled'] else theme['disabled']
    status_tag = f'<span class="tag-enabled">ENABLED</span>' if rule['enabled'] else f'<span class="tag-disabled">DISABLED</span>'
    param_tags = ' '.join([f'<span class="param-tag">{k}: {v}</span>' for k, v in rule['params'].items() if v])
    st.markdown(f'<div class="rule-card" aria-label="Rule card for {rule["name"]}">', unsafe_allow_html=True)
    cols = st.columns([4, 1, 1, 1])
    cols[0].markdown(f"<span class='badge'>{rule['type']}</span> <b>{rule['name']}</b><br>{status_tag}<br>{param_tags}", unsafe_allow_html=True)
    if cols[1].button('📝', key=f"edit_{i}", help="Edit this rule"):
        st.session_state['edit_rule_idx'] = i
        modal.open()
    if cols[2].button('✅' if rule['enabled'] else '🚫', key=f"toggle_{i}", help="Enable/disable this rule"):
        rule['enabled'] = not rule['enabled']
        save_custom_rules(st.session_state['custom_rules'])
        st.toast(f"Rule '{rule['name']}' {'enabled' if rule['enabled'] else 'disabled'}!", icon='✅' if rule['enabled'] else '🚫')
    if cols[3].button('🗑️', key=f"delete_{i}", help="Delete this rule"):
        if st.sidebar.confirm(f"Are you sure you want to delete rule '{rule['name']}'?"):
            st.session_state['custom_rules'].pop(i)
            save_custom_rules(st.session_state['custom_rules'])
            st.toast(f"Rule '{rule['name']}' deleted!", icon='🗑️')
            st.experimental_rerun()
    st.markdown('</div>', unsafe_allow_html=True)
    # Edit modal
    if st.session_state['edit_rule_idx'] == i and modal.is_open():
        with modal.container():
            st.markdown(f"### Edit Rule: {rule['name']}")
            new_name = st.text_input("Rule Name", value=rule['name'], key=f"edit_name_{i}")
            new_enabled = st.checkbox("Enabled", value=rule['enabled'], key=f"edit_enabled_{i}")
            # For simplicity, only allow editing name and enabled status here
            if st.button("Save Changes", key=f"save_edit_{i}"):
                rule['name'] = new_name
                rule['enabled'] = new_enabled
                save_custom_rules(st.session_state['custom_rules'])
                st.session_state['edit_rule_idx'] = None
                modal.close()
                st.toast(f"Rule '{rule['name']}' updated!", icon='📝')
                st.experimental_rerun()
            if st.button("Cancel", key=f"cancel_edit_{i}"):
                st.session_state['edit_rule_idx'] = None
                modal.close()
                st.experimental_rerun()
# Add new rule
with st.sidebar.expander("Add New Rule"):
    rule_name = st.text_input("Rule Name", key="new_rule_name", help="A descriptive name for your rule.")
    rule_type = st.selectbox("Rule Type", [
        "Packet Count Threshold", "Port Scan", "Protocol Violation", "Port/Protocol Trigger", "Payload Match", "Custom Expression"
    ], key="new_rule_type", help="Choose the type of rule to create.")
    params = {}
    valid = True
    help_texts = {
        "Packet Count Threshold": "Alert if more than N packets from a source IP in a time window.",
        "Port Scan": "Alert if a source IP contacts more than N unique ports in a time window.",
        "Protocol Violation": "Alert if a packet has specific TCP flag combinations (e.g. SYN+FIN).",
        "Port/Protocol Trigger": "Alert on packets to a specific port or protocol.",
        "Payload Match": "Alert if the payload contains a specific string.",
        "Custom Expression": "Advanced: Python expression using 'f' as the features dict. E.g. f['length'] > 1000"
    }
    st.caption(help_texts[rule_type])
    if rule_type == "Packet Count Threshold":
        params['src_ip'] = st.text_input("Source IP (blank=any)", key="pct_src_ip", help="Leave blank to match any source IP.")
        params['count'] = st.number_input("Packet Count Threshold", min_value=1, value=10, key="pct_count", help="Number of packets to trigger alert.")
        params['window'] = st.number_input("Time Window (seconds)", min_value=1, value=10, key="pct_window", help="Time window in seconds.")
        if not params['count'] or not params['window']:
            valid = False
    elif rule_type == "Port Scan":
        params['src_ip'] = st.text_input("Source IP (blank=any)", key="ps_src_ip", help="Leave blank to match any source IP.")
        params['unique_ports'] = st.number_input("Unique Ports Threshold", min_value=1, value=10, key="ps_ports", help="Number of unique ports to trigger alert.")
        params['window'] = st.number_input("Time Window (seconds)", min_value=1, value=10, key="ps_window", help="Time window in seconds.")
        if not params['unique_ports'] or not params['window']:
            valid = False
    elif rule_type == "Protocol Violation":
        params['tcp_flags'] = st.text_input("TCP Flags (e.g. SYN+FIN)", key="pv_flags", help="Enter flag combination, e.g. SYN+FIN.")
        if not params['tcp_flags']:
            valid = False
    elif rule_type == "Port/Protocol Trigger":
        params['dst_port'] = st.text_input("Destination Port (blank=any)", key="ppt_port", help="Leave blank to match any port.")
        params['protocol'] = st.text_input("Protocol Number (blank=any)", key="ppt_proto", help="Leave blank to match any protocol.")
        if not params['dst_port'] and not params['protocol']:
            valid = False
    elif rule_type == "Payload Match":
        params['content'] = st.text_input("Payload Content (string)", key="pm_content", help="String to search for in payload.")
        if not params['content']:
            valid = False
    elif rule_type == "Custom Expression":
        params['expression'] = st.text_area("Python Expression (features dict as 'f')", key="ce_expr", help="E.g. f['length'] > 1000")
        if not params['expression']:
            valid = False
    enabled = st.checkbox("Enabled", value=True, key="new_rule_enabled")
    if st.button("Add Rule", key="add_rule_btn"):
        if not rule_name:
            st.error("Rule name is required.")
        elif not valid:
            st.error("Please fill in all required parameters for this rule type.")
        else:
            new_rule = {
                'id': int(time.time()*1000),
                'name': rule_name or f"Rule {int(time.time())}",
                'type': rule_type,
                'params': params,
                'enabled': enabled
            }
            st.session_state['custom_rules'].append(new_rule)
            save_custom_rules(st.session_state['custom_rules'])
            st.experimental_rerun()

# How to run:
# 1. Activate your venv: source venv/bin/activate
# 2. Run: streamlit run src/dashboard.py 