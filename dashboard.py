"""
Beautiful Streamlit Dashboard with Live Updates
Real-time visualization for the anomaly detection system
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import time
from datetime import datetime, timedelta
import threading
import queue
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Page configuration
st.set_page_config(
    page_title="Real-Time Anomaly Detection Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 3rem;
        font-weight: bold;
        text-align: center;
        color: #1f77b4;
        margin-bottom: 2rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1f77b4;
    }
    .alert-card {
        background-color: #fff2f2;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #ff4444;
        margin-bottom: 1rem;
    }
    .risk-low { color: #28a745; }
    .risk-medium { color: #ffc107; }
    .risk-high { color: #fd7e14; }
    .risk-critical { color: #dc3545; }
</style>
""", unsafe_allow_html=True)

class DashboardData:
    """Manages dashboard data and state"""
    
    def __init__(self):
        self.alerts = []
        self.metrics = {
            "total_events": 0,
            "anomalies_detected": 0,
            "risk_score": 0.0,
            "uptime": "00:00:00"
        }
        self.start_time = datetime.now()
        
    def add_alert(self, alert):
        """Add a new alert to the dashboard"""
        self.alerts.append(alert)
        self.metrics["anomalies_detected"] += 1
        
    def update_metrics(self, events_processed=0):
        """Update dashboard metrics"""
        self.metrics["total_events"] += events_processed
        self.metrics["uptime"] = str(datetime.now() - self.start_time).split('.')[0]
        
        if self.alerts:
            self.metrics["risk_score"] = sum(alert["risk_score"] for alert in self.alerts[-10:]) / min(len(self.alerts), 10)
        else:
            self.metrics["risk_score"] = 0.0

# Global dashboard data
if 'dashboard_data' not in st.session_state:
    st.session_state.dashboard_data = DashboardData()

def get_risk_color(risk_score):
    """Get color based on risk score"""
    if risk_score < 0.3:
        return "risk-low"
    elif risk_score < 0.6:
        return "risk-medium"
    elif risk_score < 0.8:
        return "risk-high"
    else:
        return "risk-critical"

def render_header():
    """Render the main header"""
    st.markdown('<h1 class="main-header">🛡️ Real-Time Anomaly Detection Dashboard</h1>', unsafe_allow_html=True)
    st.markdown("---")

def render_metrics():
    """Render key metrics cards"""
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric(
            label="📊 Total Events",
            value=f"{st.session_state.dashboard_data.metrics['total_events']:,}",
            delta=None
        )
    
    with col2:
        st.metric(
            label="🚨 Anomalies Detected",
            value=st.session_state.dashboard_data.metrics['anomalies_detected'],
            delta=None
        )
    
    with col3:
        risk_score = st.session_state.dashboard_data.metrics['risk_score']
        risk_class = get_risk_color(risk_score)
        st.metric(
            label="⚠️ Risk Score",
            value=f"{risk_score:.2f}",
            delta=None
        )
    
    with col4:
        st.metric(
            label="⏱️ Uptime",
            value=st.session_state.dashboard_data.metrics['uptime'],
            delta=None
        )

def render_risk_gauge():
    """Render risk level gauge"""
    risk_score = st.session_state.dashboard_data.metrics['risk_score']
    
    fig = go.Figure(go.Indicator(
        mode = "gauge+number+delta",
        value = risk_score,
        domain = {'x': [0, 1], 'y': [0, 1]},
        title = {'text': "Overall Risk Level"},
        delta = {'reference': 0.5},
        gauge = {
            'axis': {'range': [None, 1]},
            'bar': {'color': "darkblue"},
            'steps': [
                {'range': [0, 0.3], 'color': "lightgreen"},
                {'range': [0.3, 0.6], 'color': "yellow"},
                {'range': [0.6, 0.8], 'color': "orange"},
                {'range': [0.8, 1], 'color': "red"}
            ],
            'threshold': {
                'line': {'color': "red", 'width': 4},
                'thickness': 0.75,
                'value': 0.8
            }
        }
    ))
    
    fig.update_layout(height=300)
    st.plotly_chart(fig, use_container_width=True)

def render_alerts_timeline():
    """Render alerts timeline"""
    if not st.session_state.dashboard_data.alerts:
        st.info("No alerts detected yet. Start the anomaly detection system to see real-time alerts.")
        return
    
    # Prepare data for timeline
    alerts_df = pd.DataFrame(st.session_state.dashboard_data.alerts)
    alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
    alerts_df['hour'] = alerts_df['timestamp'].dt.hour
    
    # Create timeline chart
    fig = px.scatter(
        alerts_df,
        x='timestamp',
        y='risk_score',
        color='event_type',
        size='risk_score',
        hover_data=['detector', 'explanation'],
        title="Anomaly Detection Timeline",
        labels={'risk_score': 'Risk Score', 'timestamp': 'Time'}
    )
    
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

def render_recent_alerts():
    """Render recent alerts list"""
    st.subheader("🚨 Recent Alerts")
    
    if not st.session_state.dashboard_data.alerts:
        st.info("No alerts to display.")
        return
    
    # Show last 10 alerts
    recent_alerts = st.session_state.dashboard_data.alerts[-10:]
    
    for alert in reversed(recent_alerts):
        risk_class = get_risk_color(alert['risk_score'])
        
        with st.container():
            st.markdown(f"""
            <div class="alert-card">
                <h4>🚨 {alert['detector']}</h4>
                <p><strong>Risk Score:</strong> <span class="{risk_class}">{alert['risk_score']:.2f}</span></p>
                <p><strong>Event Type:</strong> {alert['event_type']}</p>
                <p><strong>Time:</strong> {alert['timestamp']}</p>
                <p><strong>Explanation:</strong> {alert['explanation']}</p>
            </div>
            """, unsafe_allow_html=True)

def render_event_type_distribution():
    """Render event type distribution"""
    if not st.session_state.dashboard_data.alerts:
        return
    
    alerts_df = pd.DataFrame(st.session_state.dashboard_data.alerts)
    
    # Event type distribution
    event_counts = alerts_df['event_type'].value_counts()
    
    fig = px.pie(
        values=event_counts.values,
        names=event_counts.index,
        title="Alert Distribution by Event Type"
    )
    
    st.plotly_chart(fig, use_container_width=True)

def render_risk_trend():
    """Render risk score trend over time"""
    if not st.session_state.dashboard_data.alerts:
        return
    
    alerts_df = pd.DataFrame(st.session_state.dashboard_data.alerts)
    alerts_df['timestamp'] = pd.to_datetime(alerts_df['timestamp'])
    
    # Calculate rolling average
    alerts_df = alerts_df.sort_values('timestamp')
    alerts_df['rolling_risk'] = alerts_df['risk_score'].rolling(window=5, min_periods=1).mean()
    
    fig = px.line(
        alerts_df,
        x='timestamp',
        y='rolling_risk',
        title="Risk Score Trend (5-point rolling average)",
        labels={'rolling_risk': 'Average Risk Score', 'timestamp': 'Time'}
    )
    
    fig.add_hline(y=0.5, line_dash="dash", line_color="red", annotation_text="Medium Risk Threshold")
    fig.add_hline(y=0.8, line_dash="dash", line_color="darkred", annotation_text="High Risk Threshold")
    
    st.plotly_chart(fig, use_container_width=True)

def render_sidebar():
    """Render sidebar controls"""
    st.sidebar.title("🎛️ Dashboard Controls")
    
    # System status
    st.sidebar.subheader("System Status")
    if st.session_state.dashboard_data.metrics['total_events'] > 0:
        st.sidebar.success("🟢 System Active")
    else:
        st.sidebar.warning("🟡 System Starting")
    
    # Refresh controls
    st.sidebar.subheader("Refresh Controls")
    auto_refresh = st.sidebar.checkbox("Auto Refresh", value=True)
    refresh_interval = st.sidebar.slider("Refresh Interval (seconds)", 1, 10, 2)
    
    # Alert filters
    st.sidebar.subheader("Alert Filters")
    min_risk = st.sidebar.slider("Minimum Risk Score", 0.0, 1.0, 0.0, 0.1)
    
    # Demo controls
    st.sidebar.subheader("Demo Controls")
    if st.sidebar.button("🎯 Simulate Attack"):
        # Simulate an attack alert
        fake_alert = {
            "timestamp": datetime.now().isoformat(),
            "event_type": "login",
            "risk_score": 0.9,
            "detector": "Login Anomaly Detector",
            "explanation": "User 'john.doe' logged in from Russia at 3 AM - Risk Score: 90/100"
        }
        st.session_state.dashboard_data.add_alert(fake_alert)
        st.sidebar.success("Attack simulation added!")
    
    if st.sidebar.button("🧹 Clear Alerts"):
        st.session_state.dashboard_data.alerts = []
        st.sidebar.success("Alerts cleared!")
    
    return auto_refresh, refresh_interval, min_risk

def main():
    """Main dashboard function"""
    render_header()
    
    # Render sidebar and get controls
    auto_refresh, refresh_interval, min_risk = render_sidebar()
    
    # Main dashboard layout
    col1, col2 = st.columns([2, 1])
    
    with col1:
        # Metrics row
        render_metrics()
        st.markdown("---")
        
        # Risk gauge
        render_risk_gauge()
        st.markdown("---")
        
        # Alerts timeline
        render_alerts_timeline()
        st.markdown("---")
        
        # Risk trend
        render_risk_trend()
    
    with col2:
        # Recent alerts
        render_recent_alerts()
        st.markdown("---")
        
        # Event type distribution
        render_event_type_distribution()
    
    # Auto refresh
    if auto_refresh:
        time.sleep(refresh_interval)
        st.rerun()
    
    # Footer
    st.markdown("---")
    st.markdown("""
    <div style='text-align: center; color: #666;'>
        🛡️ Real-Time Anomaly Detection System | Powered by Pathway | 
        Built for Hackathon Demo
    </div>
    """, unsafe_allow_html=True)

if __name__ == "__main__":
    main()
