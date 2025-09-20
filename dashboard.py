"""
Real-Time Security Anomaly Dashboard
Streamlit UI for monitoring detected anomalies
"""

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import time
import os
from collections import deque, Counter
from dotenv import load_dotenv
from mongodb_utils import get_mongodb_manager, get_anomalies, get_anomaly_stats

# Load environment variables
load_dotenv()

# Page config
st.set_page_config(
    page_title="Security Anomaly Detection",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
    <style>
    .alert-critical {
        background-color: #ff4444;
        padding: 10px;
        border-radius: 5px;
        color: white;
        font-weight: bold;
    }
    .alert-high {
        background-color: #ff8800;
        padding: 10px;
        border-radius: 5px;
        color: white;
    }
    .alert-medium {
        background-color: #ffbb33;
        padding: 10px;
        border-radius: 5px;
        color: white;
    }
    .alert-low {
        background-color: #33bbff;
        padding: 10px;
        border-radius: 5px;
        color: white;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        border-left: 5px solid #1f77b4;
    }
    </style>
""")

def load_anomalies():
    """Load anomaly data from MongoDB"""
    try:
        # Get all anomalies from MongoDB
        all_anomalies = get_anomalies(limit=1000)
        
        # Group by type
        anomalies = {
            'login': [],
            'network': [],
            'file': [],
            'unknown': []
        }
        
        for anomaly in all_anomalies:
            anomaly_type = anomaly.get('type', 'unknown')
            if anomaly_type in anomalies:
                anomalies[anomaly_type].append(anomaly)
            else:
                anomalies['unknown'].append(anomaly)
        
        return anomalies
        
    except Exception as e:
        st.error(f"Error loading anomalies from MongoDB: {e}")
        return {'login': [], 'network': [], 'file': [], 'unknown': []}

def display_anomaly_alert(anomaly, anomaly_type):
    """Display a single anomaly as an alert card"""
    severity = anomaly.get('severity', 'UNKNOWN')
    
    if severity == 'CRITICAL':
        alert_class = 'alert-critical'
        icon = '🚨'
    elif severity == 'HIGH':
        alert_class = 'alert-high'
        icon = '⚠️'
    elif severity == 'MEDIUM':
        alert_class = 'alert-medium'
        icon = '⚡'
    else:
        alert_class = 'alert-low'
        icon = 'ℹ️'
    
    st.markdown(f"""
    <div class="{alert_class}">
        {icon} <strong>{severity}</strong> - {anomaly_type.upper()} Anomaly
        <br>Details: {json.dumps(anomaly, indent=2)}
    </div>
    """, unsafe_allow_html=True)

def main():
    st.title("🔒 Real-Time Security Anomaly Detection Dashboard")
    st.markdown("---")
    
    # Sidebar controls
    st.sidebar.header("Dashboard Controls")
    auto_refresh = st.sidebar.checkbox("Auto-refresh (5s)", value=True)
    show_historical = st.sidebar.checkbox("Show Historical Data", value=True)
    
    if auto_refresh:
        time.sleep(5)
        st.rerun()
    
    # Load anomaly data
    anomalies = load_anomalies()
    
    # Metrics row
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Login Anomalies", len(anomalies['login']))
    
    with col2:
        st.metric("Network Anomalies", len(anomalies['network']))
    
    with col3:
        st.metric("File Transfer Anomalies", len(anomalies['file']))
    
    with col4:
        total_anomalies = sum(len(anomalies[key]) for key in anomalies)
        st.metric("Total Anomalies", total_anomalies)
    
    st.markdown("---")
    
    # Display anomalies by type
    tab1, tab2, tab3 = st.tabs(["🔐 Login Anomalies", "🌐 Network Anomalies", "📁 File Transfer Anomalies"])
    
    with tab1:
        if anomalies['login']:
            for anomaly in anomalies['login']:
                display_anomaly_alert(anomaly, 'login')
        else:
            st.info("No login anomalies detected")
    
    with tab2:
        if anomalies['network']:
            for anomaly in anomalies['network']:
                display_anomaly_alert(anomaly, 'network')
        else:
            st.info("No network anomalies detected")
    
    with tab3:
        if anomalies['file']:
            for anomaly in anomalies['file']:
                display_anomaly_alert(anomaly, 'file')
        else:
            st.info("No file transfer anomalies detected")
    
    # Footer
    st.markdown("---")
    st.markdown("**Real-Time Anomaly Detection System** | Powered by Pathway AI")

if __name__ == "__main__":
    main()