"""
Real-Time Cybersecurity Anomaly Detection System using Pathway
Hackathon MVP - Instant anomaly detection with AI-powered alerts
"""

import pathway as pw
import pandas as pd
import numpy as np
from datetime import datetime
import json
import requests
import os
from typing import Dict, Optional
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# ==================== Configuration ====================
class Config:
    """Central configuration for the anomaly detection system"""

    # Thresholds for anomaly detection
    LOGIN_TIME_THRESHOLD = 22  # Hour after which login is suspicious (10 PM)
    LOGIN_TIME_EARLY_THRESHOLD = 5  # Hour before which login is suspicious (5 AM)
    TRAFFIC_SPIKE_MULTIPLIER = 10  # Traffic spike threshold (10x normal)
    FILE_SIZE_THRESHOLD_MB = 100  # Large file transfer threshold

    # Baseline values (would be learned in production)
    BASELINE_TRAFFIC_RPM = 100  # Normal requests per minute
    BASELINE_FILE_SIZE_MB = 10  # Normal file size

    # Alert endpoints
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")

    # LLM Configuration (using local Ollama or OpenAI)
    USE_LLM = os.getenv("USE_LLM", "false").lower() == "true"
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OLLAMA_URL = "http://localhost:11434/api/generate"


# ==================== Data Schemas ====================
class LoginSchema(pw.Schema):
    username: str
    location: str
    timestamp: str
    ip_address: str


class NetworkTrafficSchema(pw.Schema):
    timestamp: str
    requests_per_minute: int
    source_ip: str


class FileTransferSchema(pw.Schema):
    username: str
    timestamp: str
    file_size_mb: float
    operation: str  # upload/download
    filename: str


# ==================== Anomaly Detectors ====================
class LoginAnomalyDetector:
    _user_profiles = {}

    @staticmethod
    @pw.udf
    def detect_anomaly(username: str, location: str, timestamp: str, ip_address: str) -> Optional[Dict]:
        try:
            dt = datetime.fromisoformat(timestamp)
            hour = dt.hour
            profiles = LoginAnomalyDetector._user_profiles

            if username not in profiles:
                profiles[username] = {
                    "locations": {location},
                    "normal_hours": set(range(7, 22)),  # 7 AM to 10 PM
                    "ip_addresses": {ip_address},
                }
                return None

            profile = profiles[username]
            anomalies = []

            if location not in profile["locations"]:
                anomalies.append(
                    {"type": "unusual_location", "severity": "HIGH", "details": f"Login from new location: {location}"}
                )
                profile["locations"].add(location)

            if hour >= Config.LOGIN_TIME_THRESHOLD or hour <= Config.LOGIN_TIME_EARLY_THRESHOLD:
                anomalies.append(
                    {"type": "unusual_time", "severity": "MEDIUM", "details": f"Login at unusual hour: {hour:02d}:00"}
                )

            if ip_address not in profile["ip_addresses"]:
                anomalies.append(
                    {"type": "new_ip", "severity": "LOW", "details": f"Login from new IP: {ip_address}"}
                )
                profile["ip_addresses"].add(ip_address)

            if anomalies:
                return {
                    "username": username,
                    "location": location,
                    "timestamp": timestamp,
                    "anomalies": anomalies,
                    "risk_score": len(anomalies) * 30,
                }
        except Exception as e:
            logger.error(f"Error in login anomaly detection: {e}")
        return None


class NetworkAnomalyDetector:
    _traffic_history = []
    _baseline_rpm = Config.BASELINE_TRAFFIC_RPM

    @staticmethod
    @pw.udf
    def detect_anomaly(timestamp: str, requests_per_minute: int, source_ip: str) -> Optional[Dict]:
        try:
            NetworkAnomalyDetector._traffic_history.append(requests_per_minute)
            if len(NetworkAnomalyDetector._traffic_history) > 10:
                NetworkAnomalyDetector._traffic_history.pop(0)
                NetworkAnomalyDetector._baseline_rpm = np.mean(NetworkAnomalyDetector._traffic_history[:-1])

            if requests_per_minute > NetworkAnomalyDetector._baseline_rpm * Config.TRAFFIC_SPIKE_MULTIPLIER:
                spike_ratio = requests_per_minute / NetworkAnomalyDetector._baseline_rpm
                return {
                    "timestamp": timestamp,
                    "requests_per_minute": requests_per_minute,
                    "baseline": NetworkAnomalyDetector._baseline_rpm,
                    "spike_ratio": spike_ratio,
                    "source_ip": source_ip,
                    "severity": "CRITICAL" if spike_ratio > 50 else "HIGH",
                    "anomaly_type": "traffic_spike",
                    "details": f"Traffic {spike_ratio:.1f}x higher than normal",
                }
        except Exception as e:
            logger.error(f"Error in network anomaly detection: {e}")
        return None


class FileTransferAnomalyDetector:
    _user_patterns = {}

    @staticmethod
    @pw.udf
    def detect_anomaly(
        username: str, timestamp: str, file_size_mb: float, operation: str, filename: str
    ) -> Optional[Dict]:
        try:
            if username not in FileTransferAnomalyDetector._user_patterns:
                FileTransferAnomalyDetector._user_patterns[username] = {
                    "avg_size": Config.BASELINE_FILE_SIZE_MB,
                    "max_size": Config.BASELINE_FILE_SIZE_MB,
                    "transfer_count": 0,
                }

            pattern = FileTransferAnomalyDetector._user_patterns[username]
            anomalies = []

            if file_size_mb > Config.FILE_SIZE_THRESHOLD_MB:
                anomalies.append(
                    {
                        "type": "large_transfer",
                        "severity": "HIGH" if operation == "download" else "CRITICAL",
                        "details": f"Large {operation}: {file_size_mb:.1f}MB",
                    }
                )

            if file_size_mb > pattern["max_size"] * 5:
                anomalies.append(
                    {
                        "type": "unusual_size_for_user",
                        "severity": "MEDIUM",
                        "details": f"File size {file_size_mb/pattern['avg_size']:.1f}x larger than usual",
                    }
                )

            pattern["transfer_count"] += 1
            pattern["avg_size"] = (pattern["avg_size"] * (pattern["transfer_count"] - 1) + file_size_mb) / pattern[
                "transfer_count"
            ]
            pattern["max_size"] = max(pattern["max_size"], file_size_mb)

            if anomalies:
                return {
                    "username": username,
                    "timestamp": timestamp,
                    "file_size_mb": file_size_mb,
                    "operation": operation,
                    "filename": filename,
                    "anomalies": anomalies,
                    "risk_score": sum(
                        30 if a["severity"] == "CRITICAL" else 20 if a["severity"] == "HIGH" else 10 for a in anomalies
                    ),
                }
        except Exception as e:
            logger.error(f"Error in file transfer anomaly detection: {e}")
        return None


# ==================== Alert System ====================
class AlertSystem:
    @staticmethod
    def generate_llm_explanation(anomaly: Dict) -> str:
        if not Config.USE_LLM:
            return AlertSystem._generate_template_explanation(anomaly)
        try:
            if Config.OPENAI_API_KEY:
                return AlertSystem._openai_explain(anomaly)
            else:
                return AlertSystem._ollama_explain(anomaly)
        except:
            return AlertSystem._generate_template_explanation(anomaly)

    @staticmethod
    def _generate_template_explanation(anomaly: Dict) -> str:
        if "anomaly_type" in anomaly and anomaly["anomaly_type"] == "traffic_spike":
            return (
                f"🚨 NETWORK ALERT: Detected traffic spike! Current: {anomaly['requests_per_minute']} req/min "
                f"(Normal: ~{anomaly['baseline']:.0f} req/min). This is {anomaly['spike_ratio']:.1f}x higher. "
                f"Possible DDoS from {anomaly['source_ip']}."
            )
        elif "operation" in anomaly:
            return (
                f"📁 FILE TRANSFER ALERT: User '{anomaly['username']}' "
                f"{anomaly['operation']} {anomaly['file_size_mb']:.1f}MB '{anomaly['filename']}'. "
                f"Risk score: {anomaly['risk_score']}/100."
            )
        elif "location" in anomaly:
            alerts = anomaly["anomalies"]
            msgs = [a["details"] for a in alerts]
            return (
                f"🔐 LOGIN ALERT: User '{anomaly['username']}' anomalies: {', '.join(msgs)}. "
                f"Risk score: {anomaly['risk_score']}/100."
            )
        return f"⚠️ ANOMALY DETECTED: {json.dumps(anomaly)}"

    @staticmethod
    def _openai_explain(anomaly: Dict) -> str:
        return AlertSystem._generate_template_explanation(anomaly)

    @staticmethod
    def _ollama_explain(anomaly: Dict) -> str:
        return AlertSystem._generate_template_explanation(anomaly)

    @staticmethod
    @pw.udf
    def send_alert(anomaly: Dict) -> None:
        if not anomaly:
            return
        message = AlertSystem.generate_llm_explanation(anomaly)
        logger.warning(f"\n{'='*60}\n{message}\n{'='*60}")

        if Config.SLACK_WEBHOOK_URL:
            try:
                requests.post(Config.SLACK_WEBHOOK_URL, json={"text": message}, timeout=5)
            except Exception as e:
                logger.error(f"Failed Slack alert: {e}")

        if Config.DISCORD_WEBHOOK_URL:
            try:
                requests.post(Config.DISCORD_WEBHOOK_URL, json={"content": message}, timeout=5)
            except Exception as e:
                logger.error(f"Failed Discord alert: {e}")


# ==================== Main Pipeline ====================
def create_anomaly_detection_pipeline():
    login_table = pw.io.csv.read("./data/login_stream/", schema=LoginSchema, mode="streaming")
    network_table = pw.io.csv.read("./data/network_stream/", schema=NetworkTrafficSchema, mode="streaming")
    file_table = pw.io.csv.read("./data/file_stream/", schema=FileTransferSchema, mode="streaming")

    login_anomalies = login_table.select(
        anomaly=LoginAnomalyDetector.detect_anomaly(
            login_table.username, login_table.location, login_table.timestamp, login_table.ip_address
        )
    ).filter(pw.this.anomaly.is_not_none())

    network_anomalies = network_table.select(
        anomaly=NetworkAnomalyDetector.detect_anomaly(
            network_table.timestamp, network_table.requests_per_minute, network_table.source_ip
        )
    ).filter(pw.this.anomaly.is_not_none())

    file_anomalies = file_table.select(
        anomaly=FileTransferAnomalyDetector.detect_anomaly(
            file_table.username, file_table.timestamp, file_table.file_size_mb, file_table.operation, file_table.filename
        )
    ).filter(pw.this.anomaly.is_not_none())

    # Send alerts
    login_anomalies.select(alert=AlertSystem.send_alert(login_anomalies.anomaly))
    network_anomalies.select(alert=AlertSystem.send_alert(network_anomalies.anomaly))
    file_anomalies.select(alert=AlertSystem.send_alert(file_anomalies.anomaly))

    # Log anomalies into separate JSONL files
    pw.io.jsonlines.write(login_anomalies.select(login_anomalies.anomaly), "./output/login_anomalies.jsonl")
    pw.io.jsonlines.write(network_anomalies.select(network_anomalies.anomaly), "./output/network_anomalies.jsonl")
    pw.io.jsonlines.write(file_anomalies.select(file_anomalies.anomaly), "./output/file_anomalies.jsonl")

    return login_anomalies, network_anomalies, file_anomalies


# ==================== Entry Point ====================
if __name__ == "__main__":
    logger.info("Starting Real-Time Anomaly Detection System...")
    logger.info("Monitoring directories: ./data/login_stream/, ./data/network_stream/, ./data/file_stream/")

    os.makedirs("./output", exist_ok=True)

    try:
        create_anomaly_detection_pipeline()
        pw.run()
    except KeyboardInterrupt:
        logger.info("Shutting down anomaly detection system...")
    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        raise
