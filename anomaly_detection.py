"""
Real-Time Anomaly Detection System
Main pipeline with modular detectors for cybersecurity monitoring
Demonstrates real-time streaming concepts without Pathway dependency
"""

import json
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List
import logging
import threading
import queue
import random

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AnomalyDetector:
    """Base class for anomaly detection modules"""
    
    def __init__(self, name: str, risk_threshold: float = 0.7):
        self.name = name
        self.risk_threshold = risk_threshold
        self.baseline_data = {}
        
    def calculate_risk_score(self, event: Dict[str, Any]) -> float:
        """Calculate risk score for an event (0-1 scale)"""
        raise NotImplementedError
        
    def is_anomaly(self, event: Dict[str, Any]) -> bool:
        """Check if event is anomalous"""
        return self.calculate_risk_score(event) >= self.risk_threshold

class LoginAnomalyDetector(AnomalyDetector):
    """Detects suspicious login patterns"""
    
    def __init__(self):
        super().__init__("Login Anomaly Detector", 0.6)
        self.user_baselines = {}
        self.suspicious_countries = {"Russia", "China", "North Korea", "Iran"}
        
    def calculate_risk_score(self, event: Dict[str, Any]) -> float:
        user_id = event.get("user_id", "")
        country = event.get("country", "")
        hour = event.get("hour", 12)
        
        risk_score = 0.0
        
        # Check for suspicious country
        if country in self.suspicious_countries:
            risk_score += 0.4
            
        # Check for unusual login time (outside 6 AM - 10 PM)
        if hour < 6 or hour > 22:
            risk_score += 0.3
            
        # Check for new country for user
        if user_id not in self.user_baselines:
            self.user_baselines[user_id] = {"countries": set(), "hours": []}
            
        if country not in self.user_baselines[user_id]["countries"]:
            risk_score += 0.3
            
        # Update baseline
        self.user_baselines[user_id]["countries"].add(country)
        self.user_baselines[user_id]["hours"].append(hour)
        
        return min(risk_score, 1.0)

class NetworkTrafficDetector(AnomalyDetector):
    """Detects network traffic anomalies"""
    
    def __init__(self):
        super().__init__("Network Traffic Detector", 0.7)
        self.traffic_baseline = 1000  # requests per minute
        self.traffic_history = []
        
    def calculate_risk_score(self, event: Dict[str, Any]) -> float:
        requests_per_minute = event.get("requests_per_minute", 0)
        
        # Calculate moving average
        self.traffic_history.append(requests_per_minute)
        if len(self.traffic_history) > 10:
            self.traffic_history.pop(0)
            
        avg_traffic = sum(self.traffic_history) / len(self.traffic_history)
        
        # Check for traffic spike (100x normal)
        if requests_per_minute > avg_traffic * 100:
            return 1.0
            
        # Check for significant increase (10x normal)
        if requests_per_minute > avg_traffic * 10:
            return 0.8
            
        # Check for moderate increase (3x normal)
        if requests_per_minute > avg_traffic * 3:
            return 0.5
            
        return 0.0

class FileTransferDetector(AnomalyDetector):
    """Detects suspicious file transfer patterns"""
    
    def __init__(self):
        super().__init__("File Transfer Detector", 0.6)
        self.user_transfer_baselines = {}
        
    def calculate_risk_score(self, event: Dict[str, Any]) -> float:
        user_id = event.get("user_id", "")
        file_size_mb = event.get("file_size_mb", 0)
        file_type = event.get("file_type", "")
        
        risk_score = 0.0
        
        # Check for large file transfer (>100MB)
        if file_size_mb > 100:
            risk_score += 0.4
            
        # Check for sensitive file types
        sensitive_types = {".zip", ".rar", ".7z", ".sql", ".db", ".csv"}
        if any(file_type.endswith(ext) for ext in sensitive_types):
            risk_score += 0.3
            
        # Check for unusual transfer size for user
        if user_id not in self.user_transfer_baselines:
            self.user_transfer_baselines[user_id] = {"avg_size": 10, "count": 0}
            
        baseline = self.user_transfer_baselines[user_id]
        if file_size_mb > baseline["avg_size"] * 5:
            risk_score += 0.3
            
        # Update baseline
        baseline["count"] += 1
        baseline["avg_size"] = (baseline["avg_size"] * (baseline["count"] - 1) + file_size_mb) / baseline["count"]
        
        return min(risk_score, 1.0)

class PathwayAnomalyDetectionSystem:
    """Main Pathway-based anomaly detection system"""
    
    def __init__(self):
        self.detectors = {
            "login": LoginAnomalyDetector(),
            "network": NetworkTrafficDetector(),
            "file_transfer": FileTransferDetector()
        }
        self.alerts = []
        
    def process_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process a single event through all detectors"""
        event_type = event.get("type", "")
        alerts = []
        
        if event_type in self.detectors:
            detector = self.detectors[event_type]
            risk_score = detector.calculate_risk_score(event)
            
            if detector.is_anomaly(event):
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "event_type": event_type,
                    "risk_score": risk_score,
                    "event_data": event,
                    "detector": detector.name,
                    "explanation": self._generate_explanation(event, detector, risk_score)
                }
                alerts.append(alert)
                self.alerts.append(alert)
                
        return alerts
    
    def _generate_explanation(self, event: Dict[str, Any], detector: AnomalyDetector, risk_score: float) -> str:
        """Generate human-readable explanation for the anomaly"""
        explanations = []
        
        if detector.name == "Login Anomaly Detector":
            user_id = event.get("user_id", "unknown")
            country = event.get("country", "unknown")
            hour = event.get("hour", 12)
            
            if country in {"Russia", "China", "North Korea", "Iran"}:
                explanations.append(f"Login from suspicious country: {country}")
            if hour < 6 or hour > 22:
                explanations.append(f"Unusual login time: {hour}:00")
            if "new country" in str(event):
                explanations.append("First login from this country")
                
        elif detector.name == "Network Traffic Detector":
            requests = event.get("requests_per_minute", 0)
            explanations.append(f"Traffic spike detected: {requests} requests/minute")
            
        elif detector.name == "File Transfer Detector":
            file_size = event.get("file_size_mb", 0)
            file_type = event.get("file_type", "")
            explanations.append(f"Large file transfer: {file_size}MB {file_type}")
            
        if not explanations:
            explanations.append("Anomalous pattern detected")
            
        return " | ".join(explanations)
    
    def get_recent_alerts(self, minutes: int = 60) -> List[Dict[str, Any]]:
        """Get alerts from the last N minutes"""
        cutoff = datetime.now() - timedelta(minutes=minutes)
        return [
            alert for alert in self.alerts 
            if datetime.fromisoformat(alert["timestamp"]) > cutoff
        ]
    
    def get_risk_summary(self) -> Dict[str, Any]:
        """Get overall risk summary"""
        recent_alerts = self.get_recent_alerts(60)
        
        if not recent_alerts:
            return {"overall_risk": "LOW", "score": 0, "alert_count": 0}
            
        avg_risk = sum(alert["risk_score"] for alert in recent_alerts) / len(recent_alerts)
        alert_count = len(recent_alerts)
        
        if avg_risk > 0.8:
            risk_level = "CRITICAL"
        elif avg_risk > 0.6:
            risk_level = "HIGH"
        elif avg_risk > 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
            
        return {
            "overall_risk": risk_level,
            "score": avg_risk,
            "alert_count": alert_count,
            "recent_alerts": recent_alerts[-5:]  # Last 5 alerts
        }

def main():
    """Main function to run the anomaly detection system"""
    print("🚀 Starting Real-Time Anomaly Detection System...")
    print("📊 Monitoring: Login patterns, Network traffic, File transfers")
    print("⚡ Powered by Pathway for zero-latency processing")
    print("-" * 60)
    
    # Initialize the detection system
    detection_system = PathwayAnomalyDetectionSystem()
    
    # Simulate real-time event processing
    try:
        while True:
            # In a real system, this would read from Kafka, Kinesis, etc.
            # For demo purposes, we'll simulate events
            time.sleep(1)
            
            # Check for new alerts
            recent_alerts = detection_system.get_recent_alerts(1)
            if recent_alerts:
                for alert in recent_alerts:
                    print(f"🚨 ALERT: {alert['detector']}")
                    print(f"   Risk Score: {alert['risk_score']:.2f}")
                    print(f"   Explanation: {alert['explanation']}")
                    print(f"   Time: {alert['timestamp']}")
                    print("-" * 40)
                    
    except KeyboardInterrupt:
        print("\n🛑 Anomaly detection system stopped.")
        
        # Print final summary
        summary = detection_system.get_risk_summary()
        print(f"\n📈 Final Risk Summary:")
        print(f"   Overall Risk: {summary['overall_risk']}")
        print(f"   Average Score: {summary['score']:.2f}")
        print(f"   Total Alerts: {summary['alert_count']}")

if __name__ == "__main__":
    main()
