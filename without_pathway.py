"""
Real-Time Cybersecurity Anomaly Detection System using Pathway
Hackathon MVP - Instant anomaly detection with AI-powered alerts
"""

# import pathway as pw
# from pathway.stdlib.ml.index import KNNIndex
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import json
import requests
import os
from typing import Dict, List, Optional
import logging
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
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
    USE_LLM = os.getenv("USE_LLM", "true").lower() == "true"  # Enabled by default
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")  # or gpt-4
    OLLAMA_URL = "http://localhost:11434/api/generate"

# ==================== Data Schemas ====================
# Simplified data classes without Pathway
class LoginData:
    def __init__(self, username: str, location: str, timestamp: str, ip_address: str):
        self.username = username
        self.location = location
        self.timestamp = timestamp
        self.ip_address = ip_address

class NetworkTrafficData:
    def __init__(self, timestamp: str, requests_per_minute: int, source_ip: str):
        self.timestamp = timestamp
        self.requests_per_minute = requests_per_minute
        self.source_ip = source_ip
    
class FileTransferData:
    def __init__(self, username: str, timestamp: str, file_size_mb: float, operation: str, filename: str):
        self.username = username
        self.timestamp = timestamp
        self.file_size_mb = file_size_mb
        self.operation = operation
        self.filename = filename

# ==================== Anomaly Detectors ====================
class LoginAnomalyDetector:
    """Detects unusual login patterns"""
    
    def __init__(self):
        self.user_profiles = {}  # Store normal behavior patterns
        
    def detect_anomaly(self, username: str, location: str, timestamp: str, ip_address: str) -> Optional[Dict]:
        """
        Detect login anomalies based on location and time
        Returns anomaly details if detected, None otherwise
        """
        try:
            dt = datetime.fromisoformat(timestamp)
            hour = dt.hour
            
            # Initialize user profile if new user
            if username not in self.user_profiles:
                self.user_profiles[username] = {
                    'locations': {location},
                    'normal_hours': set(range(7, 22)),  # 7 AM to 10 PM
                    'ip_addresses': {ip_address}
                }
                return None  # First login, no anomaly
            
            profile = self.user_profiles[username]
            anomalies = []
            
            # Check for unusual location
            if location not in profile['locations']:
                anomalies.append({
                    'type': 'unusual_location',
                    'severity': 'HIGH',
                    'details': f"Login from new location: {location}"
                })
                profile['locations'].add(location)
            
            # Check for unusual time
            if hour >= Config.LOGIN_TIME_THRESHOLD or hour <= Config.LOGIN_TIME_EARLY_THRESHOLD:
                anomalies.append({
                    'type': 'unusual_time',
                    'severity': 'MEDIUM',
                    'details': f"Login at unusual hour: {hour:02d}:00"
                })
            
            # Check for new IP address
            if ip_address not in profile['ip_addresses']:
                anomalies.append({
                    'type': 'new_ip',
                    'severity': 'LOW',
                    'details': f"Login from new IP: {ip_address}"
                })
                profile['ip_addresses'].add(ip_address)
            
            if anomalies:
                return {
                    'username': username,
                    'location': location,
                    'timestamp': timestamp,
                    'anomalies': anomalies,
                    'risk_score': len(anomalies) * 30  # Simple risk scoring
                }
                
        except Exception as e:
            logger.error(f"Error in login anomaly detection: {e}")
            
        return None

class NetworkAnomalyDetector:
    """Detects network traffic anomalies (DDoS patterns)"""
    
    def __init__(self):
        self.traffic_history = []
        self.baseline_rpm = Config.BASELINE_TRAFFIC_RPM
        
    def detect_anomaly(self, timestamp: str, requests_per_minute: int, source_ip: str) -> Optional[Dict]:
        """
        Detect traffic spikes that might indicate DDoS
        """
        try:
            # Update rolling average (simplified for MVP)
            self.traffic_history.append(requests_per_minute)
            if len(self.traffic_history) > 10:
                self.traffic_history.pop(0)
                self.baseline_rpm = np.mean(self.traffic_history[:-1])
            
            # Check for traffic spike
            if requests_per_minute > self.baseline_rpm * Config.TRAFFIC_SPIKE_MULTIPLIER:
                spike_ratio = requests_per_minute / self.baseline_rpm
                return {
                    'timestamp': timestamp,
                    'requests_per_minute': requests_per_minute,
                    'baseline': self.baseline_rpm,
                    'spike_ratio': spike_ratio,
                    'source_ip': source_ip,
                    'severity': 'CRITICAL' if spike_ratio > 50 else 'HIGH',
                    'anomaly_type': 'traffic_spike',
                    'details': f"Traffic {spike_ratio:.1f}x higher than normal"
                }
                
        except Exception as e:
            logger.error(f"Error in network anomaly detection: {e}")
            
        return None

class FileTransferAnomalyDetector:
    """Detects suspicious file transfers (potential exfiltration)"""
    
    def __init__(self):
        self.user_patterns = {}
        
    def detect_anomaly(self, username: str, timestamp: str, file_size_mb: float, 
                       operation: str, filename: str) -> Optional[Dict]:
        """
        Detect abnormally large file transfers
        """
        try:
            # Initialize user pattern if new
            if username not in self.user_patterns:
                self.user_patterns[username] = {
                    'avg_size': Config.BASELINE_FILE_SIZE_MB,
                    'max_size': Config.BASELINE_FILE_SIZE_MB,
                    'transfer_count': 0
                }
            
            pattern = self.user_patterns[username]
            anomalies = []
            
            # Check for large file transfer
            if file_size_mb > Config.FILE_SIZE_THRESHOLD_MB:
                anomalies.append({
                    'type': 'large_transfer',
                    'severity': 'HIGH' if operation == 'download' else 'CRITICAL',
                    'details': f"Large {operation}: {file_size_mb:.1f}MB"
                })
            
            # Check if significantly larger than user's normal
            if file_size_mb > pattern['max_size'] * 5:
                anomalies.append({
                    'type': 'unusual_size_for_user',
                    'severity': 'MEDIUM',
                    'details': f"File size {file_size_mb/pattern['avg_size']:.1f}x larger than usual"
                })
            
            # Update user pattern
            pattern['transfer_count'] += 1
            pattern['avg_size'] = (pattern['avg_size'] * (pattern['transfer_count'] - 1) + file_size_mb) / pattern['transfer_count']
            pattern['max_size'] = max(pattern['max_size'], file_size_mb)
            
            if anomalies:
                return {
                    'username': username,
                    'timestamp': timestamp,
                    'file_size_mb': file_size_mb,
                    'operation': operation,
                    'filename': filename,
                    'anomalies': anomalies,
                    'risk_score': sum(30 if a['severity'] == 'CRITICAL' else 20 if a['severity'] == 'HIGH' else 10 
                                     for a in anomalies)
                }
                
        except Exception as e:
            logger.error(f"Error in file transfer anomaly detection: {e}")
            
        return None

# ==================== Alert System ====================
class AlertSystem:
    """Manages alert generation and distribution"""
    
    @staticmethod
    def generate_llm_explanation(anomaly: Dict) -> str:
        """
        Generate human-readable explanation using LLM (OpenAI or fallback)
        """
        if not Config.USE_LLM or not anomaly:
            return AlertSystem._generate_template_explanation(anomaly)
        
        try:
            # Try OpenAI first if API key available
            if Config.OPENAI_API_KEY:
                return AlertSystem._openai_explain(anomaly)
            else:
                # Try Ollama as fallback
                return AlertSystem._ollama_explain(anomaly)
        except Exception as e:
            logger.warning(f"LLM generation failed: {e}. Using template.")
            return AlertSystem._generate_template_explanation(anomaly)
    
    @staticmethod
    def _generate_template_explanation(anomaly: Dict) -> str:
        """Template-based alert messages"""
        if not anomaly:
            return "⚠️ Unknown anomaly detected"
            
        if 'anomaly_type' in anomaly and anomaly['anomaly_type'] == 'traffic_spike':
            return (f"🚨 NETWORK ALERT: Detected traffic spike! "
                   f"Current: {anomaly['requests_per_minute']} req/min "
                   f"(Normal: ~{anomaly['baseline']:.0f} req/min). "
                   f"This is {anomaly['spike_ratio']:.1f}x higher than baseline. "
                   f"Possible DDoS attack in progress from {anomaly['source_ip']}.")
        
        elif 'operation' in anomaly:  # File transfer
            return (f"📁 FILE TRANSFER ALERT: User '{anomaly['username']}' "
                   f"performed {anomaly['operation']} of {anomaly['file_size_mb']:.1f}MB file "
                   f"'{anomaly['filename']}'. Risk score: {anomaly['risk_score']}/100. "
                   f"Possible data exfiltration attempt.")
        
        elif 'location' in anomaly:  # Login
            alerts = anomaly['anomalies']
            alert_msgs = [a['details'] for a in alerts]
            return (f"🔐 LOGIN ALERT: User '{anomaly['username']}' login anomaly detected. "
                   f"Issues: {', '.join(alert_msgs)}. "
                   f"Risk score: {anomaly['risk_score']}/100.")
        
        return f"⚠️ ANOMALY DETECTED: {json.dumps(anomaly)}"
    
    @staticmethod
    def _openai_explain(anomaly: Dict) -> str:
        """Use OpenAI GPT to generate contextual explanation"""
        try:
            import openai
            
            # Initialize OpenAI client with new API
            client = openai.OpenAI(api_key=Config.OPENAI_API_KEY)
            
            # Prepare context for GPT
            if 'anomaly_type' in anomaly and anomaly['anomaly_type'] == 'traffic_spike':
                context = f"""
                Network anomaly detected:
                - Current traffic: {anomaly['requests_per_minute']} requests/minute
                - Normal baseline: {anomaly['baseline']:.0f} requests/minute
                - Spike ratio: {anomaly['spike_ratio']:.1f}x normal
                - Source IP: {anomaly['source_ip']}
                - Severity: {anomaly['severity']}
                """
                prompt = "Generate a concise security alert message for this network traffic spike. Include severity, likely cause (DDoS), and recommended action. Keep it under 50 words."
            
            elif 'operation' in anomaly:  # File transfer
                context = f"""
                File transfer anomaly detected:
                - User: {anomaly['username']}
                - Operation: {anomaly['operation']}
                - File: {anomaly['filename']}
                - Size: {anomaly['file_size_mb']:.1f}MB
                - Risk score: {anomaly['risk_score']}/100
                """
                prompt = "Generate a concise security alert for this suspicious file transfer. Mention potential data exfiltration risk if file is over 100MB. Keep it under 50 words."
            
            elif 'location' in anomaly:  # Login
                alerts_detail = ', '.join([a['details'] for a in anomaly['anomalies']])
                context = f"""
                Login anomaly detected:
                - User: {anomaly['username']}
                - Location: {anomaly['location']}
                - Issues: {alerts_detail}
                - Risk score: {anomaly['risk_score']}/100
                - Time: {anomaly['timestamp']}
                """
                prompt = "Generate a concise security alert for this suspicious login. Highlight the unusual aspects and risk level. Keep it under 50 words."
            
            else:
                return AlertSystem._generate_template_explanation(anomaly)
            
            # Call OpenAI API with new format
            response = client.chat.completions.create(
                model=Config.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are a cybersecurity expert generating clear, actionable security alerts. Use emojis for visual impact."},
                    {"role": "user", "content": f"Context: {context}\n\n{prompt}"}
                ],
                temperature=0.3,  # Low temperature for consistency
                max_tokens=100
            )
            
            alert_message = response.choices[0].message.content.strip()
            
            # Add emoji if not present
            if not any(emoji in alert_message for emoji in ['🚨', '⚠️', '🔐', '📁', '🌐']):
                if 'traffic' in context.lower() or 'ddos' in alert_message.lower():
                    alert_message = f"🚨 {alert_message}"
                elif 'login' in context.lower():
                    alert_message = f"🔐 {alert_message}"
                elif 'file' in context.lower():
                    alert_message = f"📁 {alert_message}"
                else:
                    alert_message = f"⚠️ {alert_message}"
            
            return alert_message
            
        except Exception as e:
            logger.error(f"OpenAI API error: {e}")
            return AlertSystem._generate_template_explanation(anomaly)
    
    @staticmethod
    def _ollama_explain(anomaly: Dict) -> str:
        """Use Ollama local LLM to generate explanation"""
        try:
            # Prepare prompt similar to OpenAI
            if 'anomaly_type' in anomaly and anomaly['anomaly_type'] == 'traffic_spike':
                prompt = f"Security alert: Network traffic is {anomaly['spike_ratio']:.1f}x normal ({anomaly['requests_per_minute']} req/min). Likely DDoS from {anomaly['source_ip']}. Keep response under 30 words."
            elif 'operation' in anomaly:
                prompt = f"Security alert: User {anomaly['username']} transferred {anomaly['file_size_mb']:.1f}MB file. Possible data theft. Keep response under 30 words."
            elif 'location' in anomaly:
                prompt = f"Security alert: User {anomaly['username']} logged in from {anomaly['location']} with risk score {anomaly['risk_score']}/100. Keep response under 30 words."
            else:
                return AlertSystem._generate_template_explanation(anomaly)
            
            response = requests.post(
                Config.OLLAMA_URL,
                json={
                    "model": "llama2",
                    "prompt": prompt,
                    "stream": False
                },
                timeout=5
            )
            
            if response.status_code == 200:
                result = response.json()
                return f"🚨 {result['response'][:200]}"  # Limit length
            else:
                return AlertSystem._generate_template_explanation(anomaly)
                
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return AlertSystem._generate_template_explanation(anomaly)
    
    @staticmethod
    def send_alert(anomaly: Dict) -> None:
        """Send alerts to various channels"""
        if not anomaly:
            return
            
        message = AlertSystem.generate_llm_explanation(anomaly)
        
        # Console output (always enabled)
        logger.warning(f"\n{'='*60}\n{message}\n{'='*60}")
        
        # Slack webhook
        if Config.SLACK_WEBHOOK_URL:
            try:
                requests.post(Config.SLACK_WEBHOOK_URL, 
                            json={"text": message},
                            timeout=5)
            except Exception as e:
                logger.error(f"Failed to send Slack alert: {e}")
        
        # Discord webhook
        if Config.DISCORD_WEBHOOK_URL:
            try:
                requests.post(Config.DISCORD_WEBHOOK_URL,
                            json={"content": message},
                            timeout=5)
            except Exception as e:
                logger.error(f"Failed to send Discord alert: {e}")

# ==================== Main Pipeline ====================
def create_anomaly_detection_pipeline():
    """
    Create the main anomaly detection pipeline (simplified without Pathway)
    """
    # Initialize detectors
    login_detector = LoginAnomalyDetector()
    network_detector = NetworkAnomalyDetector()
    file_detector = FileTransferAnomalyDetector()
    
    logger.info("Anomaly detection pipeline initialized")
    logger.info("Detectors ready: Login, Network, File Transfer")
    
    return login_detector, network_detector, file_detector

def process_csv_data(csv_file_path: str, detector_type: str, detectors):
    """
    Process CSV data and detect anomalies
    """
    try:
        import pandas as pd
        
        # Read CSV file
        df = pd.read_csv(csv_file_path)
        logger.info(f"Processing {len(df)} records from {csv_file_path}")
        
        anomalies_found = []
        
        for index, row in df.iterrows():
            anomaly = None
            
            if detector_type == 'login':
                login_detector, _, _ = detectors
                anomaly = login_detector.detect_anomaly(
                    row['username'], row['location'], 
                    row['timestamp'], row['ip_address']
                )
            elif detector_type == 'network':
                _, network_detector, _ = detectors
                anomaly = network_detector.detect_anomaly(
                    row['timestamp'], row['requests_per_minute'], 
                    row['source_ip']
                )
            elif detector_type == 'file':
                _, _, file_detector = detectors
                anomaly = file_detector.detect_anomaly(
                    row['username'], row['timestamp'], 
                    row['file_size_mb'], row['operation'], 
                    row['filename']
                )
            
            if anomaly:
                anomalies_found.append(anomaly)
                AlertSystem.send_alert(anomaly)
        
        logger.info(f"Found {len(anomalies_found)} anomalies in {csv_file_path}")
        return anomalies_found
        
    except Exception as e:
        logger.error(f"Error processing {csv_file_path}: {e}")
        return []

def monitor_directories():
    """
    Monitor directories for new CSV files (simplified file watching)
    """
    import time
    import glob
    
    # Create directories if they don't exist
    directories = ['./data/login_stream/', './data/network_stream/', './data/file_stream/']
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
    
    # Initialize detectors
    detectors = create_anomaly_detection_pipeline()
    
    logger.info("Starting directory monitoring...")
    logger.info("Watching for CSV files in:")
    for directory in directories:
        logger.info(f"  - {directory}")
    
    processed_files = set()
    
    try:
        while True:
            for directory in directories:
                # Look for CSV files
                csv_files = glob.glob(os.path.join(directory, "*.csv"))
                
                for csv_file in csv_files:
                    if csv_file not in processed_files:
                        logger.info(f"New file detected: {csv_file}")
                        
                        # Determine detector type from directory
                        if 'login_stream' in csv_file:
                            detector_type = 'login'
                        elif 'network_stream' in csv_file:
                            detector_type = 'network'
                        elif 'file_stream' in csv_file:
                            detector_type = 'file'
                        else:
                            continue
                        
                        # Process the file
                        process_csv_data(csv_file, detector_type, detectors)
                        processed_files.add(csv_file)
            
            # Wait before checking again
            time.sleep(5)
            
    except KeyboardInterrupt:
        logger.info("Stopping directory monitoring...")

def run_test_mode():
    """
    Run in test mode with sample data
    """
    logger.info("Running in TEST MODE with sample data...")
    
    # Initialize detectors
    detectors = create_anomaly_detection_pipeline()
    login_detector, network_detector, file_detector = detectors
    
    # Test data
    test_cases = [
        # Login anomaly - unusual time and location
        {
            'type': 'login',
            'data': ('john.doe', 'Unknown Location', '2024-01-15T23:45:00', '192.168.1.100')
        },
        # Network anomaly - traffic spike
        {
            'type': 'network',
            'data': ('2024-01-15T14:30:00', 5000, '192.168.1.100')
        },
        # File transfer anomaly - large download
        {
            'type': 'file',
            'data': ('jane.smith', '2024-01-15T10:15:00', 250.5, 'download', 'sensitive_data.zip')
        }
    ]
    
    for i, test_case in enumerate(test_cases, 1):
        logger.info(f"\n{'='*60}")
        logger.info(f"Test Case {i}: {test_case['type'].upper()} Anomaly Detection")
        logger.info(f"{'='*60}")
        
        if test_case['type'] == 'login':
            anomaly = login_detector.detect_anomaly(*test_case['data'])
        elif test_case['type'] == 'network':
            anomaly = network_detector.detect_anomaly(*test_case['data'])
        elif test_case['type'] == 'file':
            anomaly = file_detector.detect_anomaly(*test_case['data'])
        
        if anomaly:
            logger.info(f"🚨 Anomaly detected!")
            logger.info(f"Raw data: {json.dumps(anomaly, indent=2)}")
            
            # Generate and send alert
            AlertSystem.send_alert(anomaly)
        else:
            logger.info("✅ No anomaly detected")
    
    logger.info(f"\n{'='*60}")
    logger.info("Test completed successfully!")
    logger.info(f"{'='*60}")

# ==================== Entry Point ====================
if __name__ == "__main__":
    import sys
    
    logger.info("Starting Real-Time Anomaly Detection System...")
    logger.info(f"Configuration:")
    logger.info(f"  - USE_LLM: {Config.USE_LLM}")
    logger.info(f"  - API Key: {'Loaded' if Config.OPENAI_API_KEY else 'Not found'}")
    logger.info(f"  - Model: {Config.OPENAI_MODEL}")
    
    # Create output directory
    os.makedirs("./output", exist_ok=True)
    
    # Check command line arguments
    if len(sys.argv) > 1 and sys.argv[1] == "--monitor":
        # Run in monitoring mode
        logger.info("Starting in MONITORING MODE...")
        try:
            monitor_directories()
        except KeyboardInterrupt:
            logger.info("Shutting down anomaly detection system...")
        except Exception as e:
            logger.error(f"System error: {e}")
            import traceback
            traceback.print_exc()
    else:
        # Run in test mode by default
        logger.info("Starting in TEST MODE...")
        logger.info("Use --monitor flag to run in monitoring mode")
        try:
            run_test_mode()
        except KeyboardInterrupt:
            logger.info("Shutting down anomaly detection system...")
        except Exception as e:
            logger.error(f"System error: {e}")
            import traceback
            traceback.print_exc()