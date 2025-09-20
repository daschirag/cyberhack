"""
Real-Time Cybersecurity Anomaly Detection System using Pathway
Production-hardened version with fixes for edge cases and scalability
"""

import pathway as pw
from pathway.stdlib.ml.index import KNNIndex
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from dateutil import parser as date_parser
import json
import os
import logging
import threading
import queue
from typing import Dict, List, Optional, Tuple
from collections import deque, defaultdict
import hashlib
import time
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Redis for persistent state (optional)
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

# OpenAI for intelligent alerts (optional)
try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

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
    BASELINE_TRAFFIC_RPM = 100.0  # Normal requests per minute
    BASELINE_FILE_SIZE_MB = 10.0  # Normal file size
    MIN_BASELINE = 1.0  # Minimum baseline to avoid division by zero
    
    # Alert rate limiting
    ALERT_THROTTLE_SECONDS = 60  # Minimum seconds between similar alerts
    ALERT_BATCH_WINDOW = 5  # Seconds to batch similar alerts
    MAX_ALERTS_PER_WINDOW = 10  # Maximum alerts per time window
    
    # Output configuration - FIXED
    OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./output")
    INPUT_DIR = os.getenv("INPUT_DIR", "./input")
    
    # State persistence
    REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    STATE_BACKEND = os.getenv("STATE_BACKEND", "memory")  # memory, redis, or rocksdb
    
    # Alert endpoints
    SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", "")
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL", "")
    
    # LLM Configuration
    USE_LLM = os.getenv("USE_LLM", "true").lower() == "true"
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
    OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")
    PREFER_LOCAL_LLM = os.getenv("PREFER_LOCAL_LLM", "false").lower() == "true"
    
    # KNN Anomaly Detection
    USE_KNN_DETECTION = os.getenv("USE_KNN_DETECTION", "false").lower() == "true"
    KNN_NEIGHBORS = 5
    ANOMALY_THRESHOLD = 2.0  # Standard deviations from mean
    
    # Knowledge Base Configuration
    KB_ENABLE_RAG = os.getenv("KB_ENABLE_RAG", "true").lower() == "true"
    KB_CONTEXT_MAX_ITEMS = int(os.getenv("KB_CONTEXT_MAX_ITEMS", "5"))
    KB_PII_EXPORT = os.getenv("KB_PII_EXPORT", "false").lower() == "true"
    
    # Vector Database Configuration
    VECTOR_DB_BACKEND = os.getenv("VECTOR_DB_BACKEND", "chroma")  # chroma, pinecone, or none
    VECTOR_DB_URL = os.getenv("VECTOR_DB_URL", "")
    VECTOR_COLLECTION = os.getenv("VECTOR_COLLECTION", "anomalies")

# ==================== State Management ====================
class StateManager:
    """Manages persistent state across restarts and distributed systems"""
    
    def __init__(self):
        self.backend = Config.STATE_BACKEND
        self.redis_client = None
        
        if self.backend == "redis" and REDIS_AVAILABLE:
            try:
                self.redis_client = redis.from_url(Config.REDIS_URL)
                self.redis_client.ping()
                logger.info("Connected to Redis for state persistence")
            except Exception as e:
                logger.warning(f"Redis connection failed: {e}. Falling back to memory")
                self.backend = "memory"
        
        # In-memory fallback
        self.memory_store = defaultdict(dict)
    
    def get(self, key: str, default=None):
        """Get value from persistent store"""
        if self.backend == "redis" and self.redis_client:
            try:
                value = self.redis_client.get(key)
                if value:
                    return json.loads(value)
            except Exception as e:
                logger.error(f"Redis get error: {e}")
        
        return self.memory_store.get(key, default)
    
    def set(self, key: str, value, ttl=None):
        """Set value in persistent store"""
        if self.backend == "redis" and self.redis_client:
            try:
                self.redis_client.set(key, json.dumps(value), ex=ttl)
                return True
            except Exception as e:
                logger.error(f"Redis set error: {e}")
        
        self.memory_store[key] = value
        return True
    
    def get_user_profile(self, username: str) -> Dict:
        """Get user profile with defaults"""
        key = f"user:{username}"
        profile = self.get(key)
        if not profile:
            profile = {
                'locations': [],
                'normal_hours': list(range(7, 22)),
                'ip_addresses': [],
                'avg_login_count': 5,
                'last_seen': None
            }
        return profile
    
    def update_user_profile(self, username: str, profile: Dict):
        """Update user profile"""
        key = f"user:{username}"
        self.set(key, profile, ttl=86400 * 7)  # 7 days TTL

# ==================== Data Schemas - FIXED ====================
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
    operation: str
    filename: str

# Output Schema for Anomalies
class AnomalySchema(pw.Schema):
    anomaly_data: str  # JSON string of the anomaly

# ==================== Alert Rate Limiter ====================
class AlertRateLimiter:
    """Prevents alert flooding and groups similar alerts"""
    
    def __init__(self):
        self.alert_history = deque(maxlen=1000)
        self.alert_counts = defaultdict(lambda: deque(maxlen=100))
        self.alert_queue = queue.Queue()
        self.batch_buffer = defaultdict(list)
        self.last_alert_time = defaultdict(float)
        
        # Start background thread for batching
        self.batch_thread = threading.Thread(target=self._batch_processor, daemon=True)
        self.batch_thread.start()
    
    def should_alert(self, alert_key: str, severity: str = "MEDIUM") -> bool:
        """Check if we should send this alert based on rate limiting"""
        current_time = time.time()
        
        # Check throttling
        if alert_key in self.last_alert_time:
            time_since_last = current_time - self.last_alert_time[alert_key]
            if time_since_last < Config.ALERT_THROTTLE_SECONDS:
                # Allow CRITICAL alerts through more often
                if severity != "CRITICAL" or time_since_last < 10:
                    return False
        
        # Check rate limiting
        window_start = current_time - 300  # 5 minute window
        recent_alerts = sum(1 for t in self.alert_counts[alert_key] if t > window_start)
        
        if recent_alerts >= Config.MAX_ALERTS_PER_WINDOW:
            return False
        
        # Record this alert
        self.alert_counts[alert_key].append(current_time)
        self.last_alert_time[alert_key] = current_time
        return True
    
    def add_to_batch(self, alert_type: str, alert_data: Dict):
        """Add alert to batch for grouped sending"""
        key = f"{alert_type}:{alert_data.get('severity', 'UNKNOWN')}"
        self.batch_buffer[key].append(alert_data)
    
    def _batch_processor(self):
        """Background thread to process batched alerts"""
        while True:
            time.sleep(Config.ALERT_BATCH_WINDOW)
            self._flush_batches()
    
    def _flush_batches(self):
        """Send batched alerts"""
        if not self.batch_buffer:
            return
        
        for key, alerts in self.batch_buffer.items():
            if len(alerts) > 1:
                # Group similar alerts
                grouped_alert = self._group_alerts(alerts)
                self.alert_queue.put(grouped_alert)
            else:
                self.alert_queue.put(alerts[0])
        
        self.batch_buffer.clear()
    
    def _group_alerts(self, alerts: List[Dict]) -> Dict:
        """Group multiple similar alerts into one"""
        first = alerts[0]
        return {
            'type': 'grouped',
            'count': len(alerts),
            'severity': first.get('severity', 'UNKNOWN'),
            'message': f"[GROUPED] {len(alerts)} similar alerts: {first.get('message', '')}",
            'details': alerts[:3]  # Include first 3 for context
        }

# ==================== Global State Manager Instance ====================
STATE_MANAGER = StateManager()
RATE_LIMITER = AlertRateLimiter()

# ==================== Enhanced Anomaly Detectors - FIXED ====================
@pw.udf
def detect_login_anomaly(username: str, location: str, timestamp: str, ip_address: str) -> str:
    """Detect login anomalies with robust parsing and state management"""
    try:
        # Safe timestamp parsing
        try:
            dt = date_parser.isoparse(timestamp.replace('Z', '+00:00'))
        except:
            dt = datetime.now()  # Fallback to current time
            logger.warning(f"Failed to parse timestamp: {timestamp}")
        
        hour = dt.hour
        
        # Get persistent user profile
        profile = STATE_MANAGER.get_user_profile(username)
        
        # Initialize if new user
        if not profile['locations']:
            profile['locations'] = [location]
            profile['ip_addresses'] = [ip_address]
            profile['last_seen'] = timestamp
            STATE_MANAGER.update_user_profile(username, profile)
            return ""  # No anomaly for new users
        
        anomalies = []
        
        # Location analysis with confidence scoring
        if location not in profile['locations']:
            # Calculate geographic anomaly score (simplified)
            anomaly_score = 30 if location in ['Moscow', 'Beijing', 'Unknown'] else 20
            anomalies.append({
                'type': 'unusual_location',
                'severity': 'HIGH' if anomaly_score >= 30 else 'MEDIUM',
                'score': anomaly_score,
                'details': f"Login from new location: {location} (usual: {', '.join(profile['locations'][:2])})"
            })
            profile['locations'].append(location)
            if len(profile['locations']) > 10:
                profile['locations'] = profile['locations'][-10:]  # Keep last 10
        
        # Time-based analysis with weekday consideration
        if hour >= Config.LOGIN_TIME_THRESHOLD or hour <= Config.LOGIN_TIME_EARLY_THRESHOLD:
            is_weekend = dt.weekday() >= 5
            severity = 'LOW' if is_weekend else 'MEDIUM'
            anomalies.append({
                'type': 'unusual_time',
                'severity': severity,
                'score': 15 if is_weekend else 25,
                'details': f"Login at unusual hour: {hour:02d}:00"
            })
        
        # IP reputation check
        suspicious_ips = ['185.220.', '31.13.', '103.251.', '45.142.']  # Known bad prefixes
        if any(ip_address.startswith(prefix) for prefix in suspicious_ips):
            anomalies.append({
                'type': 'suspicious_ip',
                'severity': 'CRITICAL',
                'score': 40,
                'details': f"Login from suspicious IP: {ip_address}"
            })
        elif ip_address not in profile['ip_addresses']:
            anomalies.append({
                'type': 'new_ip',
                'severity': 'LOW',
                'score': 10,
                'details': f"Login from new IP: {ip_address}"
            })
            profile['ip_addresses'].append(ip_address)
            if len(profile['ip_addresses']) > 20:
                profile['ip_addresses'] = profile['ip_addresses'][-20:]
        
        # Update profile
        profile['last_seen'] = timestamp
        STATE_MANAGER.update_user_profile(username, profile)
        
        if anomalies:
            # Calculate normalized risk score
            raw_score = sum(a['score'] for a in anomalies)
            risk_score = min(100, int(raw_score * 1.2))  # Normalize and cap at 100
            
            # Determine overall severity
            severities = [a['severity'] for a in anomalies]
            if 'CRITICAL' in severities:
                severity = 'CRITICAL'
            elif 'HIGH' in severities:
                severity = 'HIGH'
            elif 'MEDIUM' in severities:
                severity = 'MEDIUM'
            else:
                severity = 'LOW'
            
            # Check rate limiting
            alert_key = f"login:{username}:{location}"
            if not RATE_LIMITER.should_alert(alert_key, severity):
                return ""  # Throttled
            
            result = {
                'username': username,
                'location': location,
                'timestamp': timestamp,
                'ip_address': ip_address,
                'anomalies': anomalies,
                'risk_score': risk_score,
                'severity': severity,
                'type': 'login_anomaly'
            }
            
            return json.dumps(result, default=str)
            
    except Exception as e:
        logger.error(f"Error in login anomaly detection: {e}")
    
    return ""

@pw.udf 
def detect_network_anomaly(timestamp: str, requests_per_minute: int, source_ip: str) -> str:
    """Detect traffic anomalies with robust baseline calculation"""
    try:
        # Validate input
        if requests_per_minute < 0:
            logger.warning(f"Invalid RPM value: {requests_per_minute}")
            return ""
        
        # Simple spike detection (in production, you'd use more sophisticated methods)
        baseline = Config.BASELINE_TRAFFIC_RPM
        spike_ratio = requests_per_minute / max(baseline, Config.MIN_BASELINE)
        
        # Detect anomalies based on spike ratio
        if spike_ratio > Config.TRAFFIC_SPIKE_MULTIPLIER:
            # Calculate severity based on spike ratio
            if spike_ratio > 50:
                severity = 'CRITICAL'
                risk_score = 90
            elif spike_ratio > 20:
                severity = 'HIGH'
                risk_score = 70
            else:
                severity = 'MEDIUM'
                risk_score = 50
            
            # Rate limiting
            alert_key = f"network:{source_ip}"
            if not RATE_LIMITER.should_alert(alert_key, severity):
                return ""
            
            result = {
                'timestamp': timestamp,
                'requests_per_minute': requests_per_minute,
                'baseline': baseline,
                'spike_ratio': spike_ratio,
                'source_ip': source_ip,
                'severity': severity,
                'risk_score': risk_score,
                'type': 'network_anomaly',
                'details': f"Traffic {spike_ratio:.1f}x baseline"
            }
            
            return json.dumps(result, default=str)
            
    except Exception as e:
        logger.error(f"Error in network anomaly detection: {e}")
    
    return ""

@pw.udf
def detect_file_anomaly(username: str, timestamp: str, file_size_mb: float, 
                       operation: str, filename: str) -> str:
    """Detect file transfer anomalies with pattern analysis"""
    try:
        # Validate input
        if file_size_mb < 0:
            logger.warning(f"Invalid file size: {file_size_mb}")
            return ""
        
        anomalies = []
        
        # Check for suspicious file patterns
        suspicious_extensions = ['.sql', '.dump', '.bak', '.zip', '.rar', '.7z']
        suspicious_keywords = ['password', 'credential', 'secret', 'key', 'token', 
                              'database', 'backup', 'dump', 'customer', 'financial']
        
        filename_lower = filename.lower()
        if any(filename_lower.endswith(ext) for ext in suspicious_extensions):
            anomalies.append({
                'type': 'suspicious_file_type',
                'severity': 'HIGH',
                'score': 30,
                'details': f"Suspicious file type: {filename}"
            })
        
        if any(keyword in filename_lower for keyword in suspicious_keywords):
            anomalies.append({
                'type': 'sensitive_filename',
                'severity': 'HIGH',
                'score': 35,
                'details': f"Potentially sensitive file: {filename}"
            })
        
        # Absolute threshold check
        if file_size_mb > Config.FILE_SIZE_THRESHOLD_MB:
            severity = 'CRITICAL' if file_size_mb > 500 else 'HIGH'
            anomalies.append({
                'type': 'large_transfer',
                'severity': severity,
                'score': 40 if severity == 'CRITICAL' else 30,
                'details': f"Large {operation}: {file_size_mb:.1f}MB"
            })
        
        if anomalies:
            # Calculate risk score with normalization
            raw_score = sum(a['score'] for a in anomalies)
            risk_score = min(100, int(raw_score * 1.1))
            
            # Determine severity
            severities = [a['severity'] for a in anomalies]
            if 'CRITICAL' in severities:
                severity = 'CRITICAL'
            elif 'HIGH' in severities:
                severity = 'HIGH'
            else:
                severity = 'MEDIUM'
            
            # Rate limiting
            alert_key = f"file:{username}:{operation}"
            if not RATE_LIMITER.should_alert(alert_key, severity):
                return ""
            
            result = {
                'username': username,
                'timestamp': timestamp,
                'file_size_mb': file_size_mb,
                'operation': operation,
                'filename': filename,
                'anomalies': anomalies,
                'risk_score': risk_score,
                'severity': severity,
                'type': 'file_anomaly'
            }
            
            return json.dumps(result, default=str)
            
    except Exception as e:
        logger.error(f"Error in file transfer anomaly detection: {e}")
    
    return ""

# ==================== Sample Data Generator ====================
def create_sample_data():
    """Create sample input data files for testing"""
    os.makedirs(Config.INPUT_DIR, exist_ok=True)
    os.makedirs(Config.OUTPUT_DIR, exist_ok=True)
    
    # Sample login data
    login_data = [
        {"username": "john_doe", "location": "New York", "timestamp": "2025-09-20T14:30:00Z", "ip_address": "192.168.1.100"},
        {"username": "jane_smith", "location": "Moscow", "timestamp": "2025-09-20T23:45:00Z", "ip_address": "185.220.100.50"},
        {"username": "bob_wilson", "location": "London", "timestamp": "2025-09-20T09:15:00Z", "ip_address": "10.0.0.50"}
    ]
    
    # Sample network data
    network_data = [
        {"timestamp": "2025-09-20T14:30:00Z", "requests_per_minute": 150, "source_ip": "192.168.1.100"},
        {"timestamp": "2025-09-20T14:31:00Z", "requests_per_minute": 1500, "source_ip": "192.168.1.101"},
        {"timestamp": "2025-09-20T14:32:00Z", "requests_per_minute": 80, "source_ip": "192.168.1.102"}
    ]
    
    # Sample file transfer data
    file_data = [
        {"username": "john_doe", "timestamp": "2025-09-20T14:30:00Z", "file_size_mb": 50.5, "operation": "upload", "filename": "report.pdf"},
        {"username": "jane_smith", "timestamp": "2025-09-20T14:35:00Z", "file_size_mb": 250.0, "operation": "download", "filename": "database_backup.sql"},
        {"username": "bob_wilson", "timestamp": "2025-09-20T14:40:00Z", "file_size_mb": 15.2, "operation": "upload", "filename": "document.docx"}
    ]
    
    # Write sample data files
    with open(os.path.join(Config.INPUT_DIR, "login_data.jsonl"), "w") as f:
        for item in login_data:
            f.write(json.dumps(item) + "\n")
    
    with open(os.path.join(Config.INPUT_DIR, "network_data.jsonl"), "w") as f:
        for item in network_data:
            f.write(json.dumps(item) + "\n")
    
    with open(os.path.join(Config.INPUT_DIR, "file_data.jsonl"), "w") as f:
        for item in file_data:
            f.write(json.dumps(item) + "\n")
    
    logger.info(f"Created sample data files in {Config.INPUT_DIR}")

# ==================== Main Pipeline - FIXED ====================
def main():
    """Main function to set up and run the anomaly detection pipeline"""
    
    # Create sample data for testing
    create_sample_data()
    
    logger.info("Starting Real-Time Cybersecurity Anomaly Detection System")
    logger.info(f"Input directory: {Config.INPUT_DIR}")
    logger.info(f"Output directory: {Config.OUTPUT_DIR}")
    
    try:
        # Input connectors - Read from JSONL files
        login_table = pw.io.jsonlines.read(
            os.path.join(Config.INPUT_DIR, "login_data.jsonl"),
            schema=LoginSchema,
            mode="streaming"
        )
        
        network_table = pw.io.jsonlines.read(
            os.path.join(Config.INPUT_DIR, "network_data.jsonl"),
            schema=NetworkTrafficSchema,
            mode="streaming"
        )
        
        file_table = pw.io.jsonlines.read(
            os.path.join(Config.INPUT_DIR, "file_data.jsonl"),
            schema=FileTransferSchema,
            mode="streaming"
        )
        
        # Apply anomaly detection UDFs
        login_anomalies = login_table.select(
            anomaly_data=detect_login_anomaly(
                login_table.username,
                login_table.location,
                login_table.timestamp,
                login_table.ip_address
            )
        ).filter(pw.this.anomaly_data != "")
        
        network_anomalies = network_table.select(
            anomaly_data=detect_network_anomaly(
                network_table.timestamp,
                network_table.requests_per_minute,
                network_table.source_ip
            )
        ).filter(pw.this.anomaly_data != "")
        
        file_anomalies = file_table.select(
            anomaly_data=detect_file_anomaly(
                file_table.username,
                file_table.timestamp,
                file_table.file_size_mb,
                file_table.operation,
                file_table.filename
            )
        ).filter(pw.this.anomaly_data != "")
        
        # Output connectors - Write to JSONL files
        pw.io.jsonlines.write(
            login_anomalies,
            os.path.join(Config.OUTPUT_DIR, "login_anomalies.jsonl")
        )
        
        pw.io.jsonlines.write(
            network_anomalies,
            os.path.join(Config.OUTPUT_DIR, "network_anomalies.jsonl")
        )
        
        pw.io.jsonlines.write(
            file_anomalies,
            os.path.join(Config.OUTPUT_DIR, "file_anomalies.jsonl")
        )
        
        logger.info("Pipeline configured successfully")
        logger.info("Starting streaming computation...")
        
        # Run the pipeline
        pw.run()
        
    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        raise

if __name__ == "__main__":
    main()
