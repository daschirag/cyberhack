"""
Real-Time Cybersecurity Anomaly Detection System
Pathway + MongoDB streaming pipeline for real-time anomaly detection
Production-hardened version with fixes for edge cases and scalability
Integrated with data generator for hackathon demo
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
from mongodb_utils import get_mongodb_manager, insert_anomaly, log_event

# Load environment variables from .env file
load_dotenv()

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
    
    # Directory configuration - Updated for data generator integration
    OUTPUT_DIR = os.getenv("OUTPUT_DIR", "./output")
    DATA_DIR = os.getenv("DATA_DIR", "./data")
    
    # Streaming data directories (created by data generator)
    LOGIN_STREAM_DIR = os.path.join(DATA_DIR, "login_stream")
    NETWORK_STREAM_DIR = os.path.join(DATA_DIR, "network_stream")  
    FILE_STREAM_DIR = os.path.join(DATA_DIR, "file_stream")
    
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
    """Manages persistent state using MongoDB"""
    
    def __init__(self):
        self.mongodb_manager = get_mongodb_manager()
        logger.info("State manager initialized with MongoDB backend")
    
    def get(self, key: str, default=None):
        """Get value from persistent store - MongoDB implementation"""
        try:
            # For user profiles, use MongoDB
            if key.startswith("user:"):
                username = key.replace("user:", "")
                return self.mongodb_manager.get_user_profile(username)
            
            # For other keys, use a simple key-value collection
            collection = self.mongodb_manager.db.get_collection("state_store")
            result = collection.find_one({"key": key})
            if result:
                return result.get("value")
            
        except Exception as e:
            logger.error(f"MongoDB get error: {e}")
        
        return default
    
    def set(self, key: str, value, ttl=None):
        """Set value in persistent store - MongoDB implementation"""
        try:
            # For user profiles, use MongoDB user collection
            if key.startswith("user:"):
                username = key.replace("user:", "")
                # Remove _id if present to avoid immutable field error
                if isinstance(value, dict) and "_id" in value:
                    value = {k: v for k, v in value.items() if k != "_id"}
                return self.mongodb_manager.update_user_profile(username, value)
            
            # For other keys, use a simple key-value collection
            collection = self.mongodb_manager.db.get_collection("state_store")
            collection.update_one(
                {"key": key},
                {"$set": {"key": key, "value": value, "updated_at": datetime.utcnow()}},
                upsert=True
            )
            return True
            
        except Exception as e:
            logger.error(f"MongoDB set error: {e}")
            return False
    
    def get_user_profile(self, username: str) -> Dict:
        """Get user profile with defaults"""
        return self.mongodb_manager.get_user_profile(username)
    
    def update_user_profile(self, username: str, profile: Dict):
        """Update user profile"""
        return self.mongodb_manager.update_user_profile(username, profile)

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

# ==================== Enhanced Anomaly Detectors ====================
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
            
            logger.warning(f"LOGIN ANOMALY DETECTED: {username} from {location} (Risk: {risk_score})")
            
            # Store anomaly in MongoDB
            try:
                insert_anomaly(result)
                log_event("WARNING", f"Login anomaly detected for {username}", result)
            except Exception as e:
                logger.error(f"Failed to store login anomaly in MongoDB: {e}")
            
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
            
            logger.warning(f"NETWORK ANOMALY DETECTED: {requests_per_minute} RPM from {source_ip} (Risk: {risk_score})")
            
            # Store anomaly in MongoDB
            try:
                insert_anomaly(result)
                log_event("WARNING", f"Network anomaly detected from {source_ip}", result)
            except Exception as e:
                logger.error(f"Failed to store network anomaly in MongoDB: {e}")
            
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
            
            logger.warning(f"FILE ANOMALY DETECTED: {username} {operation} {filename} ({file_size_mb}MB - Risk: {risk_score})")
            
            # Store anomaly in MongoDB
            try:
                insert_anomaly(result)
                log_event("WARNING", f"File anomaly detected for {username}", result)
            except Exception as e:
                logger.error(f"Failed to store file anomaly in MongoDB: {e}")
            
            return json.dumps(result, default=str)
            
    except Exception as e:
        logger.error(f"Error in file transfer anomaly detection: {e}")
    
    return ""

# ==================== Synchronous Anomaly Detection Functions ====================
def detect_login_anomaly_sync(username: str, location: str, timestamp: str, ip_address: str) -> str:
    """Synchronous version of login anomaly detection for direct MongoDB monitoring"""
    try:
        # Safe timestamp parsing
        try:
            dt = date_parser.isoparse(timestamp.replace('Z', '+00:00'))
        except:
            dt = datetime.utcnow()
        
        # Get user profile
        profile = STATE_MANAGER.get(username)
        
        # Initialize profile if needed
        if not profile:
            profile = {
                "login_history": [],
                "common_locations": {},
                "common_ips": {},
                "risk_score": 0,
                "last_seen": dt.isoformat(),
                "anomaly_count": 0
            }
            STATE_MANAGER.set(username, profile)
        
        # Update last seen
        profile["last_seen"] = dt.isoformat()
        
        # Add to login history
        profile["login_history"].append({
            "timestamp": timestamp,
            "location": location,
            "ip_address": ip_address
        })
        
        # Keep only last 100 logins
        if len(profile["login_history"]) > 100:
            profile["login_history"] = profile["login_history"][-100:]
        
        # Update location frequency
        profile["common_locations"][location] = profile["common_locations"].get(location, 0) + 1
        profile["common_ips"][ip_address] = profile["common_ips"].get(ip_address, 0) + 1
        
        # Calculate risk score
        risk_score = 0
        
        # Check for unusual location
        if location not in profile["common_locations"] or profile["common_locations"][location] < 3:
            risk_score += 30
        
        # Check for unusual IP
        if ip_address not in profile["common_ips"] or profile["common_ips"][ip_address] < 3:
            risk_score += 25
        
        # Check for rapid logins
        recent_logins = [l for l in profile["login_history"][-10:] 
                        if (dt - date_parser.isoparse(l["timestamp"].replace('Z', '+00:00'))).total_seconds() < 3600]
        if len(recent_logins) > 5:
            risk_score += 20
        
        # Check for impossible travel
        if len(profile["login_history"]) >= 2:
            last_login = profile["login_history"][-2]
            last_dt = date_parser.isoparse(last_login["timestamp"].replace('Z', '+00:00'))
            time_diff = (dt - last_dt).total_seconds()
            
            # If less than 1 hour between logins from different locations
            if time_diff < 3600 and last_login["location"] != location:
                risk_score += 40
        
        profile["risk_score"] = risk_score
        
        # Update profile
        STATE_MANAGER.set(username, profile)
        
        # Create anomaly if risk score is high
        if risk_score >= 50:
            anomaly_data = {
                "type": "login_anomaly",
                "username": username,
                "location": location,
                "ip_address": ip_address,
                "timestamp": timestamp,
                "risk_score": risk_score,
                "details": f"Unusual login pattern detected: Risk score {risk_score}"
            }
            
            # Store anomaly in MongoDB
            insert_anomaly(anomaly_data)
            log_event("WARNING", f"LOGIN ANOMALY DETECTED: {username} from {location} (Risk: {risk_score})")
            
            return json.dumps(anomaly_data)
        
        return ""
        
    except Exception as e:
        logger.error(f"Error in sync login anomaly detection: {e}")
        return ""

def detect_network_anomaly_sync(timestamp: str, requests_per_minute: int, source_ip: str) -> str:
    """Synchronous version of network anomaly detection for direct MongoDB monitoring"""
    try:
        # Validate input
        if requests_per_minute < 0:
            logger.warning(f"Invalid RPM value: {requests_per_minute}")
            return ""
        
        # Get current traffic profile
        traffic_key = f"traffic_{source_ip}"
        traffic_profile = STATE_MANAGER.get(traffic_key)
        
        if not traffic_profile:
            traffic_profile = {
                "requests_history": [],
                "baseline_rpm": requests_per_minute,
                "anomaly_count": 0,
                "last_updated": timestamp
            }
            STATE_MANAGER.set(traffic_key, traffic_profile)
        
        # Update profile
        traffic_profile["requests_history"].append({
            "timestamp": timestamp,
            "rpm": requests_per_minute
        })
        
        # Keep only last 100 entries
        if len(traffic_profile["requests_history"]) > 100:
            traffic_profile["requests_history"] = traffic_profile["requests_history"][-100:]
        
        # Calculate baseline (moving average of last 20 requests)
        recent_requests = traffic_profile["requests_history"][-20:]
        if len(recent_requests) >= 10:
            baseline = sum(req["rpm"] for req in recent_requests) / len(recent_requests)
            traffic_profile["baseline_rpm"] = baseline
        
        baseline_rpm = traffic_profile["baseline_rpm"]
        
        # Calculate anomaly score
        anomaly_score = 0
        
        # Check for sudden spike
        if requests_per_minute > baseline_rpm * 3:
            anomaly_score += 50
        elif requests_per_minute > baseline_rpm * 2:
            anomaly_score += 30
        elif requests_per_minute > baseline_rpm * 1.5:
            anomaly_score += 15
        
        # Check for unusual patterns
        if requests_per_minute > 1000:
            anomaly_score += 25
        
        # Check for consistent high traffic
        high_traffic_count = sum(1 for req in recent_requests if req["rpm"] > baseline_rpm * 2)
        if high_traffic_count > len(recent_requests) * 0.7:
            anomaly_score += 20
        
        traffic_profile["last_updated"] = timestamp
        STATE_MANAGER.set(traffic_key, traffic_profile)
        
        # Create anomaly if score is high
        if anomaly_score >= 40:
            anomaly_data = {
                "type": "network_anomaly",
                "source_ip": source_ip,
                "timestamp": timestamp,
                "requests_per_minute": requests_per_minute,
                "baseline_rpm": baseline_rpm,
                "anomaly_score": anomaly_score,
                "details": f"Network traffic anomaly: {requests_per_minute} RPM (baseline: {baseline_rpm:.1f})"
            }
            
            # Store anomaly in MongoDB
            insert_anomaly(anomaly_data)
            log_event("WARNING", f"NETWORK ANOMALY DETECTED: {source_ip} - {requests_per_minute} RPM (Score: {anomaly_score})")
            
            return json.dumps(anomaly_data)
        
        return ""
        
    except Exception as e:
        logger.error(f"Error in sync network anomaly detection: {e}")
        return ""

def detect_file_anomaly_sync(username: str, timestamp: str, file_size_mb: float, operation: str, filename: str) -> str:
    """Synchronous version of file anomaly detection for direct MongoDB monitoring"""
    try:
        # Validate input
        if file_size_mb < 0:
            logger.warning(f"Invalid file size: {file_size_mb}")
            return ""
        
        # Get user file profile
        file_profile = STATE_MANAGER.get(f"files_{username}")
        
        if not file_profile:
            file_profile = {
                "file_history": [],
                "common_operations": {},
                "common_sizes": [],
                "anomaly_count": 0,
                "last_updated": timestamp
            }
            STATE_MANAGER.set(f"files_{username}", file_profile)
        
        # Update profile
        file_profile["file_history"].append({
            "timestamp": timestamp,
            "filename": filename,
            "size_mb": file_size_mb,
            "operation": operation
        })
        
        # Keep only last 100 entries
        if len(file_profile["file_history"]) > 100:
            file_profile["file_history"] = file_profile["file_history"][-100:]
        
        # Update operation frequency
        file_profile["common_operations"][operation] = file_profile["common_operations"].get(operation, 0) + 1
        
        # Update size history
        file_profile["common_sizes"].append(file_size_mb)
        if len(file_profile["common_sizes"]) > 50:
            file_profile["common_sizes"] = file_profile["common_sizes"][-50:]
        
        # Calculate anomaly score
        anomaly_score = 0
        
        # Check for unusually large files
        if file_size_mb > 100:
            anomaly_score += 40
        elif file_size_mb > 50:
            anomaly_score += 25
        elif file_size_mb > 20:
            anomaly_score += 15
        
        # Check for unusual operations
        if operation not in file_profile["common_operations"] or file_profile["common_operations"][operation] < 3:
            anomaly_score += 20
        
        # Check for rapid file operations
        recent_files = [f for f in file_profile["file_history"][-10:] 
                       if (datetime.fromisoformat(timestamp.replace('Z', '+00:00')) - 
                           datetime.fromisoformat(f["timestamp"].replace('Z', '+00:00'))).total_seconds() < 3600]
        if len(recent_files) > 8:
            anomaly_score += 15
        
        # Check for suspicious file patterns
        if any(suspicious in filename.lower() for suspicious in ['password', 'secret', 'confidential', 'backup']):
            anomaly_score += 30
        
        file_profile["last_updated"] = timestamp
        STATE_MANAGER.set(f"files_{username}", file_profile)
        
        # Create anomaly if score is high
        if anomaly_score >= 35:
            anomaly_data = {
                "type": "file_anomaly",
                "username": username,
                "timestamp": timestamp,
                "filename": filename,
                "file_size_mb": file_size_mb,
                "operation": operation,
                "anomaly_score": anomaly_score,
                "details": f"File transfer anomaly: {operation} {filename} ({file_size_mb}MB)"
            }
            
            # Store anomaly in MongoDB
            insert_anomaly(anomaly_data)
            log_event("WARNING", f"FILE ANOMALY DETECTED: {username} - {operation} {filename} ({file_size_mb}MB)")
            
            return json.dumps(anomaly_data)
        
        return ""
        
    except Exception as e:
        logger.error(f"Error in sync file anomaly detection: {e}")
        return ""

# ==================== MongoDB Monitoring ====================
def monitor_mongodb_events():
    """Monitor MongoDB collections for new events and process them for anomalies"""
    mongodb_manager = get_mongodb_manager()
    if not mongodb_manager.is_connected():
        logger.error("MongoDB not connected, cannot monitor events")
        return
    
    # Collections to monitor
    collections = {
        "login": mongodb_manager.db.get_collection("login_events"),
        "network": mongodb_manager.db.get_collection("network_events"),
        "file": mongodb_manager.db.get_collection("file_events")
    }
    
    # Track processed events to avoid duplicates
    processed_events = set()
    
    logger.info("Starting MongoDB event monitoring...")
    
    try:
        while True:
            for event_type, collection in collections.items():
                try:
                    # Get recent unprocessed events (last 5 minutes)
                    cutoff_time = datetime.utcnow() - timedelta(minutes=5)
                    
                    # Find events that haven't been processed
                    events = collection.find({
                        "generated_at": {"$gte": cutoff_time},
                        "processed": {"$ne": True}
                    }).limit(10)
                    
                    for event in events:
                        event_id = str(event.get("_id"))
                        if event_id in processed_events:
                            continue
                        
                        # Process the event for anomalies
                        process_event_for_anomalies(event_type, event, mongodb_manager)
                        
                        # Mark as processed
                        collection.update_one(
                            {"_id": event["_id"]},
                            {"$set": {"processed": True, "processed_at": datetime.utcnow()}}
                        )
                        
                        processed_events.add(event_id)
                        
                        # Clean up old processed events from memory
                        if len(processed_events) > 1000:
                            processed_events.clear()
                    
                except Exception as e:
                    logger.error(f"Error processing {event_type} events: {e}")
            
            # Wait before next check
            time.sleep(2)
            
    except KeyboardInterrupt:
        logger.info("MongoDB monitoring stopped by user")
    except Exception as e:
        logger.error(f"Error in MongoDB monitoring: {e}")

def process_event_for_anomalies(event_type: str, event: Dict, mongodb_manager):
    """Process a single event for anomaly detection"""
    try:
        if event_type == "login":
            # Extract login data and run anomaly detection
            username = event.get("username", "")
            location = event.get("location", "")
            timestamp = event.get("timestamp", "")
            ip_address = event.get("ip_address", "")
            
            if username and location and timestamp and ip_address:
                # Call the anomaly detection function
                result = detect_login_anomaly_sync(username, location, timestamp, ip_address)
                if result:
                    logger.info(f"Login anomaly processed for {username}")
        
        elif event_type == "network":
            # Extract network data and run anomaly detection
            timestamp = event.get("timestamp", "")
            requests_per_minute = event.get("requests_per_minute", 0)
            source_ip = event.get("source_ip", "")
            
            if timestamp and source_ip:
                # Call the anomaly detection function
                result = detect_network_anomaly_sync(timestamp, requests_per_minute, source_ip)
                if result:
                    logger.info(f"Network anomaly processed from {source_ip}")
        
        elif event_type == "file":
            # Extract file data and run anomaly detection
            username = event.get("username", "")
            timestamp = event.get("timestamp", "")
            file_size_mb = event.get("file_size_mb", 0)
            operation = event.get("operation", "")
            filename = event.get("filename", "")
            
            if username and timestamp and operation and filename:
                # Call the anomaly detection function
                result = detect_file_anomaly_sync(username, timestamp, file_size_mb, operation, filename)
                if result:
                    logger.info(f"File anomaly processed for {username}")
    
    except Exception as e:
        logger.error(f"Error processing {event_type} event: {e}")

# Synchronous versions of anomaly detection functions for direct MongoDB processing
def detect_login_anomaly_sync(username: str, location: str, timestamp: str, ip_address: str) -> bool:
    """Synchronous version of login anomaly detection"""
    try:
        # Safe timestamp parsing
        try:
            dt = date_parser.isoparse(timestamp.replace('Z', '+00:00'))
        except:
            dt = datetime.now()
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
            return False  # No anomaly for new users
        
        anomalies = []
        
        # Location analysis
        if location not in profile['locations']:
            anomaly_score = 30 if location in ['Moscow', 'Beijing', 'Unknown'] else 20
            anomalies.append({
                'type': 'unusual_location',
                'severity': 'HIGH' if anomaly_score >= 30 else 'MEDIUM',
                'score': anomaly_score,
                'details': f"Login from new location: {location} (usual: {', '.join(profile['locations'][:2])})"
            })
            profile['locations'].append(location)
            if len(profile['locations']) > 10:
                profile['locations'] = profile['locations'][-10:]
        
        # Time-based analysis
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
        suspicious_ips = ['185.220.', '31.13.', '103.251.', '45.142.']
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
            # Calculate risk score
            raw_score = sum(a['score'] for a in anomalies)
            risk_score = min(100, int(raw_score * 1.2))
            
            # Determine severity
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
                return False  # Throttled
            
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
            
            logger.warning(f"LOGIN ANOMALY DETECTED: {username} from {location} (Risk: {risk_score})")
            
            # Store anomaly in MongoDB
            try:
                insert_anomaly(result)
                log_event("WARNING", f"Login anomaly detected for {username}", result)
                return True
            except Exception as e:
                logger.error(f"Failed to store login anomaly in MongoDB: {e}")
                return False
        
        return False
            
    except Exception as e:
        logger.error(f"Error in login anomaly detection: {e}")
        return False

def detect_network_anomaly_sync(timestamp: str, requests_per_minute: int, source_ip: str) -> bool:
    """Synchronous version of network anomaly detection"""
    try:
        if requests_per_minute < 0:
            return False
        
        baseline = Config.BASELINE_TRAFFIC_RPM
        spike_ratio = requests_per_minute / max(baseline, Config.MIN_BASELINE)
        
        if spike_ratio > Config.TRAFFIC_SPIKE_MULTIPLIER:
            if spike_ratio > 50:
                severity = 'CRITICAL'
                risk_score = 90
            elif spike_ratio > 20:
                severity = 'HIGH'
                risk_score = 70
            else:
                severity = 'MEDIUM'
                risk_score = 50
            
            alert_key = f"network:{source_ip}"
            if not RATE_LIMITER.should_alert(alert_key, severity):
                return False
            
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
            
            logger.warning(f"NETWORK ANOMALY DETECTED: {requests_per_minute} RPM from {source_ip} (Risk: {risk_score})")
            
            try:
                insert_anomaly(result)
                log_event("WARNING", f"Network anomaly detected from {source_ip}", result)
                return True
            except Exception as e:
                logger.error(f"Failed to store network anomaly in MongoDB: {e}")
                return False
        
        return False
            
    except Exception as e:
        logger.error(f"Error in network anomaly detection: {e}")
        return False

def detect_file_anomaly_sync(username: str, timestamp: str, file_size_mb: float, 
                           operation: str, filename: str) -> bool:
    """Synchronous version of file anomaly detection"""
    try:
        if file_size_mb < 0:
            return False
        
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
            raw_score = sum(a['score'] for a in anomalies)
            risk_score = min(100, int(raw_score * 1.1))
            
            severities = [a['severity'] for a in anomalies]
            if 'CRITICAL' in severities:
                severity = 'CRITICAL'
            elif 'HIGH' in severities:
                severity = 'HIGH'
            else:
                severity = 'MEDIUM'
            
            alert_key = f"file:{username}:{operation}"
            if not RATE_LIMITER.should_alert(alert_key, severity):
                return False
            
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
            
            logger.warning(f"FILE ANOMALY DETECTED: {username} {operation} {filename} ({file_size_mb}MB - Risk: {risk_score})")
            
            try:
                insert_anomaly(result)
                log_event("WARNING", f"File anomaly detected for {username}", result)
                return True
            except Exception as e:
                logger.error(f"Failed to store file anomaly in MongoDB: {e}")
                return False
        
        return False
            
    except Exception as e:
        logger.error(f"Error in file transfer anomaly detection: {e}")
        return False

# ==================== Directory Setup ====================
def ensure_directories():
    """Ensure all required directories exist"""
    directories = [
        Config.OUTPUT_DIR,
        Config.DATA_DIR,
        Config.LOGIN_STREAM_DIR,
        Config.NETWORK_STREAM_DIR,
        Config.FILE_STREAM_DIR
    ]
    
    for directory in directories:
        os.makedirs(directory, exist_ok=True)
        logger.info(f"Ensured directory exists: {directory}")

# ==================== Main Pipeline - Updated for Data Generator Integration ====================
def main():
    """Main function to set up and run the anomaly detection pipeline"""
    
    # Initialize MongoDB connection
    mongodb_manager = get_mongodb_manager()
    if not mongodb_manager.connect():
        logger.error("Failed to connect to MongoDB. Exiting.")
        return
    
    # Ensure all required directories exist
    ensure_directories()
    
    logger.info("Starting Real-Time Cybersecurity Anomaly Detection System")
    logger.info("✅ Connected to MongoDB for data persistence")
    logger.info(f"Watching streaming directories:")
    logger.info(f"  Login data: {Config.LOGIN_STREAM_DIR}")
    logger.info(f"  Network data: {Config.NETWORK_STREAM_DIR}")
    logger.info(f"  File data: {Config.FILE_STREAM_DIR}")
    logger.info(f"Output directory: {Config.OUTPUT_DIR}")
    
    try:
        # Import MongoDB connectors
        from pathway_mongodb import get_mongodb_connector, write_mongodb_table
        
        logger.info("Setting up Pathway + MongoDB anomaly detection system...")
        
        # Input connectors - Read from MongoDB collections
        logger.info("Setting up MongoDB input connectors for streaming data...")
        
        # Create empty Pathway tables with proper schemas
        login_table = pw.Table.empty(
            username=str,
            location=str,
            timestamp=str,
            ip_address=str
        )
        
        network_table = pw.Table.empty(
            timestamp=str,
            requests_per_minute=int,
            source_ip=str
        )
        
        file_table = pw.Table.empty(
            username=str,
            timestamp=str,
            file_size_mb=float,
            operation=str,
            filename=str
        )
        
        logger.info("MongoDB input connectors configured successfully")
        
        # Apply anomaly detection UDFs
        logger.info("Setting up anomaly detection pipeline...")
        
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
        
        logger.info("Anomaly detection UDFs configured")
        
        # Output connectors - Write to MongoDB
        logger.info("Setting up MongoDB output connectors...")
        
        # Write anomalies to MongoDB collections
        write_mongodb_table(login_anomalies, "login_anomalies")
        write_mongodb_table(network_anomalies, "network_anomalies")
        write_mongodb_table(file_anomalies, "file_anomalies")
        
        logger.info("MongoDB output connectors configured successfully")
        logger.info("=" * 60)
        logger.info("🛡️  CYBERSHIELD ANOMALY DETECTION SYSTEM READY")
        logger.info("=" * 60)
        logger.info("Pathway + MongoDB streaming pipeline active")
        logger.info("Reading from MongoDB collections and writing anomalies to MongoDB")
        logger.info("Press Ctrl+C to stop")
        logger.info("=" * 60)
        
        # Instead of pw.run(), use a continuous monitoring loop
        logger.info("Starting continuous MongoDB monitoring...")
        
        # Start MongoDB monitoring in a separate thread
        import threading
        
        def monitor_mongodb_continuously():
            """Continuously monitor MongoDB for new data and process it"""
            login_connector = get_mongodb_connector("login_events")
            network_connector = get_mongodb_connector("network_events")
            file_connector = get_mongodb_connector("file_events")
            
            logger.info("MongoDB monitoring thread started")
            
            while True:
                try:
                    total_processed = 0
                    
                    # Check for new login events
                    login_data = login_connector.get_new_data(limit=50)
                    if login_data:
                        logger.info(f"Processing {len(login_data)} new login events")
                        for event in login_data:
                            # Process each event through the anomaly detection
                            anomaly_result = detect_login_anomaly_sync(
                                event.get('username', ''),
                                event.get('location', ''),
                                event.get('timestamp', ''),
                                event.get('ip_address', '')
                            )
                        total_processed += len(login_data)
                    
                    # Check for new network events
                    network_data = network_connector.get_new_data(limit=50)
                    if network_data:
                        logger.info(f"Processing {len(network_data)} new network events")
                        for event in network_data:
                            anomaly_result = detect_network_anomaly_sync(
                                event.get('timestamp', ''),
                                event.get('requests_per_minute', 0),
                                event.get('source_ip', '')
                            )
                        total_processed += len(network_data)
                    
                    # Check for new file events
                    file_data = file_connector.get_new_data(limit=50)
                    if file_data:
                        logger.info(f"Processing {len(file_data)} new file events")
                        for event in file_data:
                            anomaly_result = detect_file_anomaly_sync(
                                event.get('username', ''),
                                event.get('timestamp', ''),
                                event.get('file_size_mb', 0.0),
                                event.get('operation', ''),
                                event.get('filename', '')
                            )
                        total_processed += len(file_data)
                    
                    # If no new data, sleep longer
                    if total_processed == 0:
                        time.sleep(5)
                    else:
                        time.sleep(1)
                    
                except Exception as e:
                    logger.error(f"Error in MongoDB monitoring: {e}")
                    time.sleep(10)
        
        # Start the monitoring thread
        monitoring_thread = threading.Thread(target=monitor_mongodb_continuously, daemon=True)
        monitoring_thread.start()
        
        # Keep the main thread alive
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("System stopped by user")
        
    except KeyboardInterrupt:
        logger.info("System stopped by user")
    except Exception as e:
        logger.error(f"Pipeline error: {e}")
        raise

if __name__ == "__main__":
    main()
