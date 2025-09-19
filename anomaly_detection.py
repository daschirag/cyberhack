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

# ==================== Enhanced Anomaly Detectors ====================
class LoginAnomalyDetector:
    """Detects unusual login patterns with persistent state"""
    
    def __init__(self):
        self.state_manager = StateManager()
        self.rate_limiter = AlertRateLimiter()
        
        # KNN for advanced detection (optional)
        if Config.USE_KNN_DETECTION:
            self.knn_index = None  # Would be initialized with feature vectors
    
    @pw.udf
    def detect_anomaly(self, username: str, location: str, timestamp: str, ip_address: str) -> Optional[Dict]:
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
            profile = self.state_manager.get_user_profile(username)
            
            # Initialize if new user
            if not profile['locations']:
                profile['locations'] = [location]
                profile['ip_addresses'] = [ip_address]
                profile['last_seen'] = timestamp
                self.state_manager.update_user_profile(username, profile)
                return None
            
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
            self.state_manager.update_user_profile(username, profile)
            
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
                if not self.rate_limiter.should_alert(alert_key, severity):
                    return None  # Throttled
                
                result = {
                    'username': username,
                    'location': location,
                    'timestamp': timestamp,
                    'ip_address': ip_address,
                    'anomalies': anomalies,
                    'risk_score': risk_score,
                    'severity': severity
                }
                
                # Update Knowledge Base
                try:
                    from pathway_kb import KB_INSTANCE
                    # Upsert user event
                    KB_INSTANCE.upsert_user_event(username, {
                        'location': location,
                        'timestamp': timestamp,
                        'ip_address': ip_address
                    })
                    # Upsert anomaly
                    KB_INSTANCE.upsert_anomaly(result)
                except Exception as kb_error:
                    logger.warning(f"KB update failed: {kb_error}")
                
                return result
                
        except Exception as e:
            logger.error(f"Error in login anomaly detection: {e}")
            
        return None

class NetworkAnomalyDetector:
    """Detects network traffic anomalies with statistical models"""
    
    def __init__(self):
        self.state_manager = StateManager()
        self.rate_limiter = AlertRateLimiter()
        self.traffic_history = deque(maxlen=100)
        self.baseline_rpm = Config.BASELINE_TRAFFIC_RPM
        self.ewma_alpha = 0.1  # Exponential weighted moving average
        self.ewma_baseline = Config.BASELINE_TRAFFIC_RPM
        
    @pw.udf
    def detect_anomaly(self, timestamp: str, requests_per_minute: int, source_ip: str) -> Optional[Dict]:
        """Detect traffic anomalies with robust baseline calculation"""
        try:
            # Validate input
            if requests_per_minute < 0:
                logger.warning(f"Invalid RPM value: {requests_per_minute}")
                return None
            
            # Update traffic history
            self.traffic_history.append(float(requests_per_minute))
            
            # Calculate robust baseline using EWMA
            if len(self.traffic_history) > 1:
                # Exponential weighted moving average
                self.ewma_baseline = (self.ewma_alpha * requests_per_minute + 
                                     (1 - self.ewma_alpha) * self.ewma_baseline)
                
                # Also calculate median for robustness
                median_baseline = np.median(list(self.traffic_history)[:-1])
                
                # Use combination of EWMA and median
                self.baseline_rpm = 0.7 * self.ewma_baseline + 0.3 * median_baseline
            
            # Ensure baseline is never zero
            baseline = max(self.baseline_rpm, Config.MIN_BASELINE)
            
            # Calculate spike ratio safely
            spike_ratio = requests_per_minute / baseline
            
            # Statistical anomaly detection using z-score
            if len(self.traffic_history) > 10:
                mean_traffic = np.mean(list(self.traffic_history)[:-1])
                std_traffic = np.std(list(self.traffic_history)[:-1])
                if std_traffic > 0:
                    z_score = abs((requests_per_minute - mean_traffic) / std_traffic)
                else:
                    z_score = 0
            else:
                z_score = 0
            
            # Detect anomalies based on multiple criteria
            is_spike = spike_ratio > Config.TRAFFIC_SPIKE_MULTIPLIER
            is_statistical_anomaly = z_score > Config.ANOMALY_THRESHOLD
            
            if is_spike or is_statistical_anomaly:
                # Calculate severity based on multiple factors
                if spike_ratio > 50 or z_score > 4:
                    severity = 'CRITICAL'
                    risk_score = 90
                elif spike_ratio > 20 or z_score > 3:
                    severity = 'HIGH'
                    risk_score = 70
                else:
                    severity = 'MEDIUM'
                    risk_score = 50
                
                # Add confidence based on history size
                confidence = min(1.0, len(self.traffic_history) / 20)
                risk_score = int(risk_score * confidence)
                
                # Rate limiting
                alert_key = f"network:{source_ip}"
                if not self.rate_limiter.should_alert(alert_key, severity):
                    return None
                
                result = {
                    'timestamp': timestamp,
                    'requests_per_minute': requests_per_minute,
                    'baseline': baseline,
                    'spike_ratio': spike_ratio,
                    'z_score': z_score,
                    'source_ip': source_ip,
                    'severity': severity,
                    'risk_score': risk_score,
                    'anomaly_type': 'traffic_spike',
                    'confidence': confidence,
                    'details': f"Traffic {spike_ratio:.1f}x baseline, Z-score: {z_score:.2f}"
                }
                
                # Update Knowledge Base
                try:
                    from pathway_kb import KB_INSTANCE
                    # Upsert anomaly (network anomalies don't have user context)
                    KB_INSTANCE.upsert_anomaly(result)
                except Exception as kb_error:
                    logger.warning(f"KB update failed: {kb_error}")
                
                return result
                
        except Exception as e:
            logger.error(f"Error in network anomaly detection: {e}")
            
        return None

class FileTransferAnomalyDetector:
    """Detects suspicious file transfers with user behavior profiling"""
    
    def __init__(self):
        self.state_manager = StateManager()
        self.rate_limiter = AlertRateLimiter()
        
    @pw.udf
    def detect_anomaly(self, username: str, timestamp: str, file_size_mb: float, 
                       operation: str, filename: str) -> Optional[Dict]:
        """Detect file transfer anomalies with pattern analysis"""
        try:
            # Validate input
            if file_size_mb < 0:
                logger.warning(f"Invalid file size: {file_size_mb}")
                return None
            
            # Get user's file transfer patterns
            key = f"file_pattern:{username}"
            pattern = self.state_manager.get(key)
            if not pattern:
                pattern = {
                    'avg_size': Config.BASELINE_FILE_SIZE_MB,
                    'max_size': Config.BASELINE_FILE_SIZE_MB,
                    'sizes': [],
                    'transfer_count': 0,
                    'suspicious_files': 0
                }
            
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
            
            # Size-based analysis with statistical approach
            if pattern['transfer_count'] > 5:
                # Calculate percentile-based threshold
                sizes = pattern['sizes'][-50:]  # Last 50 transfers
                if sizes:
                    p95 = np.percentile(sizes, 95)
                    if file_size_mb > p95 * 2:
                        anomalies.append({
                            'type': 'abnormal_size',
                            'severity': 'MEDIUM',
                            'score': 25,
                            'details': f"File size {file_size_mb:.1f}MB exceeds 95th percentile"
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
            
            # Update pattern with bounded history
            pattern['sizes'].append(file_size_mb)
            if len(pattern['sizes']) > 100:
                pattern['sizes'] = pattern['sizes'][-100:]  # Keep last 100
            
            pattern['transfer_count'] += 1
            pattern['avg_size'] = np.mean(pattern['sizes'])
            pattern['max_size'] = max(pattern['max_size'], file_size_mb)
            
            if anomalies:
                pattern['suspicious_files'] += 1
            
            # Save updated pattern
            self.state_manager.set(key, pattern, ttl=86400 * 30)  # 30 days TTL
            
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
                if not self.rate_limiter.should_alert(alert_key, severity):
                    return None
                
                result = {
                    'username': username,
                    'timestamp': timestamp,
                    'file_size_mb': file_size_mb,
                    'operation': operation,
                    'filename': filename,
                    'anomalies': anomalies,
                    'risk_score': risk_score,
                    'severity': severity,
                    'historical_avg': pattern['avg_size']
                }
                
                # Update Knowledge Base
                try:
                    from pathway_kb import KB_INSTANCE
                    # Upsert user event
                    KB_INSTANCE.upsert_user_event(username, {
                        'file_size_mb': file_size_mb,
                        'filename': filename,
                        'operation': operation,
                        'timestamp': timestamp
                    })
                    # Upsert anomaly
                    KB_INSTANCE.upsert_anomaly(result)
                except Exception as kb_error:
                    logger.warning(f"KB update failed: {kb_error}")
                
                return result
                
        except Exception as e:
            logger.error(f"Error in file transfer anomaly detection: {e}")
            
        return None

# ==================== Alert System with Async Webhooks ====================
class AlertSystem:
    """Manages alert generation and distribution with non-blocking operations"""
    
    def __init__(self):
        self.webhook_queue = queue.Queue()
        self.webhook_thread = threading.Thread(target=self._webhook_processor, daemon=True)
        self.webhook_thread.start()
    
    @staticmethod
    def sanitize_for_llm(data: Dict) -> Dict:
        """Remove PII and sensitive data before sending to LLM"""
        sanitized = data.copy()
        
        # Redact sensitive fields
        if 'ip_address' in sanitized:
            parts = sanitized['ip_address'].split('.')
            if len(parts) == 4:
                sanitized['ip_address'] = f"{parts[0]}.{parts[1]}.xxx.xxx"
        
        if 'username' in sanitized:
            # Keep only first letter
            sanitized['username'] = sanitized['username'][0] + '***' if sanitized['username'] else 'unknown'
        
        if 'filename' in sanitized:
            # Keep extension only
            import os.path
            _, ext = os.path.splitext(sanitized['filename'])
            sanitized['filename'] = f"***{ext}"
        
        return sanitized
    
    def generate_llm_explanation(self, anomaly: Dict) -> str:
        """Generate explanation with privacy protection and RAG context"""
        if not Config.USE_LLM or not anomaly:
            return self._generate_template_explanation(anomaly)
        
        # Get RAG context if enabled
        rag_context = ""
        if Config.KB_ENABLE_RAG:
            try:
                from pathway_kb import KB_INSTANCE
                context = KB_INSTANCE.get_context_for_anomaly(anomaly, max_items=Config.KB_CONTEXT_MAX_ITEMS)
                rag_context = self._build_rag_context_string(context)
            except Exception as e:
                logger.warning(f"RAG context retrieval failed: {e}")
        
        # Prefer local LLM for privacy
        if Config.PREFER_LOCAL_LLM:
            try:
                return self._ollama_explain(anomaly, rag_context)
            except:
                pass
        
        # Use OpenAI with sanitized data and RAG context
        if Config.OPENAI_API_KEY and OPENAI_AVAILABLE:
            sanitized = self.sanitize_for_llm(anomaly)
            return self._openai_explain(sanitized, rag_context)
        
        return self._generate_template_explanation(anomaly)
    
    def _build_rag_context_string(self, context: Dict) -> str:
        """Build compact RAG context string for LLM"""
        try:
            if not context or context.get('error'):
                return ""
            
            parts = []
            
            # User context
            if context.get('masked_username') and context['masked_username'] != 'unknown':
                parts.append(f"User {context['masked_username']}")
            
            # Recent logins
            if context.get('last_logins'):
                login_parts = []
                for login in context['last_logins'][:3]:  # Max 3 recent logins
                    location = login.get('location', 'unknown')
                    timestamp = login.get('timestamp', '')
                    if timestamp:
                        try:
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            time_str = dt.strftime('%m-%d %H:%M')
                        except:
                            time_str = 'recent'
                    else:
                        time_str = 'recent'
                    login_parts.append(f"{location}@{time_str}")
                
                if login_parts:
                    parts.append(f"last_logins: [{', '.join(login_parts)}]")
            
            # Normal hours
            if context.get('normal_hours'):
                hours = context['normal_hours']
                if hours:
                    start_hour = min(hours)
                    end_hour = max(hours)
                    parts.append(f"normal_hours: {start_hour:02d}-{end_hour:02d}")
            
            # File summary
            if context.get('file_summary') and context['file_summary'].get('total_transfers', 0) > 0:
                fs = context['file_summary']
                parts.append(f"file_summary: {fs['total_transfers']} transfers, avg {fs['avg_size_mb']:.1f}MB")
            
            # Recent related anomalies
            if context.get('recent_related_anomalies'):
                related_parts = []
                for anomaly in context['recent_related_anomalies'][:2]:  # Max 2 related
                    anomaly_type = anomaly.get('type', 'unknown')
                    timestamp = anomaly.get('timestamp', '')
                    if timestamp:
                        try:
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            date_str = dt.strftime('%m-%d')
                        except:
                            date_str = 'recent'
                    else:
                        date_str = 'recent'
                    
                    if anomaly_type == 'file_transfer':
                        related_parts.append(f"Large file {date_str}")
                    elif anomaly_type == 'login':
                        related_parts.append(f"login-new-ip {date_str}")
                    else:
                        related_parts.append(f"{anomaly_type} {date_str}")
                
                if related_parts:
                    parts.append(f"recent_related: [{', '.join(related_parts)}]")
            
            # Similar anomalies
            if context.get('similar_anomalies'):
                similar_parts = []
                for similar in context['similar_anomalies'][:2]:  # Max 2 similar
                    summary = similar.get('summary', '')
                    if summary:
                        # Truncate long summaries
                        if len(summary) > 30:
                            summary = summary[:27] + "..."
                        similar_parts.append(summary)
                
                if similar_parts:
                    parts.append(f"Similar: {', '.join(similar_parts)}")
            
            if parts:
                context_str = "CONTEXT (redacted): " + "; ".join(parts)
                # Ensure it's under 250 tokens (roughly 200 characters)
                if len(context_str) > 200:
                    context_str = context_str[:197] + "..."
                return context_str
            
            return ""
            
        except Exception as e:
            logger.error(f"Error building RAG context: {e}")
            return ""
    
    def _generate_template_explanation(self, anomaly: Dict) -> str:
        """Generate template-based explanation"""
        if not anomaly:
            return "⚠️ Unknown anomaly detected"
        
        # Template generation logic (same as before but with better error handling)
        try:
            if anomaly.get('anomaly_type') == 'traffic_spike':
                return (f"🚨 NETWORK: {anomaly.get('spike_ratio', 0):.1f}x traffic spike detected. "
                       f"Current: {anomaly.get('requests_per_minute', 0)} req/min. "
                       f"Risk: {anomaly.get('risk_score', 0)}/100")
            elif 'operation' in anomaly:
                return (f"📁 FILE: User performed {anomaly.get('operation', 'unknown')} "
                       f"of {anomaly.get('file_size_mb', 0):.1f}MB file. "
                       f"Risk: {anomaly.get('risk_score', 0)}/100")
            elif 'location' in anomaly:
                return (f"🔐 LOGIN: Suspicious activity from {anomaly.get('location', 'unknown')}. "
                       f"Risk: {anomaly.get('risk_score', 0)}/100")
        except Exception as e:
            logger.error(f"Template generation error: {e}")
        
        return "⚠️ Security anomaly detected"
    
    def _openai_explain(self, anomaly: Dict, rag_context: str = "") -> str:
        """Generate explanation using OpenAI (with sanitized data and RAG context)"""
        if not OPENAI_AVAILABLE:
            return self._generate_template_explanation(anomaly)
        
        try:
            openai.api_key = Config.OPENAI_API_KEY
            
            # Create context based on anomaly type
            context = json.dumps(anomaly, default=str)
            
            # Build system message with RAG context
            system_content = "You are a security analyst. Generate a brief, actionable alert message (max 50 words). Do not mention specific usernames or IPs."
            if rag_context:
                system_content += f"\n\n{rag_context}"
            
            response = openai.ChatCompletion.create(
                model=Config.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": system_content},
                    {"role": "user", "content": f"Explain this security anomaly: {context}"}
                ],
                temperature=0.3,
                max_tokens=100
            )
            
            return response.choices[0].message['content'].strip()
            
        except Exception as e:
            logger.error(f"OpenAI error: {e}")
            return self._generate_template_explanation(anomaly)
    
    def _ollama_explain(self, anomaly: Dict, rag_context: str = "") -> str:
        """Use local Ollama for privacy-preserving explanations"""
        try:
            import requests
            sanitized = self.sanitize_for_llm(anomaly)
            
            # Build prompt with RAG context
            prompt = f"Security alert (max 30 words): {json.dumps(sanitized)}"
            if rag_context:
                prompt = f"{rag_context}\n\n{prompt}"
            
            response = requests.post(
                Config.OLLAMA_URL,
                json={
                    "model": "llama2",
                    "prompt": prompt,
                    "stream": False
                },
                timeout=3
            )
            
            if response.status_code == 200:
                return response.json()['response'][:200]
        except:
            pass
        
        return self._generate_template_explanation(anomaly)
    
    @pw.udf
    def send_alert(self, anomaly: Dict) -> None:
        """Non-blocking alert sending"""
        if not anomaly:
            return
        
        try:
            # Generate message
            message = self.generate_llm_explanation(anomaly)
            
            # Console output (immediate)
            logger.warning(f"\n{'='*60}\n{message}\n{json.dumps(anomaly, indent=2, default=str)}\n{'='*60}")
            
            # Queue for async webhook sending
            self.webhook_queue.put({
                'message': message,
                'anomaly': anomaly
            })
            
            # Write to output (for dashboard)
            self._write_to_output(anomaly)
            
        except Exception as e:
            logger.error(f"Alert sending error: {e}")
    
    def _webhook_processor(self):
        """Background thread for webhook sending"""
        while True:
            try:
                alert = self.webhook_queue.get(timeout=1)
                self._send_to_webhooks(alert['message'])
            except queue.Empty:
                continue
            except Exception as e:
                logger.error(f"Webhook processor error: {e}")
    
    def _send_to_webhooks(self, message: str):
        """Send to webhooks (non-blocking, already in background thread)"""
        import requests
        
        if Config.SLACK_WEBHOOK_URL:
            try:
                requests.post(
                    Config.SLACK_WEBHOOK_URL,
                    json={"text": message},
                    timeout=5
                )
            except Exception as e:
                logger.error(f"Slack webhook error: {e}")
        
        if Config.DISCORD_WEBHOOK_URL:
            try:
                requests.post(
                    Config.DISCORD_WEBHOOK_URL,
                    json={"content": message},
                    timeout=5
                )
            except Exception as e:
                logger.error(f"Discord webhook error: {e}")
    
    def _write_to_output(self, anomaly: Dict):
        """Write anomaly to output file for dashboard"""
        try:
            import os
            os.makedirs("./output", exist_ok=True)
            
            # Determine output file based on anomaly type
            if anomaly.get('anomaly_type') == 'traffic_spike':
                filename = "./output/network_anomalies.jsonl"
            elif 'operation' in anomaly:
                filename = "./output/file_anomalies.jsonl"
            elif 'location' in anomaly:
                filename = "./output/login_anomalies.jsonl"
            else:
                filename = "./output/unknown_anomalies.jsonl"
            
            with open(filename, 'a') as f:
                json.dump({'anomaly': anomaly}, f)
                f.write('\n')
                
        except Exception as e:
            logger.error(f"Output write error: {e}")