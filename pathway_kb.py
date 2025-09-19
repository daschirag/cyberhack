"""
Pathway-backed Knowledge Base for Cybersecurity Anomaly Detection
Provides RAG (Retrieval-Augmented Generation) context for LLM explanations
"""

import json
import logging
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from collections import deque
import os

# Import existing StateManager
from anomaly_detection import StateManager, Config

logger = logging.getLogger(__name__)

class PathwayKB:
    """
    Knowledge Base for storing user profiles, anomaly history, and providing RAG context
    """
    
    def __init__(self):
        self.state_manager = StateManager()
        self.metrics = {
            'kb_upserts': 0,
            'kb_queries': 0,
            'vector_exports': 0,
            'vector_queries': 0
        }
        
        # Initialize vector DB if configured
        self.vector_db = None
        self._init_vector_db()
    
    def _init_vector_db(self):
        """Initialize vector database if configured"""
        if not Config.KB_ENABLE_RAG:
            return
            
        try:
            if Config.VECTOR_DB_BACKEND == 'chroma':
                self._init_chroma()
            elif Config.VECTOR_DB_BACKEND == 'pinecone':
                self._init_pinecone()
            else:
                logger.info("No vector DB backend configured, RAG will use in-memory similarity")
        except Exception as e:
            logger.warning(f"Vector DB initialization failed: {e}. Continuing without vector search.")
    
    def _init_chroma(self):
        """Initialize Chroma vector database"""
        try:
            import chromadb
            self.vector_db = chromadb.Client()
            self.collection = self.vector_db.get_or_create_collection(
                name=Config.VECTOR_COLLECTION or "anomalies"
            )
            logger.info("Chroma vector DB initialized")
        except ImportError:
            logger.warning("Chroma not installed. Install with: pip install chromadb")
        except Exception as e:
            logger.warning(f"Chroma initialization failed: {e}")
    
    def _init_pinecone(self):
        """Initialize Pinecone vector database"""
        try:
            import pinecone
            pinecone.init(api_key=os.getenv("PINECONE_API_KEY"), environment=os.getenv("PINECONE_ENV"))
            self.vector_db = pinecone.Index(Config.VECTOR_COLLECTION or "anomalies")
            logger.info("Pinecone vector DB initialized")
        except ImportError:
            logger.warning("Pinecone not installed. Install with: pip install pinecone-client")
        except Exception as e:
            logger.warning(f"Pinecone initialization failed: {e}")
    
    def upsert_user_event(self, username: str, event: Dict) -> Dict:
        """
        Upsert user profile with bounded history (last 20 logins, normal_hours, file stats)
        
        Args:
            username: User identifier
            event: Event data containing login/file transfer information
            
        Returns:
            Updated user profile
        """
        try:
            # Get existing profile
            profile = self.state_manager.get_user_profile(username)
            
            # Update based on event type
            if 'location' in event and 'timestamp' in event:
                # Login event
                login_entry = {
                    'location': event['location'],
                    'timestamp': event['timestamp'],
                    'ip_address': event.get('ip_address', 'unknown')
                }
                
                # Add to recent logins (bounded to 20)
                if 'recent_logins' not in profile:
                    profile['recent_logins'] = deque(maxlen=20)
                else:
                    profile['recent_logins'] = deque(profile['recent_logins'], maxlen=20)
                
                profile['recent_logins'].append(login_entry)
                profile['last_seen'] = event['timestamp']
                
                # Update normal hours (7 AM to 9 PM by default)
                if 'normal_hours' not in profile:
                    profile['normal_hours'] = list(range(7, 22))
            
            elif 'file_size_mb' in event:
                # File transfer event
                if 'file_stats' not in profile:
                    profile['file_stats'] = {
                        'total_transfers': 0,
                        'total_size_mb': 0.0,
                        'avg_size_mb': 0.0,
                        'max_size_mb': 0.0,
                        'recent_files': deque(maxlen=10)
                    }
                
                file_stats = profile['file_stats']
                file_stats['total_transfers'] += 1
                file_stats['total_size_mb'] += event['file_size_mb']
                file_stats['avg_size_mb'] = file_stats['total_size_mb'] / file_stats['total_transfers']
                file_stats['max_size_mb'] = max(file_stats['max_size_mb'], event['file_size_mb'])
                
                # Add recent file info
                file_info = {
                    'filename': event.get('filename', 'unknown'),
                    'size_mb': event['file_size_mb'],
                    'operation': event.get('operation', 'unknown'),
                    'timestamp': event.get('timestamp', datetime.now().isoformat())
                }
                file_stats['recent_files'].append(file_info)
            
            # Save updated profile
            self.state_manager.update_user_profile(username, profile)
            self.metrics['kb_upserts'] += 1
            
            logger.debug(f"Updated user profile for {username}: {len(profile.get('recent_logins', []))} logins, {profile.get('file_stats', {}).get('total_transfers', 0)} file transfers")
            
            return profile
            
        except Exception as e:
            logger.error(f"Error upserting user event: {e}")
            return {}
    
    def upsert_anomaly(self, anomaly: Dict) -> str:
        """
        Store anomaly summary in state and maintain recent anomalies index
        
        Args:
            anomaly: Anomaly data to store
            
        Returns:
            Anomaly ID
        """
        try:
            # Generate anomaly ID
            anomaly_id = hashlib.md5(
                f"{anomaly.get('timestamp', '')}{anomaly.get('type', '')}{anomaly.get('username', '')}".encode()
            ).hexdigest()[:12]
            
            # Create anomaly summary
            anomaly_summary = {
                'anomaly_id': anomaly_id,
                'type': anomaly.get('type', 'unknown'),
                'timestamp': anomaly.get('timestamp', datetime.now().isoformat()),
                'severity': anomaly.get('severity', 'UNKNOWN'),
                'username': anomaly.get('username', 'unknown'),
                'summary': self._create_anomaly_summary(anomaly),
                'features': self._extract_features(anomaly)
            }
            
            # Store individual anomaly
            self.state_manager.set(f"anomaly:{anomaly_id}", anomaly_summary, ttl=86400 * 30)  # 30 days
            
            # Update recent anomalies index (bounded to 500)
            recent_anomalies = self.state_manager.get("recent_anomalies", [])
            if not isinstance(recent_anomalies, list):
                recent_anomalies = []
            
            recent_anomalies.append({
                'anomaly_id': anomaly_id,
                'type': anomaly_summary['type'],
                'timestamp': anomaly_summary['timestamp'],
                'severity': anomaly_summary['severity'],
                'summary': anomaly_summary['summary']
            })
            
            # Keep only last 500
            if len(recent_anomalies) > 500:
                recent_anomalies = recent_anomalies[-500:]
            
            self.state_manager.set("recent_anomalies", recent_anomalies, ttl=86400 * 30)
            
            # Export to vector DB if configured
            if Config.KB_ENABLE_RAG and self.vector_db:
                self._export_to_vectordb([anomaly_summary])
            
            self.metrics['kb_upserts'] += 1
            logger.debug(f"Stored anomaly {anomaly_id}: {anomaly_summary['summary']}")
            
            return anomaly_id
            
        except Exception as e:
            logger.error(f"Error upserting anomaly: {e}")
            return "unknown"
    
    def get_context_for_anomaly(self, anomaly: Dict, max_items: int = 5) -> Dict:
        """
        Get sanitized, compact context for LLM
        
        Args:
            anomaly: Current anomaly data
            max_items: Maximum number of recent items to include
            
        Returns:
            Sanitized context object
        """
        try:
            context = {
                'masked_username': self._mask_username(anomaly.get('username', 'unknown')),
                'last_logins': [],
                'normal_hours': [],
                'file_summary': {},
                'recent_related_anomalies': [],
                'similar_anomalies': []
            }
            
            username = anomaly.get('username', 'unknown')
            if username != 'unknown':
                # Get user profile
                profile = self.state_manager.get_user_profile(username)
                
                # Get recent logins (sanitized)
                recent_logins = profile.get('recent_logins', [])
                if isinstance(recent_logins, deque):
                    recent_logins = list(recent_logins)
                
                for login in recent_logins[-max_items:]:
                    context['last_logins'].append({
                        'location': login.get('location', 'unknown'),
                        'timestamp': login.get('timestamp', ''),
                        'ip_masked': self._mask_ip(login.get('ip_address', 'unknown'))
                    })
                
                # Get normal hours
                context['normal_hours'] = profile.get('normal_hours', list(range(7, 22)))
                
                # Get file summary
                file_stats = profile.get('file_stats', {})
                if file_stats:
                    context['file_summary'] = {
                        'total_transfers': file_stats.get('total_transfers', 0),
                        'avg_size_mb': round(file_stats.get('avg_size_mb', 0), 1),
                        'max_size_mb': round(file_stats.get('max_size_mb', 0), 1)
                    }
            
            # Get recent related anomalies
            recent_anomalies = self.state_manager.get("recent_anomalies", [])
            anomaly_type = anomaly.get('type', 'unknown')
            
            related_anomalies = [
                a for a in recent_anomalies[-20:]  # Last 20 anomalies
                if a.get('type') == anomaly_type and a.get('anomaly_id') != anomaly.get('anomaly_id', '')
            ]
            
            context['recent_related_anomalies'] = related_anomalies[:3]  # Top 3 related
            
            # Get similar anomalies from vector DB if available
            if Config.KB_ENABLE_RAG and self.vector_db:
                similar = self.semantic_query(
                    self._create_anomaly_summary(anomaly), 
                    top_k=3
                )
                context['similar_anomalies'] = similar
            
            self.metrics['kb_queries'] += 1
            logger.debug(f"Generated context for anomaly: {len(context['last_logins'])} logins, {len(context['recent_related_anomalies'])} related anomalies")
            
            return context
            
        except Exception as e:
            logger.error(f"Error getting context for anomaly: {e}")
            return {'masked_username': 'unknown', 'error': str(e)}
    
    def export_anomalies_to_vectordb(self, batch: List[Dict]) -> bool:
        """
        Export anomalies to vector database (optional)
        
        Args:
            batch: List of anomaly summaries to export
            
        Returns:
            True if successful, False otherwise
        """
        if not Config.KB_ENABLE_RAG or not self.vector_db:
            return False
        
        try:
            return self._export_to_vectordb(batch)
        except Exception as e:
            logger.error(f"Error exporting to vector DB: {e}")
            return False
    
    def semantic_query(self, text: str, top_k: int = 5) -> List[Dict]:
        """
        Perform semantic search for similar anomalies
        
        Args:
            text: Query text
            top_k: Number of results to return
            
        Returns:
            List of similar anomaly summaries
        """
        if not Config.KB_ENABLE_RAG or not self.vector_db:
            return []
        
        try:
            if Config.VECTOR_DB_BACKEND == 'chroma':
                return self._chroma_query(text, top_k)
            elif Config.VECTOR_DB_BACKEND == 'pinecone':
                return self._pinecone_query(text, top_k)
            else:
                # Fallback to in-memory similarity
                return self._in_memory_similarity(text, top_k)
                
        except Exception as e:
            logger.error(f"Error in semantic query: {e}")
            return []
    
    def _export_to_vectordb(self, batch: List[Dict]) -> bool:
        """Export batch to vector database"""
        try:
            if Config.VECTOR_DB_BACKEND == 'chroma':
                return self._chroma_export(batch)
            elif Config.VECTOR_DB_BACKEND == 'pinecone':
                return self._pinecone_export(batch)
            return False
        except Exception as e:
            logger.error(f"Vector DB export failed: {e}")
            return False
    
    def _chroma_export(self, batch: List[Dict]) -> bool:
        """Export to Chroma"""
        try:
            documents = []
            metadatas = []
            ids = []
            
            for anomaly in batch:
                # Sanitize for vector DB
                sanitized = self._sanitize_for_vectordb(anomaly)
                documents.append(sanitized['summary'])
                metadatas.append({
                    'type': sanitized['type'],
                    'severity': sanitized['severity'],
                    'timestamp': sanitized['timestamp']
                })
                ids.append(sanitized['anomaly_id'])
            
            self.collection.add(
                documents=documents,
                metadatas=metadatas,
                ids=ids
            )
            
            self.metrics['vector_exports'] += len(batch)
            logger.debug(f"Exported {len(batch)} anomalies to Chroma")
            return True
            
        except Exception as e:
            logger.error(f"Chroma export failed: {e}")
            return False
    
    def _pinecone_export(self, batch: List[Dict]) -> bool:
        """Export to Pinecone"""
        try:
            # This would require OpenAI embeddings
            if not Config.OPENAI_API_KEY:
                logger.warning("OpenAI API key required for Pinecone export")
                return False
            
            # Implementation would go here
            logger.warning("Pinecone export not fully implemented")
            return False
            
        except Exception as e:
            logger.error(f"Pinecone export failed: {e}")
            return False
    
    def _chroma_query(self, text: str, top_k: int) -> List[Dict]:
        """Query Chroma for similar anomalies"""
        try:
            results = self.collection.query(
                query_texts=[text],
                n_results=top_k
            )
            
            similar_anomalies = []
            if results['documents'] and results['documents'][0]:
                for i, doc in enumerate(results['documents'][0]):
                    similar_anomalies.append({
                        'summary': doc,
                        'metadata': results['metadatas'][0][i] if results['metadatas'] else {},
                        'distance': results['distances'][0][i] if results['distances'] else 0
                    })
            
            self.metrics['vector_queries'] += 1
            return similar_anomalies
            
        except Exception as e:
            logger.error(f"Chroma query failed: {e}")
            return []
    
    def _pinecone_query(self, text: str, top_k: int) -> List[Dict]:
        """Query Pinecone for similar anomalies"""
        try:
            # Implementation would go here
            logger.warning("Pinecone query not fully implemented")
            return []
        except Exception as e:
            logger.error(f"Pinecone query failed: {e}")
            return []
    
    def _in_memory_similarity(self, text: str, top_k: int) -> List[Dict]:
        """Fallback in-memory similarity search"""
        try:
            recent_anomalies = self.state_manager.get("recent_anomalies", [])
            
            # Simple keyword matching
            text_lower = text.lower()
            similar = []
            
            for anomaly in recent_anomalies[-50:]:  # Check last 50
                summary = anomaly.get('summary', '').lower()
                if any(word in summary for word in text_lower.split()):
                    similar.append(anomaly)
                    if len(similar) >= top_k:
                        break
            
            return similar
            
        except Exception as e:
            logger.error(f"In-memory similarity failed: {e}")
            return []
    
    def _create_anomaly_summary(self, anomaly: Dict) -> str:
        """Create a concise summary of the anomaly"""
        try:
            parts = []
            
            if anomaly.get('type') == 'login':
                parts.append(f"Login from {anomaly.get('location', 'unknown location')}")
                if anomaly.get('anomalies'):
                    for a in anomaly['anomalies']:
                        parts.append(a.get('details', ''))
            
            elif anomaly.get('type') == 'network':
                parts.append(f"Network traffic spike: {anomaly.get('requests_per_minute', 0)} req/min")
                parts.append(f"Spike ratio: {anomaly.get('spike_ratio', 0):.1f}x")
            
            elif anomaly.get('type') == 'file_transfer':
                parts.append(f"File transfer: {anomaly.get('operation', 'unknown')} {anomaly.get('file_size_mb', 0):.1f}MB")
                parts.append(f"File: {anomaly.get('filename', 'unknown')}")
            
            return ". ".join(parts) if parts else "Security anomaly detected"
            
        except Exception as e:
            logger.error(f"Error creating anomaly summary: {e}")
            return "Security anomaly detected"
    
    def _extract_features(self, anomaly: Dict) -> Dict:
        """Extract key features from anomaly for vector search"""
        try:
            features = {
                'type': anomaly.get('type', 'unknown'),
                'severity': anomaly.get('severity', 'UNKNOWN'),
                'risk_score': anomaly.get('risk_score', 0),
                'timestamp': anomaly.get('timestamp', '')
            }
            
            # Add type-specific features
            if anomaly.get('type') == 'login':
                features.update({
                    'location': anomaly.get('location', ''),
                    'hour': self._extract_hour(anomaly.get('timestamp', ''))
                })
            elif anomaly.get('type') == 'network':
                features.update({
                    'requests_per_minute': anomaly.get('requests_per_minute', 0),
                    'spike_ratio': anomaly.get('spike_ratio', 0)
                })
            elif anomaly.get('type') == 'file_transfer':
                features.update({
                    'file_size_mb': anomaly.get('file_size_mb', 0),
                    'operation': anomaly.get('operation', ''),
                    'file_extension': self._get_file_extension(anomaly.get('filename', ''))
                })
            
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features: {e}")
            return {}
    
    def _sanitize_for_vectordb(self, anomaly: Dict) -> Dict:
        """Sanitize anomaly data for vector DB export"""
        try:
            sanitized = anomaly.copy()
            
            # Mask PII unless explicitly allowed
            if not Config.KB_PII_EXPORT:
                sanitized['username'] = self._mask_username(sanitized.get('username', 'unknown'))
                
                # Mask IP addresses in features
                if 'features' in sanitized and 'ip_address' in sanitized['features']:
                    sanitized['features']['ip_address'] = self._mask_ip(sanitized['features']['ip_address'])
            
            return sanitized
            
        except Exception as e:
            logger.error(f"Error sanitizing for vector DB: {e}")
            return anomaly
    
    def _mask_username(self, username: str) -> str:
        """Mask username for privacy"""
        if not username or username == 'unknown':
            return 'unknown'
        if len(username) <= 1:
            return username[0] + '***'
        return username[0] + '***'
    
    def _mask_ip(self, ip: str) -> str:
        """Mask IP address for privacy"""
        if not ip or ip == 'unknown':
            return 'unknown'
        parts = ip.split('.')
        if len(parts) == 4:
            return f"{parts[0]}.{parts[1]}.xxx.xxx"
        return 'xxx.xxx.xxx.xxx'
    
    def _extract_hour(self, timestamp: str) -> int:
        """Extract hour from timestamp"""
        try:
            if timestamp:
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return dt.hour
        except:
            pass
        return 0
    
    def _get_file_extension(self, filename: str) -> str:
        """Get file extension"""
        try:
            if filename and '.' in filename:
                return filename.split('.')[-1].lower()
        except:
            pass
        return 'unknown'
    
    def get_metrics(self) -> Dict:
        """Get KB metrics"""
        return self.metrics.copy()

# Global KB instance
KB_INSTANCE = PathwayKB()
