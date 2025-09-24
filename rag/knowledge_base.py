"""
Knowledge Base Management for Cybersecurity RAG
Handles loading, chunking, and processing of security knowledge documents
"""

import os
import json
import glob
from typing import List, Dict, Any, Optional
from pathlib import Path
import hashlib
import logging

from .config import RAGConfig

logger = logging.getLogger(__name__)

class KnowledgeBase:
    """Manages cybersecurity knowledge base documents"""
    
    def __init__(self, kb_path: Optional[str] = None):
        self.kb_path = kb_path or RAGConfig.KNOWLEDGE_BASE_PATH
        self.documents = []
        self.chunks = []
        
    def load_documents(self) -> List[Dict[str, Any]]:
        """Load all knowledge documents from the knowledge base directory"""
        documents = []
        
        # Supported file types
        patterns = ["*.md", "*.txt", "*.json"]
        
        for pattern in patterns:
            files = glob.glob(os.path.join(self.kb_path, pattern))
            for file_path in files:
                doc = self._load_single_document(file_path)
                if doc:
                    documents.append(doc)
        
        logger.info(f"Loaded {len(documents)} documents from knowledge base")
        self.documents = documents
        return documents
    
    def _load_single_document(self, file_path: str) -> Optional[Dict[str, Any]]:
        """Load a single document file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Create document metadata
            file_name = os.path.basename(file_path)
            file_hash = hashlib.md5(content.encode()).hexdigest()
            
            return {
                "id": file_hash,
                "filename": file_name,
                "filepath": file_path,
                "content": content,
                "source": "knowledge_base",
                "type": self._infer_document_type(file_name),
                "size": len(content)
            }
            
        except Exception as e:
            logger.error(f"Error loading document {file_path}: {e}")
            return None
    
    def _infer_document_type(self, filename: str) -> str:
        """Infer document type from filename"""
        filename_lower = filename.lower()
        
        if "threat" in filename_lower or "intel" in filename_lower:
            return "threat_intelligence"
        elif "mitre" in filename_lower or "att&ck" in filename_lower:
            return "attack_technique"
        elif "playbook" in filename_lower or "response" in filename_lower:
            return "incident_response"
        elif "ip" in filename_lower or "ioc" in filename_lower:
            return "indicators"
        else:
            return "general"
    
    def create_chunks(self, documents: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        """Create text chunks from documents for vector indexing"""
        if documents is None:
            documents = self.documents
            
        chunks = []
        
        for doc in documents:
            content = doc["content"]
            doc_chunks = self._chunk_text(content, RAGConfig.MAX_CHUNK_SIZE, RAGConfig.CHUNK_OVERLAP)
            
            for i, chunk_text in enumerate(doc_chunks):
                chunk_id = f"{doc['id']}_chunk_{i}"
                chunks.append({
                    "id": chunk_id,
                    "text": chunk_text,
                    "source": doc["filename"],
                    "doc_type": doc["type"],
                    "chunk_index": i,
                    "metadata": {
                        "filename": doc["filename"],
                        "doc_type": doc["type"],
                        "source": doc["source"]
                    }
                })
        
        logger.info(f"Created {len(chunks)} chunks from {len(documents)} documents")
        self.chunks = chunks
        return chunks
    
    def _chunk_text(self, text: str, max_size: int, overlap: int) -> List[str]:
        """Split text into overlapping chunks"""
        words = text.split()
        chunks = []
        
        if len(words) <= max_size:
            return [text]
        
        start = 0
        while start < len(words):
            end = min(start + max_size, len(words))
            chunk = " ".join(words[start:end])
            chunks.append(chunk)
            
            if end >= len(words):
                break
                
            start = end - overlap
        
        return chunks
    
    def get_document_by_type(self, doc_type: str) -> List[Dict[str, Any]]:
        """Get documents by type"""
        return [doc for doc in self.documents if doc.get("type") == doc_type]
    
    def search_documents(self, query: str) -> List[Dict[str, Any]]:
        """Simple text search in documents"""
        query_lower = query.lower()
        matching_docs = []
        
        for doc in self.documents:
            if query_lower in doc["content"].lower():
                matching_docs.append(doc)
        
        return matching_docs

# Initialize knowledge base content
def initialize_knowledge_base(kb_path: str):
    """Initialize knowledge base with default cybersecurity content"""
    
    # Threat Intelligence
    threat_intel_content = """# Threat Intelligence Database

## Tor Exit Nodes
- **Risk Level**: CRITICAL
- **Description**: Tor exit nodes are frequently used in credential stuffing attacks and account takeovers
- **Indicators**: IP addresses starting with 185.220.*, 31.13.*, 103.251.*
- **Mitigation**: Block suspicious IPs, enforce MFA, reset passwords for affected accounts
- **Context**: 87% of login attempts from Tor nodes outside business hours result from compromised accounts

## Suspicious Geolocation Patterns
- **High-Risk Countries**: Russia, China, North Korea, Iran
- **Attack Patterns**: Late-night login attempts, first-time country access
- **Mitigation**: Geographic blocking, step-up authentication, user verification

## DDoS Attack Signatures
- **Pattern**: Traffic spike >50x baseline within 5-minute window
- **Sources**: Distributed botnet IPs, amplification attacks
- **Mitigation**: Rate limiting, geo-blocking, upstream filtering
"""

    # MITRE ATT&CK Techniques
    mitre_content = """# MITRE ATT&CK Cybersecurity Framework

## T1078 - Valid Accounts
- **Technique**: Adversaries obtain and abuse credentials of existing accounts
- **Sub-techniques**: Default accounts, domain accounts, local accounts
- **Detection**: Unusual login times, geographic anomalies, privilege escalation
- **Mitigation**: MFA, account monitoring, privilege management

## T1190 - Exploit Public-Facing Application
- **Technique**: Adversaries exploit vulnerabilities in public-facing applications
- **Detection**: Unusual traffic patterns, failed authentication spikes
- **Mitigation**: Regular patching, WAF deployment, input validation

## T1041 - Exfiltration Over C2 Channel
- **Technique**: Data theft over command and control channels
- **Detection**: Large file transfers, unusual network patterns
- **Mitigation**: Data loss prevention, network monitoring, encryption
"""

    # Incident Response Playbooks
    playbook_content = """# Cybersecurity Incident Response Playbooks

## Suspicious Login Response
1. **Immediate Actions**:
   - Block suspicious IP address
   - Force password reset for affected account
   - Enable MFA if not already active
   - Revoke existing sessions

2. **Investigation Steps**:
   - Check for other accounts from same IP
   - Review user's recent activities
   - Verify user identity through secondary channel
   - Check for privilege escalation attempts

3. **Escalation Triggers**:
   - Multiple failed login attempts
   - High-privilege account involved
   - Evidence of data access

## Network Anomaly Response
1. **Immediate Actions**:
   - Enable rate limiting
   - Activate WAF challenge mode
   - Monitor top traffic sources

2. **Analysis**:
   - Identify attack pattern (DDoS, scraping, etc.)
   - Assess service impact
   - Check for vulnerability exploitation

3. **Mitigation**:
   - Implement geo-blocking if needed
   - Contact upstream providers
   - Deploy additional filtering rules

## Data Exfiltration Response
1. **Immediate Actions**:
   - Quarantine affected endpoint
   - Revoke user tokens and sessions
   - Preserve logs and evidence

2. **Investigation**:
   - Identify data accessed
   - Trace exfiltration path
   - Assess business impact

3. **Recovery**:
   - Implement additional monitoring
   - Review access controls
   - Update security policies
"""

    # File operations
    files_to_create = [
        ("threat_intelligence.md", threat_intel_content),
        ("mitre_attack_techniques.md", mitre_content),
        ("incident_response_playbooks.md", playbook_content)
    ]
    
    for filename, content in files_to_create:
        filepath = os.path.join(kb_path, filename)
        if not os.path.exists(filepath):
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
    
    logger.info(f"Initialized knowledge base at {kb_path}")
