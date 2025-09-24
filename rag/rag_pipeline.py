"""
Main RAG Pipeline Integration with Pathway
Orchestrates knowledge base, vector store, and LLM services for real-time anomaly enrichment
"""

import os
import json
import logging
from typing import Dict, Any, List, Optional
import pathway as pw

from .config import RAGConfig
from .knowledge_base import KnowledgeBase, initialize_knowledge_base
from .vector_store import VectorStore
from .llm_service import LLMService

logger = logging.getLogger(__name__)

class RAGPipeline:
    """Main RAG pipeline for cybersecurity anomaly detection"""
    
    def __init__(self):
        # Validate configuration
        RAGConfig.validate_config()
        
        # Initialize components
        self.knowledge_base = None
        self.vector_store = None
        self.llm_service = None
        self.is_initialized = False
        
        # Initialize if RAG is enabled
        if RAGConfig.ENABLE_RAG:
            self.initialize()
    
    def initialize(self) -> bool:
        """Initialize all RAG components"""
        try:
            logger.info("Initializing RAG pipeline...")
            
            # Initialize knowledge base
            self.knowledge_base = KnowledgeBase()
            
            # Initialize vector store
            self.vector_store = VectorStore()
            
            # Initialize LLM service
            self.llm_service = LLMService()
            
            # Load and index knowledge base if empty
            if not self.vector_store.health_check():
                self._index_knowledge_base()
            
            self.is_initialized = True
            logger.info("RAG pipeline initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize RAG pipeline: {e}")
            self.is_initialized = False
            return False
    
    def _index_knowledge_base(self):
        """Load and index knowledge base documents"""
        try:
            # Initialize knowledge base content if needed
            if not os.listdir(RAGConfig.KNOWLEDGE_BASE_PATH):
                initialize_knowledge_base(RAGConfig.KNOWLEDGE_BASE_PATH)
            
            # Load documents
            documents = self.knowledge_base.load_documents()
            if not documents:
                logger.warning("No documents found in knowledge base")
                return
            
            # Create chunks
            chunks = self.knowledge_base.create_chunks(documents)
            if not chunks:
                logger.warning("No chunks created from documents")
                return
            
            # Index in vector store
            success = self.vector_store.add_documents(chunks)
            if success:
                logger.info(f"Successfully indexed {len(chunks)} chunks")
            else:
                logger.error("Failed to index knowledge base")
                
        except Exception as e:
            logger.error(f"Error indexing knowledge base: {e}")
    
    def enrich_anomaly(self, anomaly: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich anomaly with RAG-generated explanation and context"""
        
        # Return original anomaly if RAG is disabled or not initialized
        if not RAGConfig.ENABLE_RAG or not self.is_initialized:
            return anomaly
        
        try:
            # Create search query from anomaly
            query = self._create_search_query(anomaly)
            
            # Retrieve relevant context
            context_documents = self.vector_store.similarity_search(
                query=query,
                top_k=RAGConfig.MAX_CONTEXT_ITEMS
            )
            
            # Generate explanation using LLM
            rag_response = self.llm_service.generate_anomaly_explanation(
                anomaly=anomaly,
                context_documents=context_documents
            )
            
            # Enrich original anomaly with RAG response
            enriched_anomaly = {
                **anomaly,
                **rag_response,
                "rag_enabled": True,
                "rag_query": query
            }
            
            logger.info(f"Successfully enriched {anomaly.get('type', 'unknown')} anomaly")
            return enriched_anomaly
            
        except Exception as e:
            logger.error(f"Error enriching anomaly: {e}")
            # Return original anomaly with error info
            return {
                **anomaly,
                "rag_enabled": False,
                "rag_error": str(e)
            }
    
    def _create_search_query(self, anomaly: Dict[str, Any]) -> str:
        """Create search query from anomaly details"""
        
        anomaly_type = anomaly.get("type", "")
        query_parts = [anomaly_type]
        
        # Add type-specific terms
        if "login" in anomaly_type:
            location = anomaly.get("location", "")
            ip_address = anomaly.get("ip_address", "")
            if location:
                query_parts.append(f"location {location}")
            if ip_address:
                query_parts.append(f"IP {ip_address}")
            query_parts.extend(["credential", "authentication", "access"])
            
        elif "network" in anomaly_type:
            spike_ratio = anomaly.get("spike_ratio", 0)
            if spike_ratio > 50:
                query_parts.extend(["DDoS", "traffic spike", "attack"])
            else:
                query_parts.extend(["network anomaly", "traffic pattern"])
                
        elif "file" in anomaly_type:
            filename = anomaly.get("filename", "")
            file_size = anomaly.get("file_size_mb", 0)
            if filename:
                query_parts.append(f"file {filename}")
            if file_size > 500:
                query_parts.extend(["data exfiltration", "large transfer"])
            query_parts.extend(["file access", "data transfer"])
        
        # Add severity and risk information
        severity = anomaly.get("severity", "")
        if severity:
            query_parts.append(severity.lower())
        
        return " ".join(query_parts)
    
    def get_pipeline_status(self) -> Dict[str, Any]:
        """Get status of RAG pipeline components"""
        return {
            "rag_enabled": RAGConfig.ENABLE_RAG,
            "initialized": self.is_initialized,
            "knowledge_base_documents": len(self.knowledge_base.documents) if self.knowledge_base else 0,
            "vector_store_info": self.vector_store.get_collection_info() if self.vector_store else {},
            "openai_model": RAGConfig.OPENAI_MODEL,
            "embedding_model": RAGConfig.EMBEDDING_MODEL
        }
    
    def reload_knowledge_base(self) -> bool:
        """Reload knowledge base (useful for updating content)"""
        try:
            if not self.is_initialized:
                return False
            
            # Delete existing collection
            self.vector_store.delete_collection()
            
            # Reinitialize vector store
            self.vector_store = VectorStore()
            
            # Reindex knowledge base
            self._index_knowledge_base()
            
            logger.info("Knowledge base reloaded successfully")
            return True
            
        except Exception as e:
            logger.error(f"Error reloading knowledge base: {e}")
            return False

# Global RAG pipeline instance
_rag_pipeline = None

def get_rag_pipeline() -> RAGPipeline:
    """Get global RAG pipeline instance (singleton pattern)"""
    global _rag_pipeline
    if _rag_pipeline is None:
        _rag_pipeline = RAGPipeline()
    return _rag_pipeline

# Pathway UDF for RAG enrichment
@pw.udf
def enrich_anomaly_with_rag(anomaly_data: str) -> str:
    """Pathway UDF to enrich anomaly with RAG"""
    try:
        # Parse anomaly JSON
        anomaly = json.loads(anomaly_data)
        
        # Get RAG pipeline
        rag = get_rag_pipeline()
        
        # Enrich anomaly
        enriched = rag.enrich_anomaly(anomaly)
        
        # Return enriched anomaly as JSON string
        return json.dumps(enriched, default=str)
        
    except Exception as e:
        logger.error(f"Error in RAG UDF: {e}")
        return anomaly_data  # Return original on error
