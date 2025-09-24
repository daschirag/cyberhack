"""
Vector Store Management for RAG using ChromaDB
Handles embedding generation, storage, and similarity search
"""

import os
import logging
from typing import List, Dict, Any, Optional, Tuple
import chromadb
from chromadb.config import Settings
import openai
from openai import OpenAI

from .config import RAGConfig

logger = logging.getLogger(__name__)

class VectorStore:
    """ChromaDB-based vector store for cybersecurity knowledge"""
    
    def __init__(self):
        self.client = None
        self.collection = None
        self.openai_client = OpenAI(api_key=RAGConfig.OPENAI_API_KEY)
        self._initialize_store()
    
    def _initialize_store(self):
        """Initialize ChromaDB client and collection"""
        try:
            # Initialize ChromaDB client
            self.client = chromadb.PersistentClient(
                path=RAGConfig.VECTOR_DB_PATH,
                settings=Settings(
                    anonymized_telemetry=False,
                    allow_reset=True
                )
            )
            
            # Get or create collection
            self.collection = self.client.get_or_create_collection(
                name=RAGConfig.VECTOR_COLLECTION,
                metadata={
                    "description": "Cybersecurity knowledge base for anomaly detection",
                    "embedding_model": RAGConfig.EMBEDDING_MODEL
                }
            )
            
            logger.info(f"Vector store initialized with collection: {RAGConfig.VECTOR_COLLECTION}")
            
        except Exception as e:
            logger.error(f"Failed to initialize vector store: {e}")
            raise
    
    def generate_embeddings(self, texts: List[str]) -> List[List[float]]:
        """Generate embeddings using OpenAI API"""
        try:
            response = self.openai_client.embeddings.create(
                model=RAGConfig.EMBEDDING_MODEL,
                input=texts
            )
            
            embeddings = [data.embedding for data in response.data]
            logger.info(f"Generated embeddings for {len(texts)} texts")
            return embeddings
            
        except Exception as e:
            logger.error(f"Failed to generate embeddings: {e}")
            raise
    
    def add_documents(self, documents: List[Dict[str, Any]]) -> bool:
        """Add documents to vector store"""
        try:
            if not documents:
                logger.warning("No documents to add")
                return False
            
            # Prepare data for ChromaDB
            ids = [doc["id"] for doc in documents]
            texts = [doc["text"] for doc in documents]
            metadatas = [doc.get("metadata", {}) for doc in documents]
            
            # Generate embeddings
            embeddings = self.generate_embeddings(texts)
            
            # Add to collection
            self.collection.upsert(
                ids=ids,
                documents=texts,
                metadatas=metadatas,
                embeddings=embeddings
            )
            
            logger.info(f"Added {len(documents)} documents to vector store")
            return True
            
        except Exception as e:
            logger.error(f"Failed to add documents: {e}")
            return False
    
    def similarity_search(self, query: str, top_k: int = None) -> List[Dict[str, Any]]:
        """Perform similarity search for query"""
        if top_k is None:
            top_k = RAGConfig.MAX_CONTEXT_ITEMS
        
        try:
            # Generate query embedding
            query_embedding = self.generate_embeddings([query])[0]
            
            # Search in collection
            results = self.collection.query(
                query_embeddings=[query_embedding],
                n_results=top_k,
                include=["documents", "metadatas", "distances"]
            )
            
            # Format results
            search_results = []
            if results["documents"] and results["documents"][0]:
                for i, (doc, metadata, distance) in enumerate(zip(
                    results["documents"][0],
                    results["metadatas"][0],
                    results["distances"][0]
                )):
                    # Filter by similarity threshold
                    similarity_score = 1 - distance  # Convert distance to similarity
                    if similarity_score >= RAGConfig.SIMILARITY_THRESHOLD:
                        search_results.append({
                            "text": doc,
                            "metadata": metadata,
                            "similarity_score": similarity_score,
                            "rank": i + 1
                        })
            
            logger.info(f"Found {len(search_results)} relevant documents for query")
            return search_results
            
        except Exception as e:
            logger.error(f"Similarity search failed: {e}")
            return []
    
    def get_collection_info(self) -> Dict[str, Any]:
        """Get information about the collection"""
        try:
            count = self.collection.count()
            return {
                "name": RAGConfig.VECTOR_COLLECTION,
                "document_count": count,
                "embedding_model": RAGConfig.EMBEDDING_MODEL,
                "embedding_dimensions": RAGConfig.EMBEDDING_DIMENSIONS
            }
        except Exception as e:
            logger.error(f"Failed to get collection info: {e}")
            return {}
    
    def delete_collection(self):
        """Delete the collection (for testing/reset)"""
        try:
            self.client.delete_collection(RAGConfig.VECTOR_COLLECTION)
            logger.info("Collection deleted successfully")
        except Exception as e:
            logger.error(f"Failed to delete collection: {e}")
    
    def health_check(self) -> bool:
        """Check if vector store is healthy"""
        try:
            info = self.get_collection_info()
            return info.get("document_count", 0) > 0
        except:
            return False
