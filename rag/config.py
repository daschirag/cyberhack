"""
RAG Configuration Management
Centralizes all RAG-related settings and environment variables
"""

import os
from typing import List, Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class RAGConfig:
    """Configuration class for RAG system"""
    
    # OpenAI Configuration
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY", "")
    OPENAI_MODEL: str = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
    EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "text-embedding-3-large")
    EMBEDDING_DIMENSIONS: int = 3072  # text-embedding-3-large dimensions
    
    # RAG Features
    ENABLE_RAG: bool = os.getenv("KB_ENABLE_RAG", "true").lower() == "true"
    MAX_CONTEXT_ITEMS: int = int(os.getenv("KB_CONTEXT_MAX_ITEMS", "5"))
    
    # Vector Database
    VECTOR_DB_BACKEND: str = os.getenv("VECTOR_DB_BACKEND", "chroma")
    VECTOR_COLLECTION: str = os.getenv("VECTOR_COLLECTION", "cybersecurity_kb")
    VECTOR_DB_PATH: str = os.getenv("VECTOR_DB_URL", "./chroma_db")
    
    # Knowledge Base
    KNOWLEDGE_BASE_PATH: str = os.path.join(os.path.dirname(__file__), "knowledge_base")
    
    # RAG Parameters
    SIMILARITY_THRESHOLD: float = 0.2
    MAX_CHUNK_SIZE: int = 1000
    CHUNK_OVERLAP: int = 200
    
    # LLM Generation
    LLM_TEMPERATURE: float = 0.2
    MAX_TOKENS: int = 500
    
    @classmethod
    def validate_config(cls) -> bool:
        """Validate RAG configuration"""
        if not cls.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is required for RAG functionality")
        
        if not os.path.exists(cls.KNOWLEDGE_BASE_PATH):
            os.makedirs(cls.KNOWLEDGE_BASE_PATH, exist_ok=True)
            
        if not os.path.exists(cls.VECTOR_DB_PATH):
            os.makedirs(cls.VECTOR_DB_PATH, exist_ok=True)
            
        return True
