import os
import sys
from dotenv import load_dotenv
load_dotenv()
os.environ["KB_ENABLE_RAG"] = "true"

try:
    # Test OpenAI client first
    from openai import OpenAI
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    print("✅ OpenAI client created successfully")
    
    # Test ChromaDB
    import chromadb
    chroma_client = chromadb.PersistentClient(path="./test_chroma")
    print("✅ ChromaDB client created successfully")
    
    # Test RAG pipeline
    from rag.rag_pipeline import get_rag_pipeline
    print("🧪 Testing RAG pipeline...")
    
    rag = get_rag_pipeline()
    print("✅ RAG pipeline created")
    
    status = rag.get_pipeline_status()
    print(f"RAG Status: {status}")
    
    # Test enrichment
    test_anomaly = {
        'type': 'login_anomaly',
        'username': 'test_user',
        'location': 'Moscow',
        'severity': 'HIGH',
        'risk_score': 85
    }
    
    print("🧪 Testing anomaly enrichment...")
    result = rag.enrich_anomaly(test_anomaly)
    
    print(f"✅ Enrichment result:")
    print(f"   Context sources: {len(result.get('context_sources', []))}")
    print(f"   Has AI explanation: {bool(result.get('ai_explanation'))}")
    print(f"   RAG enabled: {result.get('rag_enabled', False)}")
    
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()
