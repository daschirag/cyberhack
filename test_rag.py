import os
from dotenv import load_dotenv
load_dotenv()

from rag.rag_pipeline import get_rag_pipeline

try:
    rag = get_rag_pipeline()
    status = rag.get_pipeline_status()
    print("RAG Status:", status)
    
    # Test enrichment
    test_anomaly = {
        'type': 'login_anomaly', 
        'username': 'test_user',
        'location': 'Moscow',
        'severity': 'HIGH',
        'risk_score': 85
    }
    
    result = rag.enrich_anomaly(test_anomaly)
    print("Context sources:", result.get('context_sources', []))
    print("AI explanation:", result.get('ai_explanation', 'None')[:100] + "...")
    
except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()
