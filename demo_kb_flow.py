#!/usr/bin/env python3
"""
Demo script showcasing the Pathway Knowledge Base flow
Simulates anomalies, shows KB upserts, context retrieval, and mocked LLM responses
"""

import json
import time
from datetime import datetime, timedelta
from unittest.mock import Mock, patch

# Mock the imports to avoid dependency issues
import sys
sys.modules['anomaly_detection'] = Mock()

# Import our KB module
from pathway_kb import PathwayKB, KB_INSTANCE

def simulate_anomaly_detection_flow():
    """Simulate the complete anomaly detection flow with KB integration"""
    
    print("🛡️ CyberShield Knowledge Base Demo")
    print("=" * 60)
    
    # Initialize KB
    kb = PathwayKB()
    
    # Mock the state manager for demo
    kb.state_manager = Mock()
    kb.state_manager.get_user_profile.return_value = {
        'recent_logins': [],
        'normal_hours': list(range(7, 22)),
        'file_stats': {
            'total_transfers': 0,
            'total_size_mb': 0.0,
            'avg_size_mb': 0.0,
            'max_size_mb': 0.0,
            'recent_files': []
        }
    }
    kb.state_manager.update_user_profile.return_value = True
    kb.state_manager.get.return_value = []
    kb.state_manager.set.return_value = True
    
    print("✅ Knowledge Base initialized")
    print()
    
    # Simulate user activity over time
    username = "john.doe"
    print(f"👤 Simulating user activity for: {username}")
    print()
    
    # 1. Normal login events (build user profile)
    print("📝 Step 1: Building user profile with normal activity...")
    normal_locations = ["New York", "San Francisco", "Seattle"]
    normal_ips = ["192.168.1.100", "192.168.1.101", "192.168.1.102"]
    
    for i in range(15):
        event = {
            'location': normal_locations[i % len(normal_locations)],
            'timestamp': (datetime.now() - timedelta(hours=i*2)).isoformat(),
            'ip_address': normal_ips[i % len(normal_ips)]
        }
        
        profile = kb.upsert_user_event(username, event)
        print(f"  ✓ Login {i+1}: {event['location']} at {event['timestamp'][:19]}")
    
    print(f"  📊 User profile built with {len(profile.get('recent_logins', []))} recent logins")
    print()
    
    # 2. File transfer activity
    print("📁 Step 2: Recording file transfer activity...")
    file_events = [
        {'file_size_mb': 2.5, 'filename': 'report.pdf', 'operation': 'upload'},
        {'file_size_mb': 8.3, 'filename': 'presentation.pptx', 'operation': 'download'},
        {'file_size_mb': 1.2, 'filename': 'data.xlsx', 'operation': 'upload'},
        {'file_size_mb': 15.7, 'filename': 'document.docx', 'operation': 'download'},
        {'file_size_mb': 3.4, 'filename': 'image.png', 'operation': 'upload'}
    ]
    
    for i, file_event in enumerate(file_events):
        file_event['timestamp'] = (datetime.now() - timedelta(hours=i*3)).isoformat()
        profile = kb.upsert_user_event(username, file_event)
        print(f"  ✓ File {i+1}: {file_event['operation']} {file_event['filename']} ({file_event['file_size_mb']}MB)")
    
    print(f"  📊 File stats: {profile.get('file_stats', {}).get('total_transfers', 0)} transfers, avg {profile.get('file_stats', {}).get('avg_size_mb', 0):.1f}MB")
    print()
    
    # 3. Simulate suspicious login anomaly
    print("🚨 Step 3: Detecting suspicious login anomaly...")
    suspicious_login = {
        'type': 'login',
        'username': username,
        'location': 'Moscow',
        'timestamp': datetime.now().isoformat(),
        'ip_address': '185.220.101.45',
        'severity': 'HIGH',
        'risk_score': 0.85,
        'anomalies': [
            {'type': 'unusual_location', 'severity': 'HIGH', 'details': 'Login from new location: Moscow'},
            {'type': 'unusual_time', 'severity': 'MEDIUM', 'details': 'Login at unusual hour: 23:00'}
        ]
    }
    
    # Upsert anomaly to KB
    anomaly_id = kb.upsert_anomaly(suspicious_login)
    print(f"  ✓ Anomaly stored with ID: {anomaly_id}")
    print(f"  📍 Location: {suspicious_login['location']} (suspicious)")
    print(f"  🕐 Time: {suspicious_login['timestamp'][:19]} (unusual hour)")
    print(f"  ⚠️ Risk Score: {suspicious_login['risk_score']*100:.0f}%")
    print()
    
    # 4. Get RAG context for LLM
    print("🧠 Step 4: Retrieving RAG context for LLM explanation...")
    context = kb.get_context_for_anomaly(suspicious_login, max_items=5)
    
    print("  📋 Context retrieved:")
    print(f"    • Masked Username: {context.get('masked_username', 'unknown')}")
    print(f"    • Recent Logins: {len(context.get('last_logins', []))} entries")
    print(f"    • Normal Hours: {context.get('normal_hours', [])[:3]}... (7 AM - 9 PM)")
    print(f"    • File Summary: {context.get('file_summary', {})}")
    print(f"    • Related Anomalies: {len(context.get('recent_related_anomalies', []))} found")
    print()
    
    # 5. Build RAG context string
    print("🔗 Step 5: Building RAG context string for LLM...")
    
    # Mock the AlertSystem method
    def build_rag_context_string(context):
        if not context:
            return ""
        
        parts = []
        
        if context.get('masked_username'):
            parts.append(f"User {context['masked_username']}")
        
        if context.get('last_logins'):
            login_parts = []
            for login in context['last_logins'][:3]:
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
        
        if context.get('normal_hours'):
            hours = context['normal_hours']
            if hours:
                start_hour = min(hours)
                end_hour = max(hours)
                parts.append(f"normal_hours: {start_hour:02d}-{end_hour:02d}")
        
        if context.get('file_summary') and context['file_summary'].get('total_transfers', 0) > 0:
            fs = context['file_summary']
            parts.append(f"file_summary: {fs['total_transfers']} transfers, avg {fs['avg_size_mb']:.1f}MB")
        
        if parts:
            context_str = "CONTEXT (redacted): " + "; ".join(parts)
            if len(context_str) > 200:
                context_str = context_str[:197] + "..."
            return context_str
        
        return ""
    
    rag_context = build_rag_context_string(context)
    print(f"  📝 RAG Context String:")
    print(f"    {rag_context}")
    print()
    
    # 6. Simulate LLM explanation with RAG context
    print("🤖 Step 6: Generating LLM explanation with RAG context...")
    
    def mock_llm_explanation(anomaly, rag_context):
        """Mock LLM explanation that incorporates RAG context"""
        base_explanation = f"🚨 LOGIN ALERT: User {anomaly['username'][0]}*** from {anomaly['location']} at {anomaly['timestamp'][:19]}. Risk: {anomaly['risk_score']*100:.0f}%"
        
        if rag_context:
            return f"{base_explanation}\n\n{rag_context}\n\nAnalysis: This login is suspicious because it's from a new location (Moscow) outside the user's normal pattern. The user typically logs in from US locations during business hours (7 AM - 9 PM). This represents a significant deviation from established behavior patterns."
        else:
            return base_explanation
    
    llm_explanation = mock_llm_explanation(suspicious_login, rag_context)
    print("  🎯 LLM Explanation:")
    print(f"    {llm_explanation}")
    print()
    
    # 7. Show KB metrics
    print("📊 Step 7: Knowledge Base Metrics...")
    metrics = kb.get_metrics()
    print(f"  • KB Upserts: {metrics['kb_upserts']}")
    print(f"  • KB Queries: {metrics['kb_queries']}")
    print(f"  • Vector Exports: {metrics['vector_exports']}")
    print(f"  • Vector Queries: {metrics['vector_queries']}")
    print()
    
    # 8. Simulate another anomaly to show context evolution
    print("🔄 Step 8: Simulating follow-up anomaly to show context evolution...")
    
    # Add the suspicious login to user profile
    kb.upsert_user_event(username, {
        'location': suspicious_login['location'],
        'timestamp': suspicious_login['timestamp'],
        'ip_address': suspicious_login['ip_address']
    })
    
    # Simulate a large file transfer anomaly
    file_anomaly = {
        'type': 'file_transfer',
        'username': username,
        'timestamp': (datetime.now() + timedelta(minutes=30)).isoformat(),
        'file_size_mb': 500.0,
        'operation': 'download',
        'filename': 'database_backup.zip',
        'severity': 'CRITICAL',
        'risk_score': 0.95,
        'anomalies': [
            {'type': 'large_transfer', 'severity': 'CRITICAL', 'details': 'Large download: 500.0MB'},
            {'type': 'suspicious_file_type', 'severity': 'HIGH', 'details': 'Suspicious file type: database_backup.zip'}
        ]
    }
    
    # Upsert file anomaly
    file_anomaly_id = kb.upsert_anomaly(file_anomaly)
    print(f"  ✓ File anomaly stored with ID: {file_anomaly_id}")
    
    # Get context for file anomaly
    file_context = kb.get_context_for_anomaly(file_anomaly, max_items=5)
    file_rag_context = build_rag_context_string(file_context)
    
    print(f"  📋 Context for file anomaly:")
    print(f"    • Recent logins now include: {file_context.get('masked_username', 'unknown')} from Moscow")
    print(f"    • File summary updated: {file_context.get('file_summary', {})}")
    print(f"    • RAG context: {file_rag_context}")
    print()
    
    print("🎉 Demo Complete!")
    print("=" * 60)
    print("Key Benefits Demonstrated:")
    print("✅ User profile building with bounded history")
    print("✅ Anomaly storage and indexing")
    print("✅ RAG context retrieval with privacy protection")
    print("✅ LLM explanation enhancement with historical context")
    print("✅ Context evolution over time")
    print("✅ Privacy-preserving data masking")
    print("✅ Metrics tracking for monitoring")

if __name__ == "__main__":
    simulate_anomaly_detection_flow()
