"""
Integration tests for KB-Alert system
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
from datetime import datetime

# Mock the imports
import sys
sys.modules['anomaly_detection'] = Mock()
sys.modules['pathway_kb'] = Mock()

class TestKBAlertIntegration(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        # Mock the KB instance
        self.mock_kb = Mock()
        self.mock_kb.get_context_for_anomaly.return_value = {
            'masked_username': 'j***',
            'last_logins': [
                {'location': 'USA', 'timestamp': '2024-01-15T10:00:00', 'ip_masked': '192.168.xxx.xxx'},
                {'location': 'Canada', 'timestamp': '2024-01-14T15:30:00', 'ip_masked': '192.168.xxx.xxx'}
            ],
            'normal_hours': [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21],
            'file_summary': {'total_transfers': 5, 'avg_size_mb': 25.5, 'max_size_mb': 100.0},
            'recent_related_anomalies': [
                {'type': 'file_transfer', 'timestamp': '2024-01-18T14:00:00', 'summary': 'Large file transfer'},
                {'type': 'login', 'timestamp': '2024-01-12T22:00:00', 'summary': 'Login from new IP'}
            ],
            'similar_anomalies': [
                {'summary': 'Similar login anomaly from suspicious location'},
                {'summary': 'Previous file transfer of similar size'}
            ]
        }
        
        # Mock the AlertSystem
        self.alert_system = Mock()
        self.alert_system._build_rag_context_string = self._mock_build_rag_context
        self.alert_system._openai_explain = self._mock_openai_explain
        self.alert_system._generate_template_explanation = self._mock_template_explanation
    
    def _mock_build_rag_context(self, context):
        """Mock RAG context building"""
        if not context:
            return ""
        
        parts = []
        if context.get('masked_username'):
            parts.append(f"User {context['masked_username']}")
        
        if context.get('last_logins'):
            login_parts = []
            for login in context['last_logins'][:2]:
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
        
        if context.get('recent_related_anomalies'):
            related_parts = []
            for anomaly in context['recent_related_anomalies'][:2]:
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
        
        if context.get('similar_anomalies'):
            similar_parts = []
            for similar in context['similar_anomalies'][:2]:
                summary = similar.get('summary', '')
                if summary:
                    if len(summary) > 30:
                        summary = summary[:27] + "..."
                    similar_parts.append(summary)
            
            if similar_parts:
                parts.append(f"Similar: {', '.join(similar_parts)}")
        
        if parts:
            context_str = "CONTEXT (redacted): " + "; ".join(parts)
            if len(context_str) > 200:
                context_str = context_str[:197] + "..."
            return context_str
        
        return ""
    
    def _mock_openai_explain(self, anomaly, rag_context=""):
        """Mock OpenAI explanation with RAG context"""
        if rag_context:
            return f"🚨 SECURITY ALERT: {rag_context} - Suspicious activity detected requiring immediate investigation."
        else:
            return "🚨 SECURITY ALERT: Suspicious activity detected."
    
    def _mock_template_explanation(self, anomaly):
        """Mock template explanation"""
        return "⚠️ Security anomaly detected"
    
    @patch('pathway_kb.KB_INSTANCE')
    def test_generate_llm_explanation_with_rag_context(self, mock_kb_instance):
        """Test that LLM explanation includes RAG context when KB is enabled"""
        # Setup mocks
        mock_kb_instance.get_context_for_anomaly.return_value = {
            'masked_username': 'j***',
            'last_logins': [
                {'location': 'USA', 'timestamp': '2024-01-15T10:00:00', 'ip_masked': '192.168.xxx.xxx'}
            ],
            'normal_hours': [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21],
            'recent_related_anomalies': [
                {'type': 'file_transfer', 'timestamp': '2024-01-18T14:00:00', 'summary': 'Large file transfer'}
            ]
        }
        
        # Mock Config
        with patch('anomaly_detection.Config') as mock_config:
            mock_config.KB_ENABLE_RAG = True
            mock_config.KB_CONTEXT_MAX_ITEMS = 5
            mock_config.USE_LLM = True
            mock_config.OPENAI_API_KEY = "test-key"
            mock_config.OPENAI_MODEL = "gpt-3.5-turbo"
            
            # Mock OpenAI
            with patch('anomaly_detection.openai') as mock_openai:
                mock_openai.ChatCompletion.create.return_value = Mock(
                    choices=[Mock(message=Mock(content="🚨 SECURITY ALERT: CONTEXT (redacted): User j***; last_logins: [USA@01-15 10:00]; normal_hours: 07-21; recent_related: [Large file 01-18] - Suspicious login from new location detected."))]
                )
                
                # Create AlertSystem instance
                from anomaly_detection import AlertSystem
                alert_system = AlertSystem()
                
                # Test anomaly
                anomaly = {
                    'type': 'login',
                    'username': 'john.doe',
                    'location': 'SuspiciousCountry',
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'HIGH',
                    'risk_score': 0.85
                }
                
                # Generate explanation
                explanation = alert_system.generate_llm_explanation(anomaly)
                
                # Verify KB was called
                mock_kb_instance.get_context_for_anomaly.assert_called_once_with(anomaly, max_items=5)
                
                # Verify explanation contains RAG context
                self.assertIn("CONTEXT (redacted):", explanation)
                self.assertIn("User j***", explanation)
                self.assertIn("last_logins:", explanation)
                self.assertIn("normal_hours:", explanation)
    
    @patch('pathway_kb.KB_INSTANCE')
    def test_generate_llm_explanation_without_rag_context(self, mock_kb_instance):
        """Test that LLM explanation works without RAG context when KB is disabled"""
        # Mock Config
        with patch('anomaly_detection.Config') as mock_config:
            mock_config.KB_ENABLE_RAG = False
            mock_config.USE_LLM = True
            mock_config.OPENAI_API_KEY = "test-key"
            mock_config.OPENAI_MODEL = "gpt-3.5-turbo"
            
            # Mock OpenAI
            with patch('anomaly_detection.openai') as mock_openai:
                mock_openai.ChatCompletion.create.return_value = Mock(
                    choices=[Mock(message=Mock(content="🚨 SECURITY ALERT: Suspicious login from new location detected."))]
                )
                
                # Create AlertSystem instance
                from anomaly_detection import AlertSystem
                alert_system = AlertSystem()
                
                # Test anomaly
                anomaly = {
                    'type': 'login',
                    'username': 'john.doe',
                    'location': 'SuspiciousCountry',
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'HIGH',
                    'risk_score': 0.85
                }
                
                # Generate explanation
                explanation = alert_system.generate_llm_explanation(anomaly)
                
                # Verify KB was not called
                mock_kb_instance.get_context_for_anomaly.assert_not_called()
                
                # Verify explanation does not contain RAG context
                self.assertNotIn("CONTEXT (redacted):", explanation)
    
    @patch('pathway_kb.KB_INSTANCE')
    def test_rag_context_fallback_on_error(self, mock_kb_instance):
        """Test that system falls back gracefully when RAG context retrieval fails"""
        # Setup KB to raise an exception
        mock_kb_instance.get_context_for_anomaly.side_effect = Exception("KB error")
        
        # Mock Config
        with patch('anomaly_detection.Config') as mock_config:
            mock_config.KB_ENABLE_RAG = True
            mock_config.USE_LLM = True
            mock_config.OPENAI_API_KEY = "test-key"
            mock_config.OPENAI_MODEL = "gpt-3.5-turbo"
            
            # Mock OpenAI
            with patch('anomaly_detection.openai') as mock_openai:
                mock_openai.ChatCompletion.create.return_value = Mock(
                    choices=[Mock(message=Mock(content="🚨 SECURITY ALERT: Suspicious activity detected."))]
                )
                
                # Create AlertSystem instance
                from anomaly_detection import AlertSystem
                alert_system = AlertSystem()
                
                # Test anomaly
                anomaly = {
                    'type': 'login',
                    'username': 'john.doe',
                    'location': 'SuspiciousCountry',
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'HIGH',
                    'risk_score': 0.85
                }
                
                # Generate explanation (should not raise exception)
                explanation = alert_system.generate_llm_explanation(anomaly)
                
                # Verify explanation was generated despite KB error
                self.assertIsNotNone(explanation)
                self.assertIn("SECURITY ALERT", explanation)
    
    def test_build_rag_context_string_format(self):
        """Test that RAG context string is properly formatted"""
        context = {
            'masked_username': 'j***',
            'last_logins': [
                {'location': 'USA', 'timestamp': '2024-01-15T10:00:00', 'ip_masked': '192.168.xxx.xxx'},
                {'location': 'Canada', 'timestamp': '2024-01-14T15:30:00', 'ip_masked': '192.168.xxx.xxx'}
            ],
            'normal_hours': [7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21],
            'file_summary': {'total_transfers': 5, 'avg_size_mb': 25.5, 'max_size_mb': 100.0},
            'recent_related_anomalies': [
                {'type': 'file_transfer', 'timestamp': '2024-01-18T14:00:00', 'summary': 'Large file transfer'}
            ]
        }
        
        # Create AlertSystem instance
        from anomaly_detection import AlertSystem
        alert_system = AlertSystem()
        
        # Build RAG context string
        rag_context = alert_system._build_rag_context_string(context)
        
        # Verify format
        self.assertIn("CONTEXT (redacted):", rag_context)
        self.assertIn("User j***", rag_context)
        self.assertIn("last_logins:", rag_context)
        self.assertIn("normal_hours: 07-21", rag_context)
        self.assertIn("file_summary:", rag_context)
        self.assertIn("recent_related:", rag_context)
        
        # Verify length constraint
        self.assertLessEqual(len(rag_context), 200)

if __name__ == '__main__':
    unittest.main()
