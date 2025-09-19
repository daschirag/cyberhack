"""
Tests for Pathway Knowledge Base module
"""

import unittest
from unittest.mock import Mock, patch, MagicMock
import json
from datetime import datetime, timedelta

# Mock the imports to avoid dependency issues
import sys
sys.modules['anomaly_detection'] = Mock()

from pathway_kb import PathwayKB, KB_INSTANCE

class TestPathwayKB(unittest.TestCase):
    
    def setUp(self):
        """Set up test fixtures"""
        self.kb = PathwayKB()
        # Mock the state manager
        self.kb.state_manager = Mock()
        self.kb.state_manager.get_user_profile.return_value = {
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
        self.kb.state_manager.update_user_profile.return_value = True
        self.kb.state_manager.get.return_value = []
        self.kb.state_manager.set.return_value = True
    
    def test_upsert_user_event_login(self):
        """Test upserting login events with bounded history"""
        username = "testuser"
        
        # Upsert 25 login events
        for i in range(25):
            event = {
                'location': f'Location{i}',
                'timestamp': (datetime.now() - timedelta(hours=i)).isoformat(),
                'ip_address': f'192.168.1.{i}'
            }
            profile = self.kb.upsert_user_event(username, event)
        
        # Verify the profile was updated
        self.kb.state_manager.update_user_profile.assert_called()
        
        # Check that recent_logins is bounded to 20
        call_args = self.kb.state_manager.update_user_profile.call_args[0]
        updated_profile = call_args[1]
        self.assertLessEqual(len(updated_profile['recent_logins']), 20)
    
    def test_upsert_user_event_file_transfer(self):
        """Test upserting file transfer events"""
        username = "testuser"
        event = {
            'file_size_mb': 150.5,
            'filename': 'sensitive_data.zip',
            'operation': 'download',
            'timestamp': datetime.now().isoformat()
        }
        
        profile = self.kb.upsert_user_event(username, event)
        
        # Verify file stats were updated
        self.kb.state_manager.update_user_profile.assert_called()
        call_args = self.kb.state_manager.update_user_profile.call_args[0]
        updated_profile = call_args[1]
        
        file_stats = updated_profile['file_stats']
        self.assertEqual(file_stats['total_transfers'], 1)
        self.assertEqual(file_stats['total_size_mb'], 150.5)
        self.assertEqual(file_stats['avg_size_mb'], 150.5)
        self.assertEqual(file_stats['max_size_mb'], 150.5)
    
    def test_upsert_anomaly(self):
        """Test storing anomaly in knowledge base"""
        anomaly = {
            'type': 'login',
            'timestamp': datetime.now().isoformat(),
            'username': 'testuser',
            'severity': 'HIGH',
            'location': 'SuspiciousCountry',
            'risk_score': 0.85
        }
        
        anomaly_id = self.kb.upsert_anomaly(anomaly)
        
        # Verify anomaly was stored
        self.kb.state_manager.set.assert_called()
        self.assertIsNotNone(anomaly_id)
        self.assertNotEqual(anomaly_id, "unknown")
    
    def test_get_context_for_anomaly_masked_username(self):
        """Test that context returns masked username"""
        # Mock user profile with data
        mock_profile = {
            'recent_logins': [
                {'location': 'USA', 'timestamp': '2024-01-15T10:00:00', 'ip_address': '192.168.1.100'},
                {'location': 'Canada', 'timestamp': '2024-01-14T15:30:00', 'ip_address': '192.168.1.101'}
            ],
            'normal_hours': list(range(7, 22)),
            'file_stats': {
                'total_transfers': 5,
                'avg_size_mb': 25.5,
                'max_size_mb': 100.0
            }
        }
        
        self.kb.state_manager.get_user_profile.return_value = mock_profile
        
        anomaly = {
            'username': 'john.doe',
            'type': 'login',
            'timestamp': datetime.now().isoformat()
        }
        
        context = self.kb.get_context_for_anomaly(anomaly)
        
        # Verify username is masked
        self.assertEqual(context['masked_username'], 'j***')
        
        # Verify expected keys are present
        expected_keys = ['masked_username', 'last_logins', 'normal_hours', 'file_summary', 'recent_related_anomalies', 'similar_anomalies']
        for key in expected_keys:
            self.assertIn(key, context)
    
    def test_mask_username(self):
        """Test username masking functionality"""
        self.assertEqual(self.kb._mask_username('john.doe'), 'j***')
        self.assertEqual(self.kb._mask_username('a'), 'a***')
        self.assertEqual(self.kb._mask_username(''), 'unknown')
        self.assertEqual(self.kb._mask_username('unknown'), 'unknown')
    
    def test_mask_ip(self):
        """Test IP address masking functionality"""
        self.assertEqual(self.kb._mask_ip('192.168.1.100'), '192.168.xxx.xxx')
        self.assertEqual(self.kb._mask_ip('10.0.0.1'), '10.0.xxx.xxx')
        self.assertEqual(self.kb._mask_ip(''), 'unknown')
        self.assertEqual(self.kb._mask_ip('unknown'), 'unknown')
    
    def test_create_anomaly_summary(self):
        """Test anomaly summary creation"""
        # Test login anomaly
        login_anomaly = {
            'type': 'login',
            'location': 'SuspiciousCountry',
            'anomalies': [
                {'details': 'Login from new location'},
                {'details': 'Unusual time'}
            ]
        }
        summary = self.kb._create_anomaly_summary(login_anomaly)
        self.assertIn('Login from SuspiciousCountry', summary)
        self.assertIn('Login from new location', summary)
        
        # Test network anomaly
        network_anomaly = {
            'type': 'network',
            'requests_per_minute': 50000,
            'spike_ratio': 25.5
        }
        summary = self.kb._create_anomaly_summary(network_anomaly)
        self.assertIn('Network traffic spike', summary)
        self.assertIn('50000 req/min', summary)
        
        # Test file transfer anomaly
        file_anomaly = {
            'type': 'file_transfer',
            'operation': 'download',
            'file_size_mb': 250.0,
            'filename': 'sensitive_data.zip'
        }
        summary = self.kb._create_anomaly_summary(file_anomaly)
        self.assertIn('File transfer', summary)
        self.assertIn('download 250.0MB', summary)
    
    def test_metrics_tracking(self):
        """Test that metrics are properly tracked"""
        initial_metrics = self.kb.get_metrics()
        
        # Perform some operations
        self.kb.upsert_user_event('testuser', {'location': 'USA', 'timestamp': datetime.now().isoformat()})
        self.kb.upsert_anomaly({'type': 'login', 'timestamp': datetime.now().isoformat()})
        
        updated_metrics = self.kb.get_metrics()
        
        # Verify metrics increased
        self.assertGreater(updated_metrics['kb_upserts'], initial_metrics['kb_upserts'])
    
    def test_error_handling(self):
        """Test error handling in KB operations"""
        # Test with invalid data
        result = self.kb.upsert_user_event('', {})
        self.assertEqual(result, {})
        
        result = self.kb.upsert_anomaly({})
        self.assertEqual(result, "unknown")
        
        result = self.kb.get_context_for_anomaly({})
        self.assertIn('error', result)

if __name__ == '__main__':
    unittest.main()
