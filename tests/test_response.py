import unittest
from unittest.mock import Mock, patch
from nids.response import ResponseEngine

class TestResponseEngine(unittest.TestCase):
    
    def setUp(self):
        """Set up response engine."""
        self.config = {
            'response': {
                'auto_block': True,
                'notification_enabled': True,
                'alert_threshold': 0.7,
                'email': 'test@example.com'
            },
            'database': {'path': ':memory:'}
        }
        self.response_engine = ResponseEngine(self.config)
    
    def test_severity_calculation(self):
        """Test severity calculation."""
        severity = self.response_engine.get_severity('DoS', 0.95)
        self.assertEqual(severity, 'critical')
        
        severity = self.response_engine.get_severity('Probe', 0.85)
        self.assertEqual(severity, 'medium')
    
    def test_block_ip(self):
        """Test IP blocking."""
        result = self.response_engine.block_ip('192.168.1.100')
        self.assertTrue(result)
        self.assertIn('192.168.1.100', self.response_engine.blocked_ips)
    
    def test_handle_threat_below_threshold(self):
        """Test threat handling below threshold."""
        action = self.response_engine.handle_threat(
            alert_id=1,
            src_ip='192.168.1.100',
            attack_type='DoS',
            confidence=0.5  # Below threshold
        )
        
        self.assertEqual(action, 'monitored')


# ====================
# Run all tests
# ====================

if __name__ == '__main__':
    unittest.main()