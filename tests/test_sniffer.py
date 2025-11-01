import unittest
from unittest.mock import Mock, patch, MagicMock
from nids.sniffer import PacketSniffer
from scapy.all import IP, TCP, Ether

class TestPacketSniffer(unittest.TestCase):
    
    def setUp(self):
        """Set up test configuration."""
        self.config = {
            'network': {
                'interface': 'eth0',
                'filter': 'tcp',
                'packet_count': 0
            },
            'database': {'path': ':memory:'},
            'ml_models': {
                'random_forest': 'models/model_rf.pkl',
                'ensemble': 'models/model_ensemble.pkl'
            },
            'response': {
                'auto_block': False,
                'notification_enabled': False,
                'alert_threshold': 0.7,
                'email': 'test@example.com'
            }
        }
    
    @patch('nids.sniffer.sniff')
    def test_sniffer_initialization(self, mock_sniff):
        """Test sniffer initializes correctly."""
        sniffer = PacketSniffer(self.config)
        
        self.assertEqual(sniffer.interface, 'eth0')
        self.assertEqual(sniffer.filter, 'tcp')
        self.assertFalse(sniffer.running)
    
    def test_flow_id_creation(self):
        """Test flow ID creation."""
        sniffer = PacketSniffer(self.config)
        
        flow_id = sniffer.create_flow_id('192.168.1.1', '10.0.0.1', 1234, 80, 'TCP')
        self.assertIn('192.168.1.1', flow_id)
        self.assertIn('10.0.0.1', flow_id)
        self.assertIn('TCP', flow_id)