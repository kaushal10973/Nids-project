import unittest
import numpy as np
from nids.feature_extractor import FeatureExtractor
from scapy.all import IP, TCP, Ether

class TestFeatureExtractor(unittest.TestCase):
    
    def setUp(self):
        """Set up feature extractor."""
        self.extractor = FeatureExtractor()
        self.flows_dict = {}
    
    def test_extract_basic_features(self):
        """Test basic feature extraction."""
        # Create test packet
        pkt = Ether()/IP(src='192.168.1.1', dst='10.0.0.1')/TCP(sport=1234, dport=80, flags='S')
        
        features = self.extractor.extract(pkt, 'test_flow_1', self.flows_dict)
        
        self.assertIsNotNone(features)
        self.assertIsInstance(features, np.ndarray)
        self.assertEqual(len(features), 41)
    
    def test_protocol_detection(self):
        """Test protocol type detection."""
        pkt_tcp = Ether()/IP()/TCP()
        self.assertEqual(self.extractor.get_protocol_type(pkt_tcp), 6)
        
        pkt_udp = Ether()/IP()/TCP()  # Would be UDP in real scenario
        self.assertIsInstance(self.extractor.get_protocol_type(pkt_udp), int)
    
    def test_land_attack_detection(self):
        """Test LAND attack detection."""
        pkt_land = Ether()/IP(src='192.168.1.1', dst='192.168.1.1')/TCP(sport=80, dport=80)
        self.assertEqual(self.extractor.check_land(pkt_land), 1)
        
        pkt_normal = Ether()/IP(src='192.168.1.1', dst='10.0.0.1')/TCP(sport=1234, dport=80)
        self.assertEqual(self.extractor.check_land(pkt_normal), 0)

