import unittest
import tempfile
import os
from nids.database import DatabaseManager

class TestDatabaseManager(unittest.TestCase):
    
    def setUp(self):
        """Set up test database."""
        self.temp_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db')
        self.db_path = self.temp_db.name
        self.temp_db.close()
        
        # Initialize database
        from init_db import init_database
        init_database(self.db_path)
        
        self.db = DatabaseManager(self.db_path)
    
    def tearDown(self):
        """Clean up test database."""
        if os.path.exists(self.db_path):
            os.unlink(self.db_path)
    
    def test_store_alert(self):
        """Test storing alert."""
        alert_id = self.db.store_alert(
            src_ip='192.168.1.100',
            dst_ip='10.0.0.1',
            protocol='TCP',
            src_port=1234,
            dst_port=80,
            class_label='DoS',
            attack_type='DoS',
            confidence=0.95
        )
        
        self.assertIsNotNone(alert_id)
        self.assertIsInstance(alert_id, int)
    
    def test_query_logs(self):
        """Test querying logs."""
        # Store test alert
        self.db.store_alert(
            src_ip='192.168.1.100',
            dst_ip='10.0.0.1',
            protocol='TCP',
            src_port=1234,
            dst_port=80,
            class_label='DoS',
            attack_type='DoS',
            confidence=0.95
        )
        
        # Query logs
        logs = self.db.query_logs(limit=10)
        
        self.assertIsInstance(logs, list)
        self.assertGreater(len(logs), 0)
        self.assertEqual(logs[0]['src_ip'], '192.168.1.100')
    
    def test_get_statistics(self):
        """Test getting statistics."""
        # Store test alerts
        for i in range(5):
            self.db.store_alert(
                src_ip=f'192.168.1.{i}',
                dst_ip='10.0.0.1',
                protocol='TCP',
                src_port=1000+i,
                dst_port=80,
                class_label='DoS',
                attack_type='DoS',
                confidence=0.9
            )
        
        stats = self.db.get_statistics()
        
        self.assertIn('total_alerts', stats)
        self.assertIn('by_class', stats)
        self.assertEqual(stats['total_alerts'], 5)
