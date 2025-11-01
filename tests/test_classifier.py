import unittest
import numpy as np
from unittest.mock import Mock, patch
from nids.classifier import ThreatClassifier

class TestThreatClassifier(unittest.TestCase):
    
    def setUp(self):
        """Set up classifier."""
        self.config = {
            'ml_models': {
                'random_forest': 'models/model_rf.pkl',
                'ensemble': 'models/model_ensemble.pkl'
            }
        }
    
    @patch('nids.classifier.joblib.load')
    def test_classifier_initialization(self, mock_load):
        """Test classifier initialization."""
        mock_model = Mock()
        mock_load.return_value = mock_model
        
        classifier = ThreatClassifier(self.config)
        self.assertIsNotNone(classifier.rf_model)
    
    def test_classification(self):
        """Test classification with dummy model."""
        classifier = ThreatClassifier(self.config)
        
        # Create dummy features
        features = np.random.rand(41)
        
        result = classifier.classify(features)
        
        self.assertIsNotNone(result)
        self.assertIn('class', result)
        self.assertIn('confidence', result)
        self.assertIn('attack_type', result)
