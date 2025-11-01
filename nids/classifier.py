import logging
import joblib
import os
import numpy as np
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger(__name__)

class ThreatClassifier:
    """Machine learning threat classifier."""
    
    def __init__(self, config):
        self.config = config
        self.rf_model = None
        self.ensemble_model = None
        self.attack_map = {
            0: 'Normal',
            1: 'DoS',
            2: 'Probe',
            3: 'R2L',
            4: 'U2R'
        }
        
        self.load_models()
    
    def load_models(self):
        """Load pre-trained ML models."""
        try:
            rf_path = self.config['ml_models']['random_forest']
            if os.path.exists(rf_path):
                self.rf_model = joblib.load(rf_path)
                logger.info(f"Loaded Random Forest model from {rf_path}")
            else:
                logger.warning(f"Random Forest model not found at {rf_path}, creating dummy model")
                self.rf_model = self.create_dummy_model()
            
            ensemble_path = self.config['ml_models']['ensemble']
            if os.path.exists(ensemble_path):
                self.ensemble_model = joblib.load(ensemble_path)
                logger.info(f"Loaded ensemble model from {ensemble_path}")
            
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            self.rf_model = self.create_dummy_model()
    
    def create_dummy_model(self):
        """Create a dummy model for testing when real model is not available."""
        # This is just for demonstration - replace with actual trained model
        model = RandomForestClassifier(n_estimators=10, random_state=42)
        # Fit with dummy data
        X_dummy = np.random.rand(100, 41)
        y_dummy = np.random.randint(0, 5, 100)
        model.fit(X_dummy, y_dummy)
        return model
    
    def classify(self, features):
        """
        Classify traffic based on extracted features.
        Returns dict with class, attack_type, and confidence.
        """
        try:
            if self.rf_model is None:
                logger.error("No model loaded for classification")
                return None
            
            # Reshape features for single prediction
            if len(features.shape) == 1:
                features = features.reshape(1, -1)
            
            # Get prediction
            prediction = self.rf_model.predict(features)[0]
            probabilities = self.rf_model.predict_proba(features)[0]
            confidence = float(np.max(probabilities))
            
            # Map to attack type
            class_label = self.attack_map.get(prediction, 'Unknown')
            
            # Use ensemble if available for high-confidence decisions
            if self.ensemble_model and confidence < 0.8:
                ensemble_pred = self.ensemble_model.predict(features)[0]
                ensemble_proba = self.ensemble_model.predict_proba(features)[0]
                ensemble_conf = float(np.max(ensemble_proba))
                
                if ensemble_conf > confidence:
                    prediction = ensemble_pred
                    confidence = ensemble_conf
                    class_label = self.attack_map.get(prediction, 'Unknown')
            
            result = {
                'class': class_label,
                'attack_type': class_label if class_label != 'Normal' else None,
                'confidence': confidence,
                'raw_prediction': int(prediction)
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error during classification: {e}")
            return None