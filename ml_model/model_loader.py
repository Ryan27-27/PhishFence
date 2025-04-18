"""
Loads and manages ML models for phishing detection
"""
import os
import pickle
import logging
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier

logger = logging.getLogger(__name__)

class ModelLoader:
    def __init__(self):
        self.model = None
        self.model_path = None
        self.load_model()
    
    def load_model(self):
        """Load the ML model from the configured path or use default"""
        # Get model path from config or use default location
        from utils.config_manager import ConfigManager
        config = ConfigManager()
        self.model_path = config.get('model_path')
        
        try:
            # If custom model path is specified and exists, load it
            if self.model_path and os.path.exists(self.model_path):
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                logger.info(f"Loaded ML model from {self.model_path}")
            else:
                # Try to load default model
                default_path = os.path.join(os.path.dirname(__file__), 'default_model.pkl')
                if os.path.exists(default_path):
                    with open(default_path, 'rb') as f:
                        self.model = pickle.load(f)
                    logger.info(f"Loaded default ML model")
                else:
                    # Create a simple model as fallback
                    self.model = self._create_simple_model()
                    logger.info("Created simple fallback ML model")
        except Exception as e:
            logger.error(f"Error loading ML model: {e}")
            # Create a simple model as fallback
            self.model = self._create_simple_model()
            logger.info("Created simple fallback ML model after error")
    
    def _create_simple_model(self):
        """Create a simple model as fallback"""
        # Create a simple RandomForest model with some reasonable defaults
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42
        )
        
        # Train on a tiny dataset with just a few examples
        # These are just placeholder values to initialize the model
        # This is not meant to be accurate, just to prevent errors
        X = np.array([
            # URL length, domain length, dots, hyphens, underscores, digits, https, subdomains,
            # path length, suspicious words, forms, inputs, images, links, ratio ext links,
            # password field, login form, external scripts
            
            # Legitimate examples
            [30, 10, 1, 0, 0, 0, 1, 2, 10, 0, 1, 5, 10, 20, 0.1, 0, 0, 0],
            [25, 8, 1, 0, 0, 0, 1, 2, 5, 0, 1, 3, 5, 15, 0.2, 0, 0, 0],
            
            # Phishing examples
            [60, 20, 3, 2, 1, 5, 0, 4, 30, 1, 2, 10, 2, 5, 0.8, 1, 1, 1],
            [45, 15, 2, 1, 0, 3, 0, 3, 25, 1, 1, 8, 1, 3, 0.9, 1, 1, 1]
        ])
        
        y = np.array([0, 0, 1, 1])  # 0 for legitimate, 1 for phishing
        
        model.fit(X, y)
        return model
    
    def predict(self, features):
        """
        Make a prediction using the loaded model
        
        Args:
            features: Dictionary of features extracted from the URL and content
            
        Returns:
            Dictionary with prediction results
        """
        if self.model is None:
            self.load_model()
        
        try:
            # Convert features dict to feature vector
            from ml_model.feature_extractor import FeatureExtractor
            feature_extractor = FeatureExtractor()
            feature_vector = feature_extractor.transform_features(features)
            
            # Make prediction
            feature_vector = np.array([feature_vector])
            prediction = self.model.predict(feature_vector)[0]
            
            if hasattr(self.model, 'predict_proba'):
                probabilities = self.model.predict_proba(feature_vector)[0]
                probability = probabilities[1]  # Probability of phishing class
            else:
                probability = float(prediction)  # Fall back to binary prediction
            
            return {
                'is_phishing': bool(prediction),
                'probability': float(probability),
                'confidence': float(probability) if probability >= 0.5 else float(1 - probability)
            }
        except Exception as e:
            logger.error(f"Error making prediction: {e}")
            # Return safe default
            return {
                'is_phishing': False,
                'probability': 0.0,
                'confidence': 0.0,
                'error': str(e)
            }