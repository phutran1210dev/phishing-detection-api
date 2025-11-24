"""Machine learning inference module for phishing prediction."""

import asyncio
import time
import joblib
import numpy as np
from typing import Dict, List, Any, Optional
from datetime import datetime
from loguru import logger
import os

from app.config import settings
from app.ml.preprocessing.feature_extractor import FeatureExtractor
from app.database import get_database

class PhishingPredictor:
    """Main predictor class for phishing detection."""
    
    def __init__(self):
        self.models = {}
        self.feature_extractor = FeatureExtractor()
        self._load_models()
    
    def _load_models(self):
        """Load trained models from disk."""
        try:
            model_path = settings.model_path
            if not os.path.exists(model_path):
                logger.warning(f"Model path {model_path} does not exist")
                return
            
            # Load different model types
            model_files = {
                "random_forest": "rf_model.joblib",
                "gradient_boosting": "gb_model.joblib", 
                "neural_network": "nn_model.joblib",
                "ensemble": "ensemble_model.joblib"
            }
            
            for model_name, filename in model_files.items():
                filepath = os.path.join(model_path, filename)
                if os.path.exists(filepath):
                    try:
                        self.models[model_name] = joblib.load(filepath)
                        logger.info(f"Loaded model: {model_name}")
                    except Exception as e:
                        logger.error(f"Failed to load model {model_name}: {e}")
            
            if not self.models:
                logger.warning("No models loaded - creating mock models for development")
                self._create_mock_models()
                
        except Exception as e:
            logger.error(f"Error loading models: {e}")
            self._create_mock_models()
    
    def _create_mock_models(self):
        """Create mock models for development/demo purposes."""
        from sklearn.ensemble import RandomForestClassifier
        from sklearn.model_selection import train_test_split
        from sklearn.datasets import make_classification
        
        # Generate synthetic data for demo
        X, y = make_classification(n_samples=1000, n_features=20, n_classes=2, random_state=42)
        X_train, _, y_train, _ = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Create and train a simple model
        rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        rf_model.fit(X_train, y_train)
        
        self.models["random_forest"] = rf_model
        logger.info("Created mock Random Forest model for development")
    
    async def predict_single(self, url: str, include_features: bool = False) -> Dict[str, Any]:
        """Predict phishing probability for a single URL."""
        start_time = time.time()
        
        try:
            # Extract features
            features = await self.feature_extractor.extract_features(url)
            feature_vector = self._prepare_feature_vector(features)
            
            # Make prediction using ensemble of models
            probabilities = []
            predictions = []
            
            for model_name, model in self.models.items():
                try:
                    if hasattr(model, 'predict_proba'):
                        proba = model.predict_proba(feature_vector.reshape(1, -1))[0]
                        prob_phishing = proba[1] if len(proba) > 1 else proba[0]
                    else:
                        # For models without predict_proba, use decision function or predict
                        pred = model.predict(feature_vector.reshape(1, -1))[0]
                        prob_phishing = float(pred)
                    
                    probabilities.append(prob_phishing)
                    predictions.append(prob_phishing > settings.confidence_threshold)
                    
                except Exception as e:
                    logger.warning(f"Model {model_name} prediction failed: {e}")
                    # Use a default prediction based on URL analysis
                    prob_phishing = self._heuristic_prediction(url)
                    probabilities.append(prob_phishing)
                    predictions.append(prob_phishing > settings.confidence_threshold)
            
            # Ensemble prediction (average)
            avg_probability = np.mean(probabilities) if probabilities else 0.5
            is_phishing = avg_probability > settings.confidence_threshold
            confidence = self._calculate_confidence(probabilities)
            
            processing_time = (time.time() - start_time) * 1000
            
            result = {
                "is_phishing": is_phishing,
                "probability": float(avg_probability),
                "confidence": confidence,
                "processing_time_ms": processing_time
            }
            
            if include_features:
                result["features"] = {
                    "url_features": features.get("url_features", {}),
                    "content_features": features.get("content_features", {}),
                    "behavioral_features": features.get("behavioral_features", {})
                }
            
            # Store prediction in database
            await self._store_prediction(url, result)
            
            return result
            
        except Exception as e:
            logger.error(f"Prediction failed for URL {url}: {e}")
            # Return conservative prediction on error
            return {
                "is_phishing": False,
                "probability": 0.5,
                "confidence": 0.1,
                "processing_time_ms": (time.time() - start_time) * 1000,
                "error": str(e)
            }
    
    async def predict_batch(self, urls: List[str], include_features: bool = False) -> List[Dict[str, Any]]:
        """Predict phishing probability for multiple URLs."""
        tasks = [self.predict_single(url, include_features) for url in urls]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Handle any exceptions in results
        processed_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(f"Batch prediction failed for URL {urls[i]}: {result}")
                processed_results.append({
                    "is_phishing": False,
                    "probability": 0.5,
                    "confidence": 0.1,
                    "processing_time_ms": 0,
                    "error": str(result)
                })
            else:
                processed_results.append(result)
        
        return processed_results
    
    def _prepare_feature_vector(self, features: Dict[str, Any]) -> np.ndarray:
        """Convert extracted features to model input vector."""
        # This is a simplified version - in production, you'd have a proper feature pipeline
        feature_list = []
        
        # URL features (simplified)
        url_features = features.get("url_features", {})
        feature_list.extend([
            url_features.get("url_length", 0),
            url_features.get("num_dots", 0),
            url_features.get("num_hyphens", 0),
            url_features.get("num_underscores", 0),
            url_features.get("num_slashes", 0),
            url_features.get("num_questionmarks", 0),
            url_features.get("num_equals", 0),
            url_features.get("num_at", 0),
            url_features.get("num_and", 0),
            url_features.get("num_exclamation", 0),
            url_features.get("has_ip", 0),
            url_features.get("has_suspicious_tld", 0),
            url_features.get("entropy", 0),
        ])
        
        # Content features (simplified)
        content_features = features.get("content_features", {})
        feature_list.extend([
            content_features.get("num_forms", 0),
            content_features.get("num_input_fields", 0),
            content_features.get("has_password_field", 0),
            content_features.get("num_images", 0),
            content_features.get("num_links", 0),
            content_features.get("content_length", 0),
            content_features.get("num_external_links", 0),
        ])
        
        # Pad or truncate to expected size (20 features for mock model)
        while len(feature_list) < 20:
            feature_list.append(0)
        feature_list = feature_list[:20]
        
        return np.array(feature_list, dtype=np.float32)
    
    def _heuristic_prediction(self, url: str) -> float:
        """Simple heuristic-based prediction for fallback."""
        suspicious_indicators = [
            "bit.ly", "tinyurl", "t.co", "goo.gl",
            "secure", "verify", "update", "confirm",
            "account", "login", "signin", "bank",
            len(url) > 100,
            url.count('.') > 4,
            url.count('-') > 3,
            any(char.isdigit() for char in url.split('//')[1].split('/')[0])
        ]
        
        score = sum(1 for indicator in suspicious_indicators if 
                   (isinstance(indicator, str) and indicator in url.lower()) or
                   (isinstance(indicator, bool) and indicator))
        
        return min(score / len(suspicious_indicators), 0.9)
    
    def _calculate_confidence(self, probabilities: List[float]) -> float:
        """Calculate prediction confidence based on model agreement."""
        if not probabilities:
            return 0.0
        
        if len(probabilities) == 1:
            return abs(probabilities[0] - 0.5) * 2
        
        # Higher confidence when models agree
        std_dev = np.std(probabilities)
        max_std = 0.5  # Maximum possible standard deviation for probabilities
        confidence = 1.0 - (std_dev / max_std)
        
        return float(confidence)
    
    async def _store_prediction(self, url: str, result: Dict[str, Any]):
        """Store prediction result in database."""
        try:
            db = get_database()
            document = {
                "url": url,
                "result": result,
                "timestamp": datetime.utcnow()
            }
            await db.detections.insert_one(document)
        except Exception as e:
            logger.warning(f"Failed to store prediction: {e}")
    
    async def get_model_info(self) -> Dict[str, Any]:
        """Get information about loaded models."""
        model_info = {}
        
        for model_name in self.models.keys():
            # Mock model information - in production, load from metadata
            model_info[model_name] = {
                "version": "1.0.0",
                "accuracy": 0.952,
                "precision": 0.948,
                "recall": 0.956,
                "f1_score": 0.952,
                "last_trained": datetime.utcnow(),
                "total_samples": 50000
            }
        
        return model_info
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get prediction statistics."""
        try:
            db = get_database()
            
            # Get recent predictions
            recent_count = await db.detections.count_documents({
                "timestamp": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0)}
            })
            
            # Get phishing detection rate
            phishing_count = await db.detections.count_documents({
                "result.is_phishing": True,
                "timestamp": {"$gte": datetime.utcnow().replace(hour=0, minute=0, second=0)}
            })
            
            phishing_rate = phishing_count / recent_count if recent_count > 0 else 0
            
            return {
                "predictions_today": recent_count,
                "phishing_detected_today": phishing_count,
                "phishing_rate": phishing_rate,
                "models_loaded": len(self.models),
                "model_names": list(self.models.keys())
            }
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {
                "predictions_today": 0,
                "phishing_detected_today": 0,
                "phishing_rate": 0.0,
                "models_loaded": len(self.models),
                "model_names": list(self.models.keys())
            }
    
    async def get_detailed_metrics(self) -> Dict[str, Any]:
        """Get detailed model performance metrics."""
        # Mock detailed metrics - in production, load from model metadata
        return {
            "overall": {
                "accuracy": 0.952,
                "precision": 0.948,
                "recall": 0.956,
                "f1_score": 0.952,
                "auc_roc": 0.978,
                "false_positive_rate": 0.021
            },
            "by_model": {
                model_name: {
                    "accuracy": 0.950 + np.random.random() * 0.01,
                    "precision": 0.945 + np.random.random() * 0.01,
                    "recall": 0.950 + np.random.random() * 0.01
                }
                for model_name in self.models.keys()
            }
        }
    
    async def get_comprehensive_info(self) -> Dict[str, Any]:
        """Get comprehensive model and system information."""
        model_info = await self.get_model_info()
        stats = await self.get_statistics()
        metrics = await self.get_detailed_metrics()
        
        return {
            "models": model_info,
            "statistics": stats,
            "metrics": metrics,
            "system": {
                "feature_extractor_version": "1.0.0",
                "total_features": 20,
                "prediction_threshold": settings.confidence_threshold,
                "ensemble_method": "average"
            }
        }
    
    async def reload_models(self):
        """Reload models from disk."""
        self.models.clear()
        self._load_models()
        logger.info("Models reloaded successfully")