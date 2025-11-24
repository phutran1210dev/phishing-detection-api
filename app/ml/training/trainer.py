"""Model training module for phishing detection."""

import asyncio
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.preprocessing import StandardScaler
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense, Dropout
from tensorflow.keras.optimizers import Adam
import joblib
import os
from datetime import datetime
from typing import Dict, Any, Optional, Tuple
from loguru import logger

from app.config import settings
from app.database import get_database

class ModelTrainer:
    """Train and evaluate phishing detection models."""
    
    def __init__(self):
        self.models = {}
        self.scaler = StandardScaler()
        self.feature_names = []
        
    async def train_models(self, model_name: Optional[str] = None, use_new_data: bool = True):
        """Train phishing detection models."""
        try:
            logger.info("Starting model training process")
            
            # Load training data
            X, y = await self._load_training_data(use_new_data)
            
            if X is None or len(X) == 0:
                logger.warning("No training data available, generating synthetic data")
                X, y = self._generate_synthetic_data()
            
            # Prepare data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train models
            if model_name:
                await self._train_single_model(model_name, X_train_scaled, y_train, X_test_scaled, y_test)
            else:
                await self._train_all_models(X_train_scaled, y_train, X_test_scaled, y_test)
            
            # Save models
            await self._save_models()
            
            logger.info("Model training completed successfully")
            
        except Exception as e:
            logger.error(f"Model training failed: {e}")
            raise e
    
    async def _load_training_data(self, use_new_data: bool = True) -> Tuple[Optional[np.ndarray], Optional[np.ndarray]]:
        """Load training data from database."""
        try:
            db = get_database()
            
            # Query for training data
            query = {}
            if use_new_data:
                # Include recent data
                query["timestamp"] = {"$gte": datetime.utcnow().replace(day=1)}
            
            cursor = db.training_data.find(query)
            data = await cursor.to_list(length=None)
            
            if not data:
                return None, None
            
            # Convert to features and labels
            features = []
            labels = []
            
            for item in data:
                if 'features' in item and 'label' in item:
                    features.append(item['features'])
                    labels.append(item['label'])
            
            if not features:
                return None, None
            
            X = np.array(features)
            y = np.array(labels)
            
            logger.info(f"Loaded {len(X)} training samples")
            return X, y
            
        except Exception as e:
            logger.error(f"Failed to load training data: {e}")
            return None, None
    
    def _generate_synthetic_data(self, n_samples: int = 10000) -> Tuple[np.ndarray, np.ndarray]:
        """Generate synthetic training data for development."""
        logger.info("Generating synthetic training data")
        
        np.random.seed(42)
        
        # Generate features based on phishing patterns
        n_features = 20
        X = np.random.randn(n_samples, n_features)
        
        # Create realistic phishing patterns
        phishing_indicators = []
        
        for i in range(n_samples):
            # URL length (longer URLs more likely to be phishing)
            url_length = np.random.exponential(50) + 20
            
            # Number of dots (more dots suspicious)
            num_dots = np.random.poisson(2) + np.random.randint(0, 3)
            
            # Has IP address (suspicious)
            has_ip = np.random.choice([0, 1], p=[0.9, 0.1])
            
            # Is shortened URL (suspicious)
            is_shortened = np.random.choice([0, 1], p=[0.95, 0.05])
            
            # Has suspicious words
            has_suspicious_words = np.random.choice([0, 1], p=[0.7, 0.3])
            
            # HTTPS usage (legitimate sites more likely to use HTTPS)
            is_https = np.random.choice([0, 1], p=[0.3, 0.7])
            
            # Create phishing score
            phishing_score = (
                (url_length > 80) * 0.3 +
                (num_dots > 4) * 0.2 +
                has_ip * 0.4 +
                is_shortened * 0.3 +
                has_suspicious_words * 0.2 +
                (1 - is_https) * 0.1
            )
            
            # Add some noise
            phishing_score += np.random.normal(0, 0.1)
            
            # Assign features
            X[i, 0] = url_length
            X[i, 1] = num_dots
            X[i, 2] = has_ip
            X[i, 3] = is_shortened
            X[i, 4] = has_suspicious_words
            X[i, 5] = is_https
            
            phishing_indicators.append(phishing_score)
        
        # Convert scores to binary labels
        y = (np.array(phishing_indicators) > 0.5).astype(int)
        
        # Ensure some class balance
        n_phishing = np.sum(y)
        if n_phishing < n_samples * 0.2:
            # Force some samples to be phishing
            indices = np.random.choice(np.where(y == 0)[0], size=int(n_samples * 0.3 - n_phishing), replace=False)
            y[indices] = 1
        
        logger.info(f"Generated {n_samples} samples with {np.sum(y)} phishing examples ({np.mean(y):.2%})")
        return X, y
    
    async def _train_single_model(self, model_name: str, X_train: np.ndarray, y_train: np.ndarray, 
                                X_test: np.ndarray, y_test: np.ndarray):
        """Train a single model."""
        logger.info(f"Training {model_name} model")
        
        if model_name == "random_forest":
            model = self._train_random_forest(X_train, y_train)
        elif model_name == "gradient_boosting":
            model = self._train_gradient_boosting(X_train, y_train)
        elif model_name == "neural_network":
            model = self._train_neural_network(X_train, y_train, X_test, y_test)
        else:
            raise ValueError(f"Unknown model name: {model_name}")
        
        self.models[model_name] = model
        
        # Evaluate model
        await self._evaluate_model(model_name, model, X_test, y_test)
    
    async def _train_all_models(self, X_train: np.ndarray, y_train: np.ndarray,
                              X_test: np.ndarray, y_test: np.ndarray):
        """Train all available models."""
        
        # Random Forest
        logger.info("Training Random Forest model")
        rf_model = self._train_random_forest(X_train, y_train)
        self.models["random_forest"] = rf_model
        await self._evaluate_model("random_forest", rf_model, X_test, y_test)
        
        # Gradient Boosting
        logger.info("Training Gradient Boosting model")
        gb_model = self._train_gradient_boosting(X_train, y_train)
        self.models["gradient_boosting"] = gb_model
        await self._evaluate_model("gradient_boosting", gb_model, X_test, y_test)
        
        # Neural Network (scikit-learn)
        logger.info("Training Neural Network model")
        nn_model = self._train_sklearn_neural_network(X_train, y_train)
        self.models["neural_network"] = nn_model
        await self._evaluate_model("neural_network", nn_model, X_test, y_test)
        
        # Create ensemble model
        logger.info("Creating ensemble model")
        ensemble_model = self._create_ensemble_model()
        self.models["ensemble"] = ensemble_model
    
    def _train_random_forest(self, X_train: np.ndarray, y_train: np.ndarray) -> RandomForestClassifier:
        """Train Random Forest model with hyperparameter tuning."""
        
        # Hyperparameter grid
        param_grid = {
            'n_estimators': [100, 200, 300],
            'max_depth': [10, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4]
        }
        
        rf = RandomForestClassifier(random_state=42)
        
        # Use a smaller grid for faster training in development
        if X_train.shape[0] < 5000:
            param_grid = {
                'n_estimators': [100, 200],
                'max_depth': [10, 20],
                'min_samples_split': [2, 5],
                'min_samples_leaf': [1, 2]
            }
        
        grid_search = GridSearchCV(rf, param_grid, cv=3, scoring='roc_auc', n_jobs=-1)
        grid_search.fit(X_train, y_train)
        
        logger.info(f"Best RF parameters: {grid_search.best_params_}")
        return grid_search.best_estimator_
    
    def _train_gradient_boosting(self, X_train: np.ndarray, y_train: np.ndarray) -> GradientBoostingClassifier:
        """Train Gradient Boosting model."""
        
        param_grid = {
            'n_estimators': [100, 200],
            'learning_rate': [0.05, 0.1, 0.15],
            'max_depth': [3, 5, 7]
        }
        
        gb = GradientBoostingClassifier(random_state=42)
        grid_search = GridSearchCV(gb, param_grid, cv=3, scoring='roc_auc', n_jobs=-1)
        grid_search.fit(X_train, y_train)
        
        logger.info(f"Best GB parameters: {grid_search.best_params_}")
        return grid_search.best_estimator_
    
    def _train_sklearn_neural_network(self, X_train: np.ndarray, y_train: np.ndarray) -> MLPClassifier:
        """Train scikit-learn Neural Network model."""
        
        mlp = MLPClassifier(
            hidden_layer_sizes=(100, 50),
            activation='relu',
            solver='adam',
            alpha=0.001,
            learning_rate='adaptive',
            max_iter=500,
            random_state=42
        )
        
        mlp.fit(X_train, y_train)
        return mlp
    
    def _train_neural_network(self, X_train: np.ndarray, y_train: np.ndarray,
                            X_test: np.ndarray, y_test: np.ndarray) -> tf.keras.Model:
        """Train TensorFlow Neural Network model."""
        
        model = Sequential([
            Dense(128, activation='relu', input_shape=(X_train.shape[1],)),
            Dropout(0.3),
            Dense(64, activation='relu'),
            Dropout(0.3),
            Dense(32, activation='relu'),
            Dropout(0.2),
            Dense(1, activation='sigmoid')
        ])
        
        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', 'precision', 'recall']
        )
        
        # Train model
        history = model.fit(
            X_train, y_train,
            validation_data=(X_test, y_test),
            epochs=50,
            batch_size=settings.batch_size,
            verbose=0
        )
        
        return model
    
    def _create_ensemble_model(self) -> Dict[str, Any]:
        """Create ensemble model from trained models."""
        return {
            'type': 'voting_ensemble',
            'models': list(self.models.keys()),
            'weights': [1.0] * len(self.models),  # Equal weights
            'method': 'average'
        }
    
    async def _evaluate_model(self, model_name: str, model: Any, X_test: np.ndarray, y_test: np.ndarray):
        """Evaluate model performance."""
        try:
            # Make predictions
            if hasattr(model, 'predict_proba'):
                y_pred_proba = model.predict_proba(X_test)[:, 1]
            else:
                y_pred_proba = model.predict(X_test)
            
            y_pred = (y_pred_proba > 0.5).astype(int)
            
            # Calculate metrics
            from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
            
            accuracy = accuracy_score(y_test, y_pred)
            precision = precision_score(y_test, y_pred, zero_division=0)
            recall = recall_score(y_test, y_pred, zero_division=0)
            f1 = f1_score(y_test, y_pred, zero_division=0)
            
            try:
                auc_roc = roc_auc_score(y_test, y_pred_proba)
            except:
                auc_roc = 0.5
            
            metrics = {
                'model_name': model_name,
                'accuracy': accuracy,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'auc_roc': auc_roc,
                'test_samples': len(y_test)
            }
            
            logger.info(f"{model_name} metrics: Accuracy={accuracy:.3f}, Precision={precision:.3f}, "
                       f"Recall={recall:.3f}, F1={f1:.3f}, AUC-ROC={auc_roc:.3f}")
            
            # Store metrics in database
            await self._store_model_metrics(model_name, metrics)
            
        except Exception as e:
            logger.error(f"Model evaluation failed for {model_name}: {e}")
    
    async def _save_models(self):
        """Save trained models to disk."""
        try:
            os.makedirs(settings.model_path, exist_ok=True)
            
            for model_name, model in self.models.items():
                if model_name == "ensemble":
                    # Save ensemble configuration
                    filepath = os.path.join(settings.model_path, f"{model_name}_model.joblib")
                    joblib.dump(model, filepath)
                else:
                    filepath = os.path.join(settings.model_path, f"{model_name.replace('_', '')}_model.joblib")
                    joblib.dump(model, filepath)
                
                logger.info(f"Saved {model_name} model to {filepath}")
            
            # Save scaler
            scaler_path = os.path.join(settings.model_path, "scaler.joblib")
            joblib.dump(self.scaler, scaler_path)
            
        except Exception as e:
            logger.error(f"Failed to save models: {e}")
            raise e
    
    async def _store_model_metrics(self, model_name: str, metrics: Dict[str, Any]):
        """Store model metrics in database."""
        try:
            db = get_database()
            
            document = {
                'model_name': model_name,
                'metrics': metrics,
                'timestamp': datetime.utcnow(),
                'version': '1.0.0'
            }
            
            await db.model_metadata.insert_one(document)
            
        except Exception as e:
            logger.warning(f"Failed to store model metrics: {e}")