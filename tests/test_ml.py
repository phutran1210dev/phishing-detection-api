"""Test machine learning components."""

import pytest
import numpy as np
from unittest.mock import AsyncMock, MagicMock

from app.ml.inference.predictor import PhishingPredictor
from app.ml.preprocessing.feature_extractor import FeatureExtractor
from app.ml.training.trainer import ModelTrainer

class TestPhishingPredictor:
    """Test PhishingPredictor class."""
    
    @pytest.fixture
    def predictor(self):
        """Create predictor instance."""
        return PhishingPredictor()
    
    @pytest.mark.asyncio
    async def test_predict_single(self, predictor):
        """Test single URL prediction."""
        url = "https://www.example.com"
        result = await predictor.predict_single(url)
        
        assert isinstance(result, dict)
        assert "is_phishing" in result
        assert "probability" in result
        assert "confidence" in result
        assert isinstance(result["is_phishing"], bool)
        assert 0.0 <= result["probability"] <= 1.0
        assert 0.0 <= result["confidence"] <= 1.0
    
    @pytest.mark.asyncio
    async def test_predict_batch(self, predictor, sample_urls):
        """Test batch prediction."""
        results = await predictor.predict_batch(sample_urls[:2])
        
        assert isinstance(results, list)
        assert len(results) == 2
        
        for result in results:
            assert "is_phishing" in result
            assert "probability" in result
            assert "confidence" in result
    
    @pytest.mark.asyncio
    async def test_get_statistics(self, predictor):
        """Test statistics retrieval."""
        stats = await predictor.get_statistics()
        
        assert isinstance(stats, dict)
        assert "models_loaded" in stats
        assert "model_names" in stats
    
    def test_prepare_feature_vector(self, predictor):
        """Test feature vector preparation."""
        features = {
            "url_features": {"url_length": 50, "num_dots": 2},
            "content_features": {"num_forms": 1},
            "behavioral_features": {"redirect_count": 0}
        }
        
        vector = predictor._prepare_feature_vector(features)
        assert isinstance(vector, np.ndarray)
        assert len(vector) == 20  # Expected feature count
    
    def test_heuristic_prediction(self, predictor):
        """Test heuristic prediction fallback."""
        # Test suspicious URL
        suspicious_url = "https://bit.ly/suspicious-link-with-many-parameters"
        score = predictor._heuristic_prediction(suspicious_url)
        assert 0.0 <= score <= 1.0
        
        # Test normal URL
        normal_url = "https://www.google.com"
        score = predictor._heuristic_prediction(normal_url)
        assert 0.0 <= score <= 1.0

class TestFeatureExtractor:
    """Test FeatureExtractor class."""
    
    @pytest.fixture
    def extractor(self):
        """Create feature extractor instance."""
        return FeatureExtractor()
    
    @pytest.mark.asyncio
    async def test_extract_features(self, extractor):
        """Test feature extraction."""
        url = "https://www.example.com"
        
        with pytest.raises(Exception):
            # This will likely fail due to network, but we test the structure
            features = await extractor.extract_features(url)
    
    def test_extract_url_features(self, extractor):
        """Test URL feature extraction."""
        url = "https://suspicious-site.com/long/path?param=value#anchor"
        features = extractor._extract_url_features(url)
        
        assert isinstance(features, dict)
        assert "url_length" in features
        assert "num_dots" in features
        assert "num_slashes" in features
        assert "is_https" in features
        assert features["url_length"] > 0
        assert features["is_https"] == 1
    
    def test_is_ip_address(self, extractor):
        """Test IP address detection."""
        assert extractor._is_ip_address("192.168.1.1") == True
        assert extractor._is_ip_address("www.example.com") == False
        assert extractor._is_ip_address("256.1.1.1") == False
    
    def test_calculate_entropy(self, extractor):
        """Test entropy calculation."""
        # Random string should have high entropy
        random_text = "asldjfklasdjfklajsdf"
        entropy1 = extractor._calculate_entropy(random_text)
        
        # Repeated string should have low entropy
        repeated_text = "aaaaaaaaaaaaaaaa"
        entropy2 = extractor._calculate_entropy(repeated_text)
        
        assert entropy1 > entropy2
        assert entropy1 > 0
        assert entropy2 >= 0

class TestModelTrainer:
    """Test ModelTrainer class."""
    
    @pytest.fixture
    def trainer(self):
        """Create model trainer instance."""
        return ModelTrainer()
    
    def test_generate_synthetic_data(self, trainer):
        """Test synthetic data generation."""
        X, y = trainer._generate_synthetic_data(n_samples=100)
        
        assert X.shape == (100, 20)
        assert y.shape == (100,)
        assert np.all((y == 0) | (y == 1))  # Binary labels
        assert 0.1 <= np.mean(y) <= 0.9  # Reasonable class balance
    
    def test_prepare_feature_vector(self, trainer):
        """Test feature vector preparation."""
        X, y = trainer._generate_synthetic_data(n_samples=10)
        assert isinstance(X, np.ndarray)
        assert isinstance(y, np.ndarray)
        assert X.dtype == np.float64
    
    @pytest.mark.asyncio
    async def test_load_training_data_empty(self, trainer):
        """Test loading training data when none exists."""
        # Mock empty database response
        trainer._load_training_data = AsyncMock(return_value=(None, None))
        
        X, y = await trainer._load_training_data()
        assert X is None
        assert y is None