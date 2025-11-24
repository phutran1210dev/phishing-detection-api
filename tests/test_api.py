"""Test API endpoints."""

import pytest
from fastapi import status

class TestDetectionEndpoints:
    """Test detection API endpoints."""
    
    def test_single_url_detection(self, client):
        """Test single URL detection endpoint."""
        response = client.post(
            "/api/v1/detect/url",
            json={"url": "https://www.google.com"}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "url" in data
        assert "is_phishing" in data
        assert "probability" in data
        assert "confidence" in data
        assert 0.0 <= data["probability"] <= 1.0
        assert 0.0 <= data["confidence"] <= 1.0
    
    def test_batch_url_detection(self, client, sample_urls):
        """Test batch URL detection endpoint."""
        response = client.post(
            "/api/v1/detect/batch",
            json={"urls": sample_urls[:2]}
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "results" in data
        assert "total_processed" in data
        assert len(data["results"]) == 2
        
        for result in data["results"]:
            assert "is_phishing" in result
            assert "probability" in result
    
    def test_invalid_url(self, client):
        """Test detection with invalid URL."""
        response = client.post(
            "/api/v1/detect/url",
            json={"url": "invalid-url"}
        )
        
        # Should handle gracefully
        assert response.status_code in [status.HTTP_200_OK, status.HTTP_422_UNPROCESSABLE_ENTITY]
    
    def test_detection_with_features(self, client):
        """Test detection with feature analysis included."""
        response = client.post(
            "/api/v1/detect/url",
            json={
                "url": "https://www.example.com",
                "include_features": True
            }
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        if "features" in data:
            assert "url_features" in data["features"]

class TestModelEndpoints:
    """Test model management endpoints."""
    
    def test_model_status(self, client):
        """Test model status endpoint."""
        response = client.get("/api/v1/models/status")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "status" in data
        assert "models" in data
    
    def test_model_metrics(self, client):
        """Test model metrics endpoint."""
        response = client.get("/api/v1/models/metrics")
        
        assert response.status_code == status.HTTP_200_OK
    
    def test_model_info(self, client):
        """Test model info endpoint."""
        response = client.get("/api/v1/models/info")
        
        assert response.status_code == status.HTTP_200_OK

class TestHealthEndpoints:
    """Test health check endpoints."""
    
    def test_health_check(self, client):
        """Test health check endpoint."""
        response = client.get("/api/v1/health")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "status" in data
        assert "database" in data
        assert "models" in data
        assert "uptime_seconds" in data
    
    def test_ping(self, client):
        """Test ping endpoint."""
        response = client.get("/api/v1/ping")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "message" in data
        assert data["message"] == "pong"
    
    def test_status(self, client):
        """Test status endpoint."""
        response = client.get("/api/v1/status")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "status" in data
        assert "service" in data

class TestRootEndpoint:
    """Test root endpoint."""
    
    def test_root(self, client):
        """Test root endpoint."""
        response = client.get("/")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "message" in data
        assert "version" in data