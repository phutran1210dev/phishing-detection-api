"""Configuration settings for the phishing detection API."""

from pydantic_settings import BaseSettings
from typing import List, Optional
import os

class Settings(BaseSettings):
    """Application settings."""
    
    # Application
    environment: str = "development"
    debug: bool = True
    api_host: str = "0.0.0.0"
    api_port: int = 8000
    log_level: str = "INFO"
    workers: int = 1
    
    # Database
    mongodb_url: str = "mongodb://localhost:27017"
    database_name: str = "phishing_detection"
    
    # Redis
    redis_url: str = "redis://localhost:6379"
    
    # Security
    jwt_secret_key: str = "secret_key"
    encryption_key: str = "default_key"
    
    # ML
    model_update_interval: int = 3600
    ensemble_weights: str = "[0.3,0.3,0.4]"
    enable_real_time_learning: bool = True
    
    # Feature Flags
    enable_advanced_ml: bool = True
    enable_threat_intelligence: bool = True
    enable_behavioral_analytics: bool = True
    enable_compliance_features: bool = True
    enable_siem_integration: bool = False
    enable_soar_integration: bool = False
    
    # Monitoring
    prometheus_enabled: bool = True
    metrics_port: int = 9090
    
    # Cache
    cache_ttl: int = 3600
    cache_max_size: int = 1000
    
    # Rate Limiting
    rate_limit_per_minute: int = 100
    rate_limit_burst: int = 20
    
    # File Upload
    max_file_size: str = "50MB"
    upload_dir: str = "./uploads"
    allowed_file_types: str = ".csv,.json,.txt,.xlsx"
    
    # Logging
    log_file: str = "./logs/app.log"
    log_rotation: str = "10MB"
    log_retention: str = "30"
    
    class Config:
        env_file = ".env.local"
        extra = "ignore"  # Ignore extra fields

# Global settings instance
settings = Settings()