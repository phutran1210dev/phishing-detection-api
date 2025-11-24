"""Configuration management."""

from pydantic_settings import BaseSettings
from typing import Optional
import os

class Settings(BaseSettings):
    """Application settings."""
    
    # Database
    database_url: str = "mongodb://localhost:27017"
    database_name: str = "phishing_detection"
    
    # ML Models
    model_path: str = "./models"
    model_retrain_interval_hours: int = 24
    batch_size: int = 32
    confidence_threshold: float = 0.5
    
    # API Configuration
    api_prefix: str = "/api/v1"
    max_batch_size: int = 100
    rate_limit_per_minute: int = 60
    
    # Security
    secret_key: str = "your-secret-key-here"
    access_token_expire_minutes: int = 30
    
    # Logging
    log_level: str = "INFO"
    
    # External Services
    whois_timeout: int = 10
    http_timeout: int = 30
    user_agent: str = "PhishingDetectionBot/1.0"
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()