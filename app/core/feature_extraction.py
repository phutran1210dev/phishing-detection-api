"""Feature extraction module for URL analysis."""

import asyncio
import re
import tldextract
from urllib.parse import urlparse
from typing import Dict, Any
import aiohttp
from loguru import logger

class FeatureExtractor:
    """Extract features from URLs for ML models."""
    
    def __init__(self):
        self.session = None
    
    async def extract_features(self, url: str) -> Dict[str, Any]:
        """Extract comprehensive features from URL."""
        
        try:
            # Parse URL
            parsed = urlparse(url)
            extracted = tldextract.extract(url)
            
            features = {}
            
            # Basic URL features
            features['url_length'] = len(url)
            features['has_https'] = url.startswith('https://')
            features['domain_length'] = len(extracted.domain) if extracted.domain else 0
            features['subdomain_count'] = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
            
            # Path features
            features['path_length'] = len(parsed.path)
            features['has_query'] = bool(parsed.query)
            features['query_length'] = len(parsed.query) if parsed.query else 0
            
            # Suspicious patterns
            suspicious_keywords = [
                'login', 'secure', 'account', 'update', 'verify', 'confirm',
                'bank', 'paypal', 'amazon', 'microsoft', 'apple'
            ]
            
            features['suspicious_keywords_count'] = sum(
                1 for keyword in suspicious_keywords 
                if keyword.lower() in url.lower()
            )
            
            # Domain features (mock data for testing)
            features['domain_age_days'] = 365  # Mock: 1 year old
            features['is_ip_address'] = bool(re.match(r'\d+\.\d+\.\d+\.\d+', extracted.domain or ''))
            
            # Character analysis
            features['digit_count'] = sum(1 for c in url if c.isdigit())
            features['special_char_count'] = sum(1 for c in url if not c.isalnum() and c not in '/:.-')
            
            logger.info(f"Extracted {len(features)} features for URL: {url}")
            return features
            
        except Exception as e:
            logger.error(f"Error extracting features from {url}: {e}")
            # Return basic features on error
            return {
                'url_length': len(url),
                'has_https': url.startswith('https://'),
                'error': str(e)
            }