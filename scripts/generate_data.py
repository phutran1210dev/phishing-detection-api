#!/usr/bin/env python3
"""
Synthetic data generation script for development and testing.
This script generates synthetic phishing/legitimate URL data for training.
"""

import asyncio
import random
import sys
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Add app to path
sys.path.append(str(Path(__file__).parent.parent))

from app.database import connect_to_mongo, close_mongo_connection, get_database
from loguru import logger

# Sample legitimate domains
LEGITIMATE_DOMAINS = [
    "google.com", "microsoft.com", "apple.com", "amazon.com", "github.com",
    "stackoverflow.com", "wikipedia.org", "linkedin.com", "twitter.com", 
    "facebook.com", "youtube.com", "netflix.com", "paypal.com", "ebay.com",
    "yahoo.com", "reddit.com", "instagram.com", "pinterest.com", "dropbox.com",
    "medium.com", "wordpress.com", "shopify.com", "salesforce.com", "zoom.us"
]

# Sample phishing indicators
PHISHING_DOMAINS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "paypaI-secure.tk", "amazon-update.ml", "microsoft-verify.ga",
    "apple-support.cf", "google-security.bit", "github-login.onion",
    "bank-update.tk", "secure-login.ml", "verify-account.ga",
    "suspicious-site.cf", "phishing-example.bit"
]

SUSPICIOUS_PATHS = [
    "/secure/login", "/verify/account", "/update/payment", "/confirm/identity",
    "/security/alert", "/account/suspended", "/urgent/action", "/limited/access",
    "/banking/secure", "/paypal/verify", "/amazon/update", "/apple/support"
]

def generate_synthetic_urls(count: int) -> List[Dict[str, Any]]:
    """Generate synthetic URL data with labels."""
    
    urls_data = []
    
    for i in range(count):
        is_phishing = random.choice([True, False])
        
        if is_phishing:
            # Generate phishing URL
            domain = random.choice(PHISHING_DOMAINS)
            path = random.choice(SUSPICIOUS_PATHS)
            
            # Add suspicious elements
            if random.random() < 0.3:
                domain = f"{random.randint(100, 999)}.{domain}"
            
            if random.random() < 0.4:
                path += f"?token={random.randint(100000, 999999)}"
            
            url = f"http{'s' if random.random() < 0.3 else ''}://{domain}{path}"
            
        else:
            # Generate legitimate URL
            domain = random.choice(LEGITIMATE_DOMAINS)
            paths = ["/", "/about", "/contact", "/help", "/support", "/login", "/signup"]
            path = random.choice(paths)
            
            url = f"https://{domain}{path}"
        
        # Create feature vector (simplified)
        features = {
            "url_length": len(url),
            "num_dots": url.count('.'),
            "num_hyphens": url.count('-'),
            "num_underscores": url.count('_'),
            "num_slashes": url.count('/'),
            "num_questionmarks": url.count('?'),
            "num_equals": url.count('='),
            "num_at": url.count('@'),
            "has_ip": 1 if any(char.isdigit() for char in domain) else 0,
            "is_https": 1 if url.startswith('https') else 0,
            "has_suspicious_words": 1 if any(word in url.lower() for word in 
                                           ['secure', 'verify', 'update', 'confirm']) else 0,
            "entropy": sum(ord(c) for c in url) / len(url),  # Simple entropy approximation
        }
        
        urls_data.append({
            "url": url,
            "features": list(features.values()),
            "label": 1 if is_phishing else 0,
            "timestamp": datetime.utcnow()
        })
    
    return urls_data

async def store_synthetic_data(urls_data: List[Dict[str, Any]]):
    """Store synthetic data in database."""
    
    try:
        database = get_database()
        
        # Store in training_data collection
        await database.training_data.insert_many(urls_data)
        
        logger.info(f"Stored {len(urls_data)} synthetic training samples")
        
        # Print statistics
        phishing_count = sum(1 for item in urls_data if item["label"] == 1)
        legitimate_count = len(urls_data) - phishing_count
        
        logger.info(f"Generated data: {phishing_count} phishing, {legitimate_count} legitimate")
        
    except Exception as e:
        logger.error(f"Failed to store synthetic data: {e}")
        raise e

async def main():
    """Generate and store synthetic training data."""
    
    logger.info("Starting synthetic data generation")
    
    try:
        # Connect to database
        await connect_to_mongo()
        
        # Generate synthetic data
        sample_count = 1000  # Generate 1000 samples
        urls_data = generate_synthetic_urls(sample_count)
        
        # Store in database
        await store_synthetic_data(urls_data)
        
        logger.info("Synthetic data generation completed successfully")
        
    except Exception as e:
        logger.error(f"Synthetic data generation failed: {e}")
        sys.exit(1)
    finally:
        await close_mongo_connection()

if __name__ == "__main__":
    asyncio.run(main())