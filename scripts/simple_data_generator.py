#!/usr/bin/env python3
"""
Simple data generator script for phishing detection.
Generates sample CSV files without dependencies.
"""

import csv
import random
import json
from datetime import datetime
from pathlib import Path

def generate_sample_data():
    """Generate sample training data."""
    
    # Sample legitimate URLs
    legitimate_urls = [
        "https://www.google.com",
        "https://www.github.com", 
        "https://stackoverflow.com",
        "https://www.microsoft.com",
        "https://www.amazon.com",
        "https://www.paypal.com",
        "https://www.apple.com",
        "https://www.facebook.com",
        "https://www.youtube.com",
        "https://www.wikipedia.org"
    ]
    
    # Sample phishing URLs (obviously fake for demo)
    phishing_urls = [
        "http://paypal-security-update.suspicious.tk",
        "https://amazon-verify-account.fake.net", 
        "http://apple-id-locked.phish.com",
        "https://microsoft-security-alert.scam.org",
        "http://google-account-suspended.malicious.tk",
        "https://bank-security-notice.fake.co",
        "http://facebook-verify.suspicious.net",
        "https://github-security.phish.org",
        "http://youtube-copyright.scam.tk",
        "https://wikipedia-donation.fake.com"
    ]
    
    # Create data directory
    data_dir = Path("data")
    data_dir.mkdir(exist_ok=True)
    
    # Generate training data CSV
    training_data = []
    
    # Add legitimate URLs
    for url in legitimate_urls:
        training_data.append({
            'url': url,
            'label': 0,  # 0 = legitimate
            'timestamp': datetime.now().isoformat(),
            'url_length': len(url),
            'num_dots': url.count('.'),
            'has_https': 1 if url.startswith('https') else 0,
            'suspicious_keywords': sum(1 for word in ['secure', 'verify', 'update', 'login'] if word in url.lower())
        })
    
    # Add phishing URLs
    for url in phishing_urls:
        training_data.append({
            'url': url,
            'label': 1,  # 1 = phishing
            'timestamp': datetime.now().isoformat(),
            'url_length': len(url),
            'num_dots': url.count('.'),
            'has_https': 1 if url.startswith('https') else 0,
            'suspicious_keywords': sum(1 for word in ['secure', 'verify', 'update', 'login'] if word in url.lower())
        })
    
    # Shuffle the data
    random.shuffle(training_data)
    
    # Save to CSV
    csv_file = data_dir / "sample_training_data.csv"
    with open(csv_file, 'w', newline='') as f:
        if training_data:
            writer = csv.DictWriter(f, fieldnames=training_data[0].keys())
            writer.writeheader()
            writer.writerows(training_data)
    
    # Generate features CSV (more detailed)
    features_data = []
    for item in training_data:
        url = item['url']
        features_data.append({
            'url': url,
            'url_length': len(url),
            'num_dots': url.count('.'),
            'num_hyphens': url.count('-'),
            'num_underscores': url.count('_'),
            'num_slashes': url.count('/'),
            'has_https': 1 if url.startswith('https') else 0,
            'has_ip': 1 if any(c.isdigit() for c in url.split('//')[1].split('/')[0]) else 0,
            'suspicious_keywords': sum(1 for word in ['secure', 'verify', 'update', 'login', 'account', 'bank'] if word in url.lower()),
            'domain_length': len(url.split('//')[1].split('/')[0]),
            'label': item['label']
        })
    
    features_file = data_dir / "url_features.csv"
    with open(features_file, 'w', newline='') as f:
        if features_data:
            writer = csv.DictWriter(f, fieldnames=features_data[0].keys())
            writer.writeheader()
            writer.writerows(features_data)
    
    # Generate recent detections JSON
    recent_detections = []
    for i in range(50):
        url = random.choice(legitimate_urls + phishing_urls)
        is_phishing = url in phishing_urls
        recent_detections.append({
            'url': url,
            'prediction': {
                'is_phishing': is_phishing,
                'confidence': random.uniform(0.7, 0.95),
                'risk_score': random.uniform(7, 9) if is_phishing else random.uniform(1, 3)
            },
            'timestamp': datetime.now().isoformat()
        })
    
    json_file = data_dir / "recent_detections.json"
    with open(json_file, 'w') as f:
        json.dump(recent_detections, f, indent=2)
    
    print(f"✅ Generated sample data:")
    print(f"   📄 {csv_file} - {len(training_data)} training samples")
    print(f"   📄 {features_file} - {len(features_data)} feature vectors")
    print(f"   📄 {json_file} - {len(recent_detections)} recent detections")
    print(f"\n📊 Data distribution:")
    print(f"   🟢 Legitimate URLs: {sum(1 for item in training_data if item['label'] == 0)}")
    print(f"   🔴 Phishing URLs: {sum(1 for item in training_data if item['label'] == 1)}")

if __name__ == "__main__":
    generate_sample_data()