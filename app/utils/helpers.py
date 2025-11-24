"""Utility functions for the phishing detection API."""

import hashlib
import json
import re
from typing import Any, Dict, List
from urllib.parse import urlparse
import asyncio

def normalize_url(url: str) -> str:
    """Normalize URL for consistent processing."""
    # Add protocol if missing
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    # Parse and reconstruct URL
    parsed = urlparse(url)
    
    # Remove trailing slashes and normalize case
    path = parsed.path.rstrip('/')
    if not path:
        path = '/'
    
    normalized = f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}"
    
    if parsed.query:
        normalized += f"?{parsed.query}"
    
    return normalized

def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except:
        return ""

def generate_url_hash(url: str) -> str:
    """Generate MD5 hash for URL."""
    normalized_url = normalize_url(url)
    return hashlib.md5(normalized_url.encode()).hexdigest()

def is_valid_url(url: str) -> bool:
    """Check if URL is valid."""
    url_pattern = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    
    return bool(url_pattern.match(url))

def sanitize_input(text: str, max_length: int = 1000) -> str:
    """Sanitize user input."""
    if not text:
        return ""
    
    # Remove potentially dangerous characters
    sanitized = re.sub(r'[<>"\']', '', text)
    
    # Truncate to max length
    return sanitized[:max_length]

def calculate_similarity(text1: str, text2: str) -> float:
    """Calculate similarity between two texts using Jaccard similarity."""
    if not text1 or not text2:
        return 0.0
    
    # Convert to sets of words
    words1 = set(text1.lower().split())
    words2 = set(text2.lower().split())
    
    # Calculate Jaccard similarity
    intersection = words1.intersection(words2)
    union = words1.union(words2)
    
    if not union:
        return 0.0
    
    return len(intersection) / len(union)

def format_response(data: Any, status: str = "success", message: str = "") -> Dict[str, Any]:
    """Format API response consistently."""
    return {
        "status": status,
        "message": message,
        "data": data
    }

def validate_batch_request(urls: List[str], max_size: int = 100) -> List[str]:
    """Validate and clean batch URL request."""
    if not urls:
        return []
    
    if len(urls) > max_size:
        urls = urls[:max_size]
    
    # Remove duplicates and invalid URLs
    valid_urls = []
    seen_urls = set()
    
    for url in urls:
        if url and isinstance(url, str):
            normalized_url = normalize_url(url)
            if is_valid_url(normalized_url) and normalized_url not in seen_urls:
                valid_urls.append(normalized_url)
                seen_urls.add(normalized_url)
    
    return valid_urls

async def retry_async(func, *args, max_retries: int = 3, delay: float = 1.0, **kwargs):
    """Retry async function with exponential backoff."""
    for attempt in range(max_retries):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            
            await asyncio.sleep(delay * (2 ** attempt))
    
    return None

def mask_sensitive_data(data: str, mask_char: str = "*") -> str:
    """Mask sensitive information in strings."""
    # Mask email addresses
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    data = re.sub(email_pattern, lambda m: m.group()[:2] + mask_char * (len(m.group()) - 4) + m.group()[-2:], data)
    
    # Mask phone numbers
    phone_pattern = r'\b\d{3}-?\d{3}-?\d{4}\b'
    data = re.sub(phone_pattern, mask_char * 10, data)
    
    # Mask credit card numbers
    cc_pattern = r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b'
    data = re.sub(cc_pattern, mask_char * 16, data)
    
    return data

def get_file_size_mb(file_path: str) -> float:
    """Get file size in megabytes."""
    try:
        import os
        size_bytes = os.path.getsize(file_path)
        return size_bytes / (1024 * 1024)
    except:
        return 0.0

def truncate_text(text: str, max_length: int = 100, suffix: str = "...") -> str:
    """Truncate text to maximum length."""
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix

def parse_user_agent(user_agent: str) -> Dict[str, str]:
    """Parse user agent string to extract browser and OS information."""
    if not user_agent:
        return {"browser": "unknown", "os": "unknown"}
    
    browser = "unknown"
    os = "unknown"
    
    # Simple browser detection
    if "Chrome" in user_agent:
        browser = "Chrome"
    elif "Firefox" in user_agent:
        browser = "Firefox"
    elif "Safari" in user_agent and "Chrome" not in user_agent:
        browser = "Safari"
    elif "Edge" in user_agent:
        browser = "Edge"
    
    # Simple OS detection
    if "Windows" in user_agent:
        os = "Windows"
    elif "Mac" in user_agent:
        os = "macOS"
    elif "Linux" in user_agent:
        os = "Linux"
    elif "Android" in user_agent:
        os = "Android"
    elif "iOS" in user_agent:
        os = "iOS"
    
    return {"browser": browser, "os": os}