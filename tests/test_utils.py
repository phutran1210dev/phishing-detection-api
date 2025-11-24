"""Test utility functions."""

import pytest
from app.utils.helpers import (
    normalize_url,
    extract_domain,
    is_valid_url,
    sanitize_input,
    calculate_similarity,
    validate_batch_request,
    mask_sensitive_data,
    truncate_text,
    parse_user_agent
)

class TestHelpers:
    """Test helper functions."""
    
    def test_normalize_url(self):
        """Test URL normalization."""
        # Test adding protocol
        assert normalize_url("www.example.com") == "https://www.example.com"
        assert normalize_url("example.com/path") == "https://example.com/path"
        
        # Test case normalization
        assert normalize_url("HTTPS://WWW.EXAMPLE.COM/PATH") == "https://www.example.com/PATH"
        
        # Test trailing slash removal
        assert normalize_url("https://example.com/") == "https://example.com"
        
        # Test with existing protocol
        assert normalize_url("http://example.com") == "http://example.com"
    
    def test_extract_domain(self):
        """Test domain extraction."""
        assert extract_domain("https://www.example.com/path") == "www.example.com"
        assert extract_domain("http://subdomain.example.com:8080/") == "subdomain.example.com:8080"
        assert extract_domain("invalid") == ""
    
    def test_is_valid_url(self):
        """Test URL validation."""
        # Valid URLs
        assert is_valid_url("https://www.example.com") == True
        assert is_valid_url("http://localhost:8080") == True
        assert is_valid_url("https://192.168.1.1") == True
        
        # Invalid URLs
        assert is_valid_url("not-a-url") == False
        assert is_valid_url("ftp://example.com") == False
        assert is_valid_url("") == False
    
    def test_sanitize_input(self):
        """Test input sanitization."""
        # Test removing dangerous characters
        assert sanitize_input('<script>alert("xss")</script>') == 'scriptalert(xss)/script'
        assert sanitize_input('normal text') == 'normal text'
        
        # Test length truncation
        long_text = "a" * 2000
        sanitized = sanitize_input(long_text, max_length=100)
        assert len(sanitized) == 100
    
    def test_calculate_similarity(self):
        """Test text similarity calculation."""
        # Identical texts
        assert calculate_similarity("hello world", "hello world") == 1.0
        
        # No similarity
        assert calculate_similarity("abc", "def") == 0.0
        
        # Partial similarity
        similarity = calculate_similarity("hello world", "hello there")
        assert 0.0 < similarity < 1.0
        
        # Empty texts
        assert calculate_similarity("", "anything") == 0.0
        assert calculate_similarity("", "") == 0.0
    
    def test_validate_batch_request(self):
        """Test batch request validation."""
        urls = [
            "https://www.google.com",
            "https://www.github.com",
            "invalid-url",
            "https://www.google.com",  # duplicate
            "https://www.stackoverflow.com"
        ]
        
        valid_urls = validate_batch_request(urls)
        
        # Should remove invalid and duplicate URLs
        assert len(valid_urls) == 3
        assert "invalid-url" not in valid_urls
        assert valid_urls.count("https://www.google.com") == 1
    
    def test_validate_batch_request_max_size(self):
        """Test batch request size limit."""
        urls = [f"https://example{i}.com" for i in range(150)]
        
        valid_urls = validate_batch_request(urls, max_size=100)
        assert len(valid_urls) == 100
    
    def test_mask_sensitive_data(self):
        """Test sensitive data masking."""
        text = "Contact john.doe@example.com or call 555-123-4567"
        masked = mask_sensitive_data(text)
        
        # Email should be masked
        assert "jo*******@example.com" in masked or "john.doe@example.com" not in masked
        
        # Phone should be masked  
        assert "555-123-4567" not in masked
    
    def test_truncate_text(self):
        """Test text truncation."""
        long_text = "This is a very long text that should be truncated"
        
        truncated = truncate_text(long_text, max_length=20)
        assert len(truncated) <= 20
        assert truncated.endswith("...")
        
        # Short text should not be truncated
        short_text = "Short"
        assert truncate_text(short_text, max_length=20) == short_text
    
    def test_parse_user_agent(self):
        """Test user agent parsing."""
        # Chrome on Windows
        chrome_ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        parsed = parse_user_agent(chrome_ua)
        assert parsed["browser"] == "Chrome"
        assert parsed["os"] == "Windows"
        
        # Firefox on Mac
        firefox_ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:89.0) Gecko/20100101 Firefox/89.0"
        parsed = parse_user_agent(firefox_ua)
        assert parsed["browser"] == "Firefox"
        assert parsed["os"] == "macOS"
        
        # Unknown user agent
        parsed = parse_user_agent("")
        assert parsed["browser"] == "unknown"
        assert parsed["os"] == "unknown"