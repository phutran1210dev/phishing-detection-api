"""Advanced input validation and sanitization."""

import re
import html
import urllib.parse
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, validator, Field
from fastapi import HTTPException
from loguru import logger
import hashlib
import secrets

class URLValidation(BaseModel):
    """URL validation model."""
    
    url: str = Field(..., min_length=1, max_length=2048)
    
    @validator('url')
    def validate_url(cls, v):
        # Basic URL pattern validation
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        
        if not url_pattern.match(v):
            raise ValueError('Invalid URL format')
        
        # Check for dangerous protocols
        dangerous_schemes = ['javascript:', 'vbscript:', 'data:', 'file:']
        if any(v.lower().startswith(scheme) for scheme in dangerous_schemes):
            raise ValueError('Dangerous URL scheme detected')
        
        # Check URL length
        if len(v) > 2048:
            raise ValueError('URL too long')
        
        return v

class TextValidation(BaseModel):
    """Text content validation model."""
    
    content: str = Field(..., max_length=100000)
    
    @validator('content')
    def validate_content(cls, v):
        # Check for potential XSS patterns
        xss_patterns = [
            r'<script.*?>.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=',
            r'<iframe.*?>',
            r'<object.*?>',
            r'<embed.*?>',
            r'<link.*?>',
            r'<meta.*?>'
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, v, re.IGNORECASE | re.DOTALL):
                raise ValueError(f'Potentially dangerous content detected: {pattern}')
        
        return v

class EmailValidation(BaseModel):
    """Email validation model."""
    
    email: str = Field(..., max_length=254)
    
    @validator('email')
    def validate_email(cls, v):
        email_pattern = re.compile(
            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        )
        
        if not email_pattern.match(v):
            raise ValueError('Invalid email format')
        
        return v.lower()

class IPValidation(BaseModel):
    """IP address validation model."""
    
    ip: str = Field(..., max_length=45)
    
    @validator('ip')
    def validate_ip(cls, v):
        # IPv4 pattern
        ipv4_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        
        # IPv6 pattern (simplified)
        ipv6_pattern = re.compile(
            r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$'
        )
        
        if not (ipv4_pattern.match(v) or ipv6_pattern.match(v)):
            raise ValueError('Invalid IP address format')
        
        return v

class PhishingDetectionRequest(BaseModel):
    """Complete phishing detection request validation."""
    
    url: Optional[str] = None
    content: Optional[str] = None
    email: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    additional_features: Optional[Dict[str, Any]] = None
    
    @validator('url')
    def validate_url(cls, v):
        if v:
            return URLValidation(url=v).url
        return v
    
    @validator('content')
    def validate_content(cls, v):
        if v:
            return TextValidation(content=v).content
        return v
    
    @validator('email')
    def validate_email(cls, v):
        if v:
            return EmailValidation(email=v).email
        return v
    
    @validator('source_ip')
    def validate_source_ip(cls, v):
        if v:
            return IPValidation(ip=v).ip
        return v
    
    @validator('user_agent')
    def validate_user_agent(cls, v):
        if v and len(v) > 1000:
            raise ValueError('User agent string too long')
        return v
    
    @validator('additional_features')
    def validate_additional_features(cls, v):
        if v and len(str(v)) > 50000:
            raise ValueError('Additional features payload too large')
        return v

class InputSanitizer:
    """Advanced input sanitization utilities."""
    
    def __init__(self):
        self.html_escape_table = {
            "&": "&amp;",
            '"': "&quot;",
            "'": "&#x27;",
            ">": "&gt;",
            "<": "&lt;",
        }
        
        # Dangerous patterns to remove
        self.dangerous_patterns = [
            r'<script.*?</script>',
            r'javascript:',
            r'vbscript:',
            r'on\w+\s*=.*?["\'].*?["\']',
            r'<iframe.*?>.*?</iframe>',
            r'<object.*?>.*?</object>',
            r'<embed.*?>',
            r'<link.*?>',
            r'<meta.*?>'
        ]
    
    def sanitize_html(self, text: str) -> str:
        """Sanitize HTML content."""
        
        if not text:
            return ""
        
        # HTML escape
        sanitized = html.escape(text)
        
        # Remove dangerous patterns
        for pattern in self.dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        return sanitized.strip()
    
    def sanitize_url(self, url: str) -> str:
        """Sanitize URL."""
        
        if not url:
            return ""
        
        # URL decode first
        try:
            decoded_url = urllib.parse.unquote(url)
        except Exception:
            decoded_url = url
        
        # Parse URL components
        try:
            parsed = urllib.parse.urlparse(decoded_url)
            
            # Validate scheme
            if parsed.scheme.lower() not in ['http', 'https']:
                raise ValueError("Invalid URL scheme")
            
            # Rebuild clean URL
            clean_url = urllib.parse.urlunparse((
                parsed.scheme.lower(),
                parsed.netloc.lower(),
                parsed.path,
                parsed.params,
                parsed.query,
                ''  # Remove fragment for security
            ))
            
            return clean_url
            
        except Exception as e:
            logger.warning(f"URL sanitization failed: {e}")
            raise ValueError("Invalid URL format")
    
    def sanitize_text(self, text: str, max_length: int = 10000) -> str:
        """Sanitize general text input."""
        
        if not text:
            return ""
        
        # Truncate if too long
        if len(text) > max_length:
            text = text[:max_length]
        
        # Remove control characters
        sanitized = ''.join(char for char in text if ord(char) >= 32 or char in '\t\n\r')
        
        # Remove potential XSS patterns
        for pattern in self.dangerous_patterns:
            sanitized = re.sub(pattern, '', sanitized, flags=re.IGNORECASE | re.DOTALL)
        
        return sanitized.strip()
    
    def validate_file_upload(self, filename: str, content_type: str, 
                           file_size: int) -> Dict[str, Any]:
        """Validate file upload."""
        
        # Allowed file types
        allowed_types = {
            'text/plain': ['.txt', '.log'],
            'text/csv': ['.csv'],
            'application/json': ['.json'],
            'text/html': ['.html', '.htm'],
            'application/pdf': ['.pdf']
        }
        
        # Check file size (max 10MB)
        max_size = 10 * 1024 * 1024
        if file_size > max_size:
            raise ValueError("File too large")
        
        # Validate filename
        safe_filename = self._sanitize_filename(filename)
        
        # Check content type
        if content_type not in allowed_types:
            raise ValueError("File type not allowed")
        
        # Check file extension
        file_ext = '.' + safe_filename.split('.')[-1].lower()
        if file_ext not in allowed_types[content_type]:
            raise ValueError("File extension doesn't match content type")
        
        return {
            "safe_filename": safe_filename,
            "content_type": content_type,
            "file_size": file_size,
            "is_valid": True
        }
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe storage."""
        
        if not filename:
            return f"upload_{secrets.token_hex(8)}"
        
        # Remove path traversal attempts
        filename = filename.replace('..', '').replace('/', '').replace('\\', '')
        
        # Remove dangerous characters
        safe_chars = re.sub(r'[^\w\-_\.]', '', filename)
        
        # Ensure reasonable length
        if len(safe_chars) > 100:
            name_part = safe_chars[:80]
            ext_part = safe_chars[-15:] if '.' in safe_chars[-15:] else ''
            safe_chars = name_part + ext_part
        
        # Add timestamp if filename is empty
        if not safe_chars or safe_chars == '.':
            safe_chars = f"upload_{secrets.token_hex(8)}.txt"
        
        return safe_chars

class SecurityValidator:
    """Security-focused validation utilities."""
    
    def __init__(self):
        self.sanitizer = InputSanitizer()
    
    def validate_request_size(self, content_length: int, max_size: int = 1048576) -> bool:
        """Validate request size (default 1MB)."""
        
        return content_length <= max_size
    
    def validate_request_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Validate HTTP headers for security issues."""
        
        issues = []
        
        # Check for suspicious headers
        suspicious_headers = [
            'x-forwarded-proto', 'x-forwarded-host', 'x-real-ip',
            'x-cluster-client-ip', 'cf-connecting-ip'
        ]
        
        for header in suspicious_headers:
            if header in headers:
                issues.append(f"Proxy header present: {header}")
        
        # Check User-Agent
        user_agent = headers.get('user-agent', '')
        if not user_agent:
            issues.append("Missing User-Agent header")
        elif len(user_agent) > 1000:
            issues.append("User-Agent header too long")
        
        # Check for potential bot signatures
        bot_signatures = ['bot', 'crawler', 'spider', 'scraper']
        if any(sig in user_agent.lower() for sig in bot_signatures):
            issues.append("Bot signature detected in User-Agent")
        
        return {
            "issues": issues,
            "risk_score": min(len(issues) * 0.2, 1.0),
            "is_suspicious": len(issues) > 2
        }
    
    def detect_injection_attempts(self, input_data: str) -> Dict[str, Any]:
        """Detect potential injection attempts."""
        
        injection_patterns = {
            'sql_injection': [
                r"(\bUNION\b.*\bSELECT\b)",
                r"(\bSELECT\b.*\bFROM\b)",
                r"(\bINSERT\b.*\bINTO\b)",
                r"(\bDELETE\b.*\bFROM\b)",
                r"(\bDROP\b.*\bTABLE\b)",
                r"(--|\#|\/\*|\*\/)",
                r"(\b(OR|AND)\b\s+\d+\s*=\s*\d+)"
            ],
            'xss_injection': [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"vbscript:",
                r"on\w+\s*=",
                r"<iframe[^>]*>",
                r"<object[^>]*>",
                r"<embed[^>]*>"
            ],
            'command_injection': [
                r"(;|\||\||&|&&|\$\(|\`)",
                r"(rm\s+|del\s+|format\s+)",
                r"(cat\s+|type\s+|more\s+)",
                r"(wget\s+|curl\s+|nc\s+)"
            ]
        }
        
        detected_patterns = {}
        total_matches = 0
        
        for injection_type, patterns in injection_patterns.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, input_data, re.IGNORECASE):
                    matches.append(pattern)
            
            detected_patterns[injection_type] = matches
            total_matches += len(matches)
        
        return {
            "detected_patterns": detected_patterns,
            "total_matches": total_matches,
            "risk_score": min(total_matches * 0.3, 1.0),
            "is_malicious": total_matches > 0
        }
    
    def generate_request_signature(self, request_data: Dict[str, Any]) -> str:
        """Generate unique signature for request."""
        
        signature_data = {
            "method": request_data.get("method", ""),
            "path": request_data.get("path", ""),
            "user_agent": request_data.get("user_agent", ""),
            "content_type": request_data.get("content_type", ""),
            "content_length": request_data.get("content_length", 0)
        }
        
        signature_str = "|".join(str(v) for v in signature_data.values())
        return hashlib.sha256(signature_str.encode()).hexdigest()[:16]

# Global instances
input_sanitizer = InputSanitizer()
security_validator = SecurityValidator()

def validate_and_sanitize(data: Any, data_type: str = "text") -> Dict[str, Any]:
    """Main validation and sanitization function."""
    
    try:
        if data_type == "url":
            sanitized = input_sanitizer.sanitize_url(str(data))
            validation = URLValidation(url=sanitized)
            return {"sanitized": validation.url, "is_valid": True, "errors": []}
        
        elif data_type == "text":
            sanitized = input_sanitizer.sanitize_text(str(data))
            validation = TextValidation(content=sanitized)
            return {"sanitized": validation.content, "is_valid": True, "errors": []}
        
        elif data_type == "email":
            sanitized = str(data).strip().lower()
            validation = EmailValidation(email=sanitized)
            return {"sanitized": validation.email, "is_valid": True, "errors": []}
        
        elif data_type == "ip":
            sanitized = str(data).strip()
            validation = IPValidation(ip=sanitized)
            return {"sanitized": validation.ip, "is_valid": True, "errors": []}
        
        else:
            # Default text sanitization
            sanitized = input_sanitizer.sanitize_text(str(data))
            return {"sanitized": sanitized, "is_valid": True, "errors": []}
    
    except ValueError as e:
        return {"sanitized": "", "is_valid": False, "errors": [str(e)]}
    
    except Exception as e:
        logger.error(f"Validation error: {e}")
        return {"sanitized": "", "is_valid": False, "errors": ["Validation failed"]}