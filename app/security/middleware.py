"""Security middleware and headers management."""

import time
import json
from typing import Dict, Any, Optional, List
from fastapi import Request, Response, HTTPException
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import RequestResponseEndpoint
from loguru import logger
import asyncio
from collections import defaultdict, deque
import hashlib
import ipaddress

class SecurityHeaders:
    """Manage security headers for responses."""
    
    @staticmethod
    def get_security_headers() -> Dict[str, str]:
        """Get comprehensive security headers."""
        
        return {
            # Prevent MIME type sniffing
            "X-Content-Type-Options": "nosniff",
            
            # Prevent clickjacking
            "X-Frame-Options": "DENY",
            
            # XSS protection
            "X-XSS-Protection": "1; mode=block",
            
            # Force HTTPS
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            
            # Content Security Policy
            "Content-Security-Policy": (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data: https:; "
                "font-src 'self'; "
                "connect-src 'self'; "
                "frame-ancestors 'none'; "
                "object-src 'none'; "
                "base-uri 'self'"
            ),
            
            # Referrer policy
            "Referrer-Policy": "strict-origin-when-cross-origin",
            
            # Permission policy
            "Permissions-Policy": (
                "geolocation=(), microphone=(), camera=(), "
                "payment=(), usb=(), magnetometer=(), gyroscope=()"
            ),
            
            # Cross-Origin policies
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            
            # Cache control
            "Cache-Control": "no-store, no-cache, must-revalidate, private",
            "Pragma": "no-cache",
            "Expires": "0"
        }

class RateLimiter:
    """Advanced rate limiting with multiple strategies."""
    
    def __init__(self):
        self.requests = defaultdict(deque)  # IP -> timestamps
        self.blocked_ips = set()
        self.whitelist = set()
        
        # Rate limiting rules
        self.rules = {
            "per_minute": {"limit": 60, "window": 60},
            "per_hour": {"limit": 1000, "window": 3600},
            "per_day": {"limit": 10000, "window": 86400}
        }
        
        # Burst protection
        self.burst_threshold = 10  # requests per second
        self.burst_window = 1
        
        logger.info("Rate limiter initialized")
    
    def is_allowed(self, client_ip: str, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Check if request is allowed based on rate limits."""
        
        current_time = time.time()
        
        # Check if IP is blocked
        if client_ip in self.blocked_ips:
            return {
                "allowed": False,
                "reason": "IP blocked",
                "retry_after": 3600
            }
        
        # Check whitelist
        if client_ip in self.whitelist:
            return {"allowed": True, "reason": "Whitelisted"}
        
        # Get request history for this IP
        ip_requests = self.requests[client_ip]
        
        # Clean old requests
        self._clean_old_requests(ip_requests, current_time)
        
        # Check burst protection
        burst_count = sum(1 for ts in ip_requests if current_time - ts <= self.burst_window)
        if burst_count >= self.burst_threshold:
            logger.warning(f"Burst limit exceeded for IP: {client_ip}")
            return {
                "allowed": False,
                "reason": "Burst limit exceeded",
                "retry_after": self.burst_window
            }
        
        # Check rate limiting rules
        for rule_name, rule in self.rules.items():
            window_start = current_time - rule["window"]
            requests_in_window = sum(1 for ts in ip_requests if ts >= window_start)
            
            if requests_in_window >= rule["limit"]:
                logger.warning(f"Rate limit exceeded for IP {client_ip}: {rule_name}")
                return {
                    "allowed": False,
                    "reason": f"Rate limit exceeded: {rule_name}",
                    "retry_after": rule["window"]
                }
        
        # Record this request
        ip_requests.append(current_time)
        
        return {"allowed": True, "reason": "Within limits"}
    
    def _clean_old_requests(self, request_queue: deque, current_time: float):
        """Remove old requests outside all windows."""
        
        max_window = max(rule["window"] for rule in self.rules.values())
        cutoff_time = current_time - max_window
        
        while request_queue and request_queue[0] < cutoff_time:
            request_queue.popleft()
    
    def block_ip(self, ip: str, duration: int = 3600):
        """Block IP address for specified duration."""
        
        self.blocked_ips.add(ip)
        
        # Schedule unblocking
        async def unblock_later():
            await asyncio.sleep(duration)
            self.blocked_ips.discard(ip)
            logger.info(f"IP {ip} unblocked after {duration} seconds")
        
        asyncio.create_task(unblock_later())
        logger.warning(f"IP {ip} blocked for {duration} seconds")
    
    def add_to_whitelist(self, ip: str):
        """Add IP to whitelist."""
        
        self.whitelist.add(ip)
        logger.info(f"IP {ip} added to whitelist")

class ThreatDetector:
    """Detect various security threats."""
    
    def __init__(self):
        self.suspicious_user_agents = [
            'sqlmap', 'nikto', 'burpsuite', 'nessus', 'nmap',
            'masscan', 'zap', 'acunetix', 'havij', 'pangolin'
        ]
        
        self.malicious_patterns = [
            # SQL Injection patterns
            r"(\bunion\b.*\bselect\b)",
            r"(\bor\b\s+\d+\s*=\s*\d+)",
            r"(\band\b\s+\d+\s*=\s*\d+)",
            
            # XSS patterns
            r"<script[^>]*>",
            r"javascript:",
            r"vbscript:",
            
            # Command injection
            r"(\||&|;|\$\(|\`)",
            r"(rm\s|del\s|format\s)",
            
            # Path traversal
            r"(\.\./|\.\.\\)",
            r"(/etc/passwd|/windows/system32)",
        ]
        
        # Track suspicious behavior
        self.suspicious_activity = defaultdict(list)
        
    def analyze_request(self, request: Request, 
                       request_body: Optional[str] = None) -> Dict[str, Any]:
        """Analyze request for security threats."""
        
        threats = []
        risk_score = 0.0
        
        # Get client info
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "").lower()
        
        # Check User-Agent
        if any(suspicious in user_agent for suspicious in self.suspicious_user_agents):
            threats.append("Suspicious user agent detected")
            risk_score += 0.8
        
        # Check for empty or missing User-Agent
        if not user_agent:
            threats.append("Missing user agent")
            risk_score += 0.3
        
        # Analyze URL and query parameters
        url_analysis = self._analyze_url(str(request.url))
        if url_analysis["is_suspicious"]:
            threats.extend(url_analysis["threats"])
            risk_score += url_analysis["risk_score"]
        
        # Analyze request body if provided
        if request_body:
            body_analysis = self._analyze_request_body(request_body)
            if body_analysis["is_suspicious"]:
                threats.extend(body_analysis["threats"])
                risk_score += body_analysis["risk_score"]
        
        # Check headers
        header_analysis = self._analyze_headers(dict(request.headers))
        if header_analysis["is_suspicious"]:
            threats.extend(header_analysis["threats"])
            risk_score += header_analysis["risk_score"]
        
        # Geographic analysis
        geo_analysis = self._analyze_geographic_risk(client_ip)
        if geo_analysis["is_high_risk"]:
            threats.extend(geo_analysis["threats"])
            risk_score += geo_analysis["risk_score"]
        
        # Normalize risk score
        risk_score = min(risk_score, 1.0)
        
        # Store suspicious activity
        if risk_score > 0.5:
            self.suspicious_activity[client_ip].append({
                "timestamp": time.time(),
                "threats": threats,
                "risk_score": risk_score,
                "url": str(request.url),
                "user_agent": user_agent
            })
        
        return {
            "client_ip": client_ip,
            "threats": threats,
            "risk_score": risk_score,
            "is_suspicious": risk_score > 0.3,
            "is_high_risk": risk_score > 0.7
        }
    
    def _get_client_ip(self, request: Request) -> str:
        """Get real client IP address."""
        
        # Check X-Forwarded-For header
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
        
        # Check CF-Connecting-IP (Cloudflare)
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip.strip()
        
        # Fall back to direct client IP
        return request.client.host
    
    def _analyze_url(self, url: str) -> Dict[str, Any]:
        """Analyze URL for suspicious patterns."""
        
        threats = []
        risk_score = 0.0
        
        # Check for malicious patterns
        for pattern in self.malicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                threats.append(f"Malicious pattern in URL: {pattern}")
                risk_score += 0.4
        
        # Check URL length
        if len(url) > 2048:
            threats.append("Unusually long URL")
            risk_score += 0.2
        
        # Check for suspicious parameters
        suspicious_params = ['cmd', 'exec', 'system', 'shell', 'file', 'path']
        if any(param in url.lower() for param in suspicious_params):
            threats.append("Suspicious parameters in URL")
            risk_score += 0.3
        
        return {
            "threats": threats,
            "risk_score": min(risk_score, 1.0),
            "is_suspicious": len(threats) > 0
        }
    
    def _analyze_request_body(self, body: str) -> Dict[str, Any]:
        """Analyze request body for threats."""
        
        threats = []
        risk_score = 0.0
        
        # Check body size
        if len(body) > 1000000:  # 1MB
            threats.append("Large request body")
            risk_score += 0.3
        
        # Check for malicious patterns
        for pattern in self.malicious_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                threats.append(f"Malicious pattern in body: {pattern}")
                risk_score += 0.5
        
        return {
            "threats": threats,
            "risk_score": min(risk_score, 1.0),
            "is_suspicious": len(threats) > 0
        }
    
    def _analyze_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """Analyze HTTP headers for threats."""
        
        threats = []
        risk_score = 0.0
        
        # Check for proxy headers (potential IP spoofing)
        proxy_headers = ['x-forwarded-for', 'x-real-ip', 'x-originating-ip']
        proxy_count = sum(1 for header in proxy_headers if header in headers)
        
        if proxy_count > 1:
            threats.append("Multiple proxy headers detected")
            risk_score += 0.2
        
        # Check for unusual headers
        unusual_headers = ['x-cluster-client-ip', 'x-forwarded-proto', 'x-forwarded-host']
        for header in unusual_headers:
            if header in headers:
                threats.append(f"Unusual header: {header}")
                risk_score += 0.1
        
        return {
            "threats": threats,
            "risk_score": min(risk_score, 1.0),
            "is_suspicious": len(threats) > 0
        }
    
    def _analyze_geographic_risk(self, ip: str) -> Dict[str, Any]:
        """Analyze geographic risk based on IP."""
        
        threats = []
        risk_score = 0.0
        
        try:
            # Check if IP is private
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                return {"threats": [], "risk_score": 0.0, "is_high_risk": False}
            
            # In production, integrate with GeoIP service
            # For now, just check for localhost and private ranges
            
        except ValueError:
            threats.append("Invalid IP address")
            risk_score += 0.2
        
        return {
            "threats": threats,
            "risk_score": min(risk_score, 1.0),
            "is_high_risk": risk_score > 0.5
        }

class SecurityMiddleware(BaseHTTPMiddleware):
    """Comprehensive security middleware."""
    
    def __init__(self, app, enable_rate_limiting: bool = True,
                 enable_threat_detection: bool = True):
        super().__init__(app)
        self.rate_limiter = RateLimiter() if enable_rate_limiting else None
        self.threat_detector = ThreatDetector() if enable_threat_detection else None
        self.security_headers = SecurityHeaders()
        
        logger.info("Security middleware initialized")
    
    async def dispatch(self, request: Request, 
                      call_next: RequestResponseEndpoint) -> Response:
        """Main security middleware logic."""
        
        start_time = time.time()
        
        try:
            # Get client IP
            client_ip = self._get_client_ip(request)
            
            # Rate limiting
            if self.rate_limiter:
                rate_limit_result = self.rate_limiter.is_allowed(client_ip)
                if not rate_limit_result["allowed"]:
                    return JSONResponse(
                        status_code=429,
                        content={
                            "error": "Rate limit exceeded",
                            "reason": rate_limit_result["reason"],
                            "retry_after": rate_limit_result.get("retry_after", 60)
                        },
                        headers=self.security_headers.get_security_headers()
                    )
            
            # Request size validation
            content_length = request.headers.get("content-length")
            if content_length:
                try:
                    size = int(content_length)
                    if size > 10 * 1024 * 1024:  # 10MB
                        return JSONResponse(
                            status_code=413,
                            content={"error": "Request too large"},
                            headers=self.security_headers.get_security_headers()
                        )
                except ValueError:
                    pass
            
            # Read request body for threat analysis
            request_body = None
            if request.method in ["POST", "PUT", "PATCH"]:
                try:
                    body = await request.body()
                    request_body = body.decode() if body else None
                    
                    # Recreate request with body
                    async def receive():
                        return {"type": "http.request", "body": body, "more_body": False}
                    
                    request._receive = receive
                    
                except Exception as e:
                    logger.warning(f"Could not read request body: {e}")
            
            # Threat detection
            if self.threat_detector:
                threat_analysis = self.threat_detector.analyze_request(
                    request, request_body
                )
                
                # Block high-risk requests
                if threat_analysis["is_high_risk"]:
                    logger.warning(
                        f"High-risk request blocked from {client_ip}: "
                        f"{threat_analysis['threats']}"
                    )
                    
                    # Auto-block IP if very suspicious
                    if threat_analysis["risk_score"] > 0.9 and self.rate_limiter:
                        self.rate_limiter.block_ip(client_ip, 7200)  # 2 hours
                    
                    return JSONResponse(
                        status_code=403,
                        content={
                            "error": "Request blocked by security system",
                            "threats_detected": len(threat_analysis["threats"])
                        },
                        headers=self.security_headers.get_security_headers()
                    )
                
                # Add threat info to request state
                request.state.threat_analysis = threat_analysis
            
            # Process request
            response = await call_next(request)
            
            # Add security headers
            for header, value in self.security_headers.get_security_headers().items():
                response.headers[header] = value
            
            # Add request processing time
            process_time = time.time() - start_time
            response.headers["X-Process-Time"] = str(process_time)
            
            # Log request
            self._log_request(request, response, process_time, client_ip)
            
            return response
            
        except Exception as e:
            logger.error(f"Security middleware error: {e}")
            
            # Return secure error response
            return JSONResponse(
                status_code=500,
                content={"error": "Internal server error"},
                headers=self.security_headers.get_security_headers()
            )
    
    def _get_client_ip(self, request: Request) -> str:
        """Get real client IP address."""
        
        # Same as ThreatDetector._get_client_ip
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
        
        cf_ip = request.headers.get("cf-connecting-ip")
        if cf_ip:
            return cf_ip.strip()
        
        return request.client.host
    
    def _log_request(self, request: Request, response: Response,
                    process_time: float, client_ip: str):
        """Log request for security monitoring."""
        
        log_data = {
            "timestamp": time.time(),
            "client_ip": client_ip,
            "method": request.method,
            "url": str(request.url),
            "user_agent": request.headers.get("user-agent", ""),
            "status_code": response.status_code,
            "process_time": process_time,
            "content_length": response.headers.get("content-length", 0)
        }
        
        # Add threat analysis if available
        if hasattr(request.state, 'threat_analysis'):
            log_data["threat_analysis"] = request.state.threat_analysis
        
        # Log based on status code
        if response.status_code >= 400:
            logger.warning(f"HTTP {response.status_code}: {json.dumps(log_data)}")
        elif hasattr(request.state, 'threat_analysis'):
            if request.state.threat_analysis["is_suspicious"]:
                logger.info(f"Suspicious request: {json.dumps(log_data)}")
        
        # Log slow requests
        if process_time > 5.0:
            logger.warning(f"Slow request ({process_time:.2f}s): {json.dumps(log_data)}")

# Utility functions for CORS and other security features

def get_cors_settings() -> Dict[str, Any]:
    """Get CORS configuration."""
    
    return {
        "allow_origins": ["https://yourdomain.com"],  # Configure for production
        "allow_credentials": True,
        "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        "allow_headers": [
            "Authorization",
            "Content-Type",
            "X-API-Key",
            "X-Requested-With",
            "Accept",
            "Origin",
            "User-Agent"
        ],
        "expose_headers": [
            "X-Process-Time",
            "X-RateLimit-Remaining",
            "X-RateLimit-Reset"
        ]
    }

import re