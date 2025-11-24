"""Rate limiting utility for API endpoints."""

import time
from typing import Dict
from fastapi import HTTPException, Request
from collections import defaultdict, deque

from app.config import settings

class RateLimiter:
    """Simple in-memory rate limiter."""
    
    def __init__(self):
        self.requests: Dict[str, deque] = defaultdict(deque)
        self.cleanup_interval = 60  # Cleanup every minute
        self.last_cleanup = time.time()
    
    def is_allowed(self, client_ip: str) -> bool:
        """Check if client is allowed to make request."""
        current_time = time.time()
        
        # Cleanup old entries periodically
        if current_time - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries(current_time)
            self.last_cleanup = current_time
        
        # Get client's request history
        client_requests = self.requests[client_ip]
        
        # Remove requests older than 1 minute
        cutoff_time = current_time - 60
        while client_requests and client_requests[0] < cutoff_time:
            client_requests.popleft()
        
        # Check if under rate limit
        if len(client_requests) < settings.rate_limit_per_minute:
            client_requests.append(current_time)
            return True
        
        return False
    
    def _cleanup_old_entries(self, current_time: float):
        """Remove old entries to prevent memory leaks."""
        cutoff_time = current_time - 300  # Keep 5 minutes of history
        
        clients_to_remove = []
        for client_ip, requests in self.requests.items():
            # Remove old requests
            while requests and requests[0] < cutoff_time:
                requests.popleft()
            
            # Remove clients with no recent requests
            if not requests:
                clients_to_remove.append(client_ip)
        
        for client_ip in clients_to_remove:
            del self.requests[client_ip]

# Global rate limiter instance
rate_limiter = RateLimiter()

def get_client_ip(request: Request) -> str:
    """Extract client IP address from request."""
    # Check for forwarded headers first
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fallback to client host
    return request.client.host if request.client else "unknown"

async def rate_limit(request: Request):
    """Rate limiting dependency for FastAPI endpoints."""
    client_ip = get_client_ip(request)
    
    if not rate_limiter.is_allowed(client_ip):
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Maximum {settings.rate_limit_per_minute} requests per minute."
        )
    
    return None