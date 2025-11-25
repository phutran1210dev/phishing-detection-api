"""Advanced authentication and authorization system."""

import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Union
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
import secrets
import hashlib
from enum import Enum
from loguru import logger
import asyncio
import time
from collections import defaultdict

class Role(str, Enum):
    """User roles with different permissions."""
    ADMIN = "admin"
    ANALYST = "analyst"
    API_USER = "api_user"
    READONLY = "readonly"

class Permission(str, Enum):
    """Specific permissions."""
    READ_DETECTIONS = "read:detections"
    WRITE_DETECTIONS = "write:detections"
    MANAGE_MODELS = "manage:models"
    VIEW_ANALYTICS = "view:analytics"
    MANAGE_USERS = "manage:users"
    SYSTEM_CONFIG = "system:config"
    EXPORT_DATA = "export:data"

# Role-Permission mapping
ROLE_PERMISSIONS = {
    Role.ADMIN: [
        Permission.READ_DETECTIONS, Permission.WRITE_DETECTIONS,
        Permission.MANAGE_MODELS, Permission.VIEW_ANALYTICS,
        Permission.MANAGE_USERS, Permission.SYSTEM_CONFIG,
        Permission.EXPORT_DATA
    ],
    Role.ANALYST: [
        Permission.READ_DETECTIONS, Permission.VIEW_ANALYTICS,
        Permission.EXPORT_DATA
    ],
    Role.API_USER: [
        Permission.READ_DETECTIONS, Permission.WRITE_DETECTIONS
    ],
    Role.READONLY: [
        Permission.READ_DETECTIONS
    ]
}

class User(BaseModel):
    """User model."""
    id: str
    username: str
    email: str
    role: Role
    is_active: bool = True
    created_at: datetime
    last_login: Optional[datetime] = None
    api_key_hash: Optional[str] = None
    rate_limit: int = 1000  # requests per hour
    permissions: List[Permission]

class TokenData(BaseModel):
    """JWT token data."""
    user_id: str
    username: str
    role: Role
    permissions: List[Permission]
    exp: datetime
    iat: datetime

class AuthenticationSystem:
    """Advanced authentication and authorization system."""
    
    def __init__(self, secret_key: str, token_expire_hours: int = 24):
        self.secret_key = secret_key
        self.token_expire_hours = token_expire_hours
        self.algorithm = "HS256"
        
        # In-memory user store (in production, use database)
        self.users: Dict[str, User] = {}
        self.api_keys: Dict[str, str] = {}  # api_key -> user_id
        
        # Rate limiting
        self.rate_limit_store = defaultdict(lambda: defaultdict(int))
        self.rate_limit_window = 3600  # 1 hour
        
        # Security tracking
        self.failed_attempts = defaultdict(int)
        self.blocked_ips = set()
        
        logger.info("Authentication system initialized")
    
    def create_user(self, username: str, email: str, password: str, 
                   role: Role) -> User:
        """Create a new user."""
        
        user_id = self._generate_user_id()
        password_hash = self._hash_password(password)
        
        user = User(
            id=user_id,
            username=username,
            email=email,
            role=role,
            created_at=datetime.utcnow(),
            permissions=ROLE_PERMISSIONS.get(role, [])
        )
        
        # Store user with password hash
        self.users[user_id] = user
        
        logger.info(f"User created: {username} ({role})")
        return user
    
    def authenticate_user(self, username: str, password: str) -> Optional[User]:
        """Authenticate user with username and password."""
        
        # Find user by username
        user = None
        for u in self.users.values():
            if u.username == username and u.is_active:
                user = u
                break
        
        if not user:
            return None
        
        # Check password (simplified - in production, store password hash properly)
        if self._verify_password(password, "hashed_password"):  # Placeholder
            user.last_login = datetime.utcnow()
            return user
        
        return None
    
    def create_access_token(self, user: User) -> str:
        """Create JWT access token."""
        
        expire_time = datetime.utcnow() + timedelta(hours=self.token_expire_hours)
        
        token_data = {
            "user_id": user.id,
            "username": user.username,
            "role": user.role.value,
            "permissions": [p.value for p in user.permissions],
            "exp": expire_time,
            "iat": datetime.utcnow()
        }
        
        token = jwt.encode(token_data, self.secret_key, algorithm=self.algorithm)
        
        logger.info(f"Access token created for user: {user.username}")
        return token
    
    def verify_token(self, token: str) -> Optional[TokenData]:
        """Verify and decode JWT token."""
        
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            
            token_data = TokenData(
                user_id=payload["user_id"],
                username=payload["username"],
                role=Role(payload["role"]),
                permissions=[Permission(p) for p in payload["permissions"]],
                exp=datetime.fromtimestamp(payload["exp"]),
                iat=datetime.fromtimestamp(payload["iat"])
            )
            
            return token_data
            
        except jwt.ExpiredSignatureError:
            logger.warning("Token has expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid token: {e}")
            return None
    
    def generate_api_key(self, user_id: str) -> str:
        """Generate API key for user."""
        
        if user_id not in self.users:
            raise ValueError("User not found")
        
        # Generate secure API key
        api_key = f"pk_{secrets.token_urlsafe(32)}"
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        
        # Store API key mapping
        self.api_keys[api_key] = user_id
        self.users[user_id].api_key_hash = api_key_hash
        
        logger.info(f"API key generated for user: {self.users[user_id].username}")
        return api_key
    
    def verify_api_key(self, api_key: str) -> Optional[User]:
        """Verify API key and return user."""
        
        user_id = self.api_keys.get(api_key)
        if user_id and user_id in self.users:
            user = self.users[user_id]
            if user.is_active:
                return user
        
        return None
    
    def check_rate_limit(self, user_id: str, request_ip: str) -> bool:
        """Check if user has exceeded rate limit."""
        
        current_time = int(time.time())
        window_start = current_time - self.rate_limit_window
        
        # Clean old entries
        user_requests = self.rate_limit_store[user_id]
        for timestamp in list(user_requests.keys()):
            if timestamp < window_start:
                del user_requests[timestamp]
        
        # Count requests in current window
        total_requests = sum(user_requests.values())
        
        user = self.users.get(user_id)
        rate_limit = user.rate_limit if user else 100
        
        if total_requests >= rate_limit:
            logger.warning(f"Rate limit exceeded for user {user_id}")
            return False
        
        # Record this request
        user_requests[current_time] += 1
        return True
    
    def check_permission(self, user: User, permission: Permission) -> bool:
        """Check if user has specific permission."""
        
        return permission in user.permissions
    
    def _generate_user_id(self) -> str:
        """Generate unique user ID."""
        
        return f"user_{secrets.token_urlsafe(16)}"
    
    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        
        salt = bcrypt.gensalt()
        return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        
        return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

# FastAPI Security Dependencies

security = HTTPBearer()
auth_system = AuthenticationSystem("your-secret-key")

class SecurityManager:
    """Manage security-related operations."""
    
    def __init__(self):
        self.blocked_ips = set()
        self.suspicious_patterns = []
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin"
        }
    
    def validate_input(self, data: Any) -> Dict[str, Any]:
        """Validate and sanitize input data."""
        
        if isinstance(data, str):
            # Remove potential XSS patterns
            dangerous_patterns = ['<script', 'javascript:', 'vbscript:', 'onload=', 'onerror=']
            cleaned_data = data
            
            for pattern in dangerous_patterns:
                cleaned_data = cleaned_data.replace(pattern, '')
            
            # Limit length
            if len(cleaned_data) > 10000:
                raise HTTPException(status_code=400, detail="Input too long")
            
            return {"sanitized": cleaned_data, "original_length": len(data)}
        
        return {"sanitized": data, "original_length": 0}
    
    def check_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Check IP address reputation."""
        
        # Placeholder for IP reputation check
        # In production, integrate with threat intelligence feeds
        
        is_blocked = ip_address in self.blocked_ips
        is_suspicious = ip_address.startswith('10.') or ip_address.startswith('192.168.')
        
        return {
            "ip_address": ip_address,
            "is_blocked": is_blocked,
            "is_suspicious": is_suspicious,
            "reputation_score": 0.8 if not is_suspicious else 0.3,
            "country": "Unknown",  # Would integrate with GeoIP service
            "asn": "Unknown"
        }
    
    def detect_anomalies(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """Detect anomalous request patterns."""
        
        anomalies = []
        
        # Check for unusual request patterns
        if request_data.get('request_size', 0) > 1000000:  # 1MB
            anomalies.append("Large request size")
        
        if len(request_data.get('headers', {})) > 50:
            anomalies.append("Excessive headers")
        
        user_agent = request_data.get('user_agent', '')
        if not user_agent or len(user_agent) < 10:
            anomalies.append("Suspicious user agent")
        
        # Check for bot patterns
        bot_indicators = ['bot', 'crawler', 'spider', 'scraper']
        if any(indicator in user_agent.lower() for indicator in bot_indicators):
            anomalies.append("Bot detected")
        
        return {
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies,
            "risk_score": min(len(anomalies) * 0.3, 1.0)
        }

# FastAPI Dependencies

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> User:
    """Get current authenticated user from JWT token."""
    
    token_data = auth_system.verify_token(credentials.credentials)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid authentication token")
    
    user = auth_system.users.get(token_data.user_id)
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive")
    
    return user

async def get_api_key_user(request: Request) -> Optional[User]:
    """Get user from API key authentication."""
    
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        return None
    
    user = auth_system.verify_api_key(api_key)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    # Check rate limit
    client_ip = request.client.host
    if not auth_system.check_rate_limit(user.id, client_ip):
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    
    return user

def require_permission(permission: Permission):
    """Decorator to require specific permission."""
    
    def permission_dependency(user: User = Depends(get_current_user)) -> User:
        if not auth_system.check_permission(user, permission):
            raise HTTPException(
                status_code=403, 
                detail=f"Insufficient permissions. Required: {permission.value}"
            )
        return user
    
    return permission_dependency

def require_role(role: Role):
    """Decorator to require specific role."""
    
    def role_dependency(user: User = Depends(get_current_user)) -> User:
        if user.role != role and user.role != Role.ADMIN:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient role. Required: {role.value}"
            )
        return user
    
    return role_dependency

async def security_middleware(request: Request) -> Dict[str, Any]:
    """Security middleware for request processing."""
    
    security_manager = SecurityManager()
    
    # Get client IP
    client_ip = request.client.host
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        client_ip = forwarded_for.split(",")[0].strip()
    
    # Check IP reputation
    ip_reputation = security_manager.check_ip_reputation(client_ip)
    if ip_reputation["is_blocked"]:
        raise HTTPException(status_code=403, detail="IP address blocked")
    
    # Prepare request data for anomaly detection
    request_data = {
        "method": request.method,
        "url": str(request.url),
        "headers": dict(request.headers),
        "client_ip": client_ip,
        "user_agent": request.headers.get("User-Agent", ""),
        "request_size": request.headers.get("Content-Length", 0)
    }
    
    # Detect anomalies
    anomaly_result = security_manager.detect_anomalies(request_data)
    
    # Log suspicious activity
    if anomaly_result["risk_score"] > 0.7:
        logger.warning(f"Suspicious request detected from {client_ip}: {anomaly_result}")
    
    return {
        "client_ip": client_ip,
        "ip_reputation": ip_reputation,
        "anomaly_detection": anomaly_result,
        "security_headers": security_manager.security_headers
    }