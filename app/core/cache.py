"""Advanced caching system with Redis integration."""

import json
import pickle
import time
import hashlib
from typing import Any, Dict, List, Optional, Union, Callable
from datetime import datetime, timedelta
import asyncio
import aioredis
from loguru import logger
from functools import wraps
import inspect
from enum import Enum

class CacheStrategy(str, Enum):
    """Cache invalidation strategies."""
    TTL = "ttl"  # Time-based expiration
    LRU = "lru"  # Least Recently Used
    LFU = "lfu"  # Least Frequently Used
    WRITE_THROUGH = "write_through"  # Update cache and DB simultaneously
    WRITE_BACK = "write_back"  # Update cache first, DB later

class CacheManager:
    """Advanced Redis-based caching system."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379",
                 default_ttl: int = 3600, max_connections: int = 20):
        self.redis_url = redis_url
        self.default_ttl = default_ttl
        self.max_connections = max_connections
        self.redis_pool = None
        self.cache_stats = {
            "hits": 0,
            "misses": 0,
            "sets": 0,
            "deletes": 0,
            "errors": 0
        }
        
        logger.info(f"Cache manager initialized with TTL: {default_ttl}s")
    
    async def initialize(self):
        """Initialize Redis connection pool."""
        
        try:
            self.redis_pool = aioredis.ConnectionPool.from_url(
                self.redis_url,
                max_connections=self.max_connections,
                decode_responses=False,  # Handle binary data
                retry_on_timeout=True,
                health_check_interval=30
            )
            
            # Test connection
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            await redis.ping()
            
            logger.info("Redis connection pool initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize Redis: {e}")
            raise
    
    async def get(self, key: str, default: Any = None) -> Any:
        """Get value from cache."""
        
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            
            # Try to get from cache
            cached_data = await redis.get(self._make_key(key))
            
            if cached_data:
                self.cache_stats["hits"] += 1
                
                # Try to deserialize
                try:
                    return pickle.loads(cached_data)
                except Exception:
                    # Fallback to JSON
                    try:
                        return json.loads(cached_data.decode())
                    except Exception:
                        return cached_data.decode()
            
            self.cache_stats["misses"] += 1
            return default
            
        except Exception as e:
            logger.error(f"Cache get error for key {key}: {e}")
            self.cache_stats["errors"] += 1
            return default
    
    async def set(self, key: str, value: Any, ttl: Optional[int] = None,
                 strategy: CacheStrategy = CacheStrategy.TTL) -> bool:
        """Set value in cache with various strategies."""
        
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            
            # Serialize value
            try:
                serialized_value = pickle.dumps(value)
            except Exception:
                # Fallback to JSON
                try:
                    serialized_value = json.dumps(value).encode()
                except Exception:
                    serialized_value = str(value).encode()
            
            cache_key = self._make_key(key)
            actual_ttl = ttl or self.default_ttl
            
            # Apply caching strategy
            if strategy == CacheStrategy.TTL:
                await redis.setex(cache_key, actual_ttl, serialized_value)
            
            elif strategy == CacheStrategy.LRU:
                # Set with TTL and add to LRU tracking
                await redis.setex(cache_key, actual_ttl, serialized_value)
                await redis.zadd(f"{cache_key}:lru", {cache_key: time.time()})
            
            elif strategy == CacheStrategy.LFU:
                # Set with TTL and increment frequency counter
                await redis.setex(cache_key, actual_ttl, serialized_value)
                await redis.incr(f"{cache_key}:freq")
            
            self.cache_stats["sets"] += 1
            return True
            
        except Exception as e:
            logger.error(f"Cache set error for key {key}: {e}")
            self.cache_stats["errors"] += 1
            return False
    
    async def delete(self, key: str) -> bool:
        """Delete key from cache."""
        
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            
            cache_key = self._make_key(key)
            deleted = await redis.delete(cache_key)
            
            if deleted:
                self.cache_stats["deletes"] += 1
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Cache delete error for key {key}: {e}")
            self.cache_stats["errors"] += 1
            return False
    
    async def exists(self, key: str) -> bool:
        """Check if key exists in cache."""
        
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            return await redis.exists(self._make_key(key)) > 0
            
        except Exception as e:
            logger.error(f"Cache exists error for key {key}: {e}")
            return False
    
    async def clear_pattern(self, pattern: str) -> int:
        """Clear keys matching pattern."""
        
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            
            keys = await redis.keys(self._make_key(pattern))
            if keys:
                deleted = await redis.delete(*keys)
                self.cache_stats["deletes"] += deleted
                return deleted
            
            return 0
            
        except Exception as e:
            logger.error(f"Cache clear pattern error: {e}")
            return 0
    
    async def get_multiple(self, keys: List[str]) -> Dict[str, Any]:
        """Get multiple values from cache."""
        
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            
            cache_keys = [self._make_key(key) for key in keys]
            values = await redis.mget(cache_keys)
            
            result = {}
            for i, (original_key, value) in enumerate(zip(keys, values)):
                if value:
                    try:
                        result[original_key] = pickle.loads(value)
                        self.cache_stats["hits"] += 1
                    except Exception:
                        try:
                            result[original_key] = json.loads(value.decode())
                            self.cache_stats["hits"] += 1
                        except Exception:
                            result[original_key] = value.decode()
                            self.cache_stats["hits"] += 1
                else:
                    self.cache_stats["misses"] += 1
            
            return result
            
        except Exception as e:
            logger.error(f"Cache get multiple error: {e}")
            self.cache_stats["errors"] += 1
            return {}
    
    async def set_multiple(self, items: Dict[str, Any], ttl: Optional[int] = None) -> int:
        """Set multiple values in cache."""
        
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            
            pipe = redis.pipeline()
            actual_ttl = ttl or self.default_ttl
            
            for key, value in items.items():
                try:
                    serialized_value = pickle.dumps(value)
                except Exception:
                    try:
                        serialized_value = json.dumps(value).encode()
                    except Exception:
                        serialized_value = str(value).encode()
                
                cache_key = self._make_key(key)
                pipe.setex(cache_key, actual_ttl, serialized_value)
            
            await pipe.execute()
            self.cache_stats["sets"] += len(items)
            return len(items)
            
        except Exception as e:
            logger.error(f"Cache set multiple error: {e}")
            self.cache_stats["errors"] += 1
            return 0
    
    def _make_key(self, key: str) -> str:
        """Create namespaced cache key."""
        
        return f"phishing_api:cache:{key}"
    
    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        
        total_requests = self.cache_stats["hits"] + self.cache_stats["misses"]
        hit_rate = (self.cache_stats["hits"] / total_requests * 100) if total_requests > 0 else 0
        
        return {
            **self.cache_stats,
            "total_requests": total_requests,
            "hit_rate_percent": round(hit_rate, 2)
        }
    
    async def cleanup_expired(self):
        """Clean up expired cache entries (for strategies other than TTL)."""
        
        try:
            redis = aioredis.Redis(connection_pool=self.redis_pool)
            
            # Clean up LRU tracking
            lru_keys = await redis.keys(self._make_key("*:lru"))
            for lru_key in lru_keys:
                # Remove entries older than 24 hours from LRU tracking
                cutoff_time = time.time() - 86400
                await redis.zremrangebyscore(lru_key, 0, cutoff_time)
            
            # Clean up frequency counters
            freq_keys = await redis.keys(self._make_key("*:freq"))
            for freq_key in freq_keys:
                # Check if main key exists, if not delete frequency counter
                main_key = freq_key.replace(b":freq", b"")
                if not await redis.exists(main_key):
                    await redis.delete(freq_key)
            
            logger.info("Cache cleanup completed")
            
        except Exception as e:
            logger.error(f"Cache cleanup error: {e}")

class CacheDecorator:
    """Decorator for automatic function result caching."""
    
    def __init__(self, cache_manager: CacheManager,
                 ttl: Optional[int] = None,
                 key_prefix: str = "func_cache",
                 strategy: CacheStrategy = CacheStrategy.TTL):
        self.cache_manager = cache_manager
        self.ttl = ttl
        self.key_prefix = key_prefix
        self.strategy = strategy
    
    def __call__(self, func: Callable) -> Callable:
        """Cache decorator implementation."""
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Generate cache key from function signature
            cache_key = self._generate_cache_key(func, args, kwargs)
            
            # Try to get from cache
            cached_result = await self.cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function
            if inspect.iscoroutinefunction(func):
                result = await func(*args, **kwargs)
            else:
                result = func(*args, **kwargs)
            
            # Cache result
            await self.cache_manager.set(cache_key, result, self.ttl, self.strategy)
            
            return result
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            # For sync functions, use asyncio to handle cache operations
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(async_wrapper(*args, **kwargs))
        
        # Return appropriate wrapper based on function type
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    def _generate_cache_key(self, func: Callable, args: tuple, kwargs: dict) -> str:
        """Generate unique cache key for function call."""
        
        # Create signature string
        func_name = f"{func.__module__}.{func.__name__}"
        
        # Convert args and kwargs to strings
        args_str = str(args)
        kwargs_str = str(sorted(kwargs.items()))
        
        # Create hash of parameters
        param_hash = hashlib.md5(f"{args_str}:{kwargs_str}".encode()).hexdigest()[:8]
        
        return f"{self.key_prefix}:{func_name}:{param_hash}"

class ModelCache:
    """Specialized caching for ML models and predictions."""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
        self.model_cache_prefix = "models"
        self.prediction_cache_prefix = "predictions"
        self.feature_cache_prefix = "features"
    
    async def cache_model(self, model_id: str, model_data: Any, version: str = "latest"):
        """Cache trained model."""
        
        cache_key = f"{self.model_cache_prefix}:{model_id}:{version}"
        return await self.cache_manager.set(cache_key, model_data, ttl=86400)  # 24 hours
    
    async def get_cached_model(self, model_id: str, version: str = "latest") -> Any:
        """Get cached model."""
        
        cache_key = f"{self.model_cache_prefix}:{model_id}:{version}"
        return await self.cache_manager.get(cache_key)
    
    async def cache_prediction(self, input_hash: str, prediction: Dict[str, Any], 
                             model_version: str = "latest", ttl: int = 3600):
        """Cache prediction result."""
        
        cache_key = f"{self.prediction_cache_prefix}:{model_version}:{input_hash}"
        return await self.cache_manager.set(cache_key, prediction, ttl=ttl)
    
    async def get_cached_prediction(self, input_hash: str, 
                                  model_version: str = "latest") -> Optional[Dict[str, Any]]:
        """Get cached prediction."""
        
        cache_key = f"{self.prediction_cache_prefix}:{model_version}:{input_hash}"
        return await self.cache_manager.get(cache_key)
    
    async def cache_features(self, url_hash: str, features: Dict[str, Any], ttl: int = 7200):
        """Cache extracted features."""
        
        cache_key = f"{self.feature_cache_prefix}:{url_hash}"
        return await self.cache_manager.set(cache_key, features, ttl=ttl)
    
    async def get_cached_features(self, url_hash: str) -> Optional[Dict[str, Any]]:
        """Get cached features."""
        
        cache_key = f"{self.feature_cache_prefix}:{url_hash}"
        return await self.cache_manager.get(cache_key)
    
    def generate_input_hash(self, input_data: Union[str, Dict[str, Any]]) -> str:
        """Generate hash for input data."""
        
        if isinstance(input_data, str):
            content = input_data
        else:
            content = json.dumps(input_data, sort_keys=True)
        
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    async def invalidate_model_cache(self, model_id: str):
        """Invalidate all cache entries for a model."""
        
        await self.cache_manager.clear_pattern(f"{self.model_cache_prefix}:{model_id}:*")
        await self.cache_manager.clear_pattern(f"{self.prediction_cache_prefix}:*")
        
        logger.info(f"Cache invalidated for model: {model_id}")

class SessionCache:
    """Session-based caching for user data."""
    
    def __init__(self, cache_manager: CacheManager):
        self.cache_manager = cache_manager
        self.session_prefix = "sessions"
        self.user_cache_prefix = "users"
    
    async def create_session(self, session_id: str, user_data: Dict[str, Any], 
                           ttl: int = 3600) -> bool:
        """Create user session."""
        
        cache_key = f"{self.session_prefix}:{session_id}"
        return await self.cache_manager.set(cache_key, user_data, ttl=ttl)
    
    async def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data."""
        
        cache_key = f"{self.session_prefix}:{session_id}"
        return await self.cache_manager.get(cache_key)
    
    async def update_session(self, session_id: str, data: Dict[str, Any]) -> bool:
        """Update session data."""
        
        cache_key = f"{self.session_prefix}:{session_id}"
        
        # Get existing session
        existing_session = await self.get_session(session_id)
        if existing_session:
            existing_session.update(data)
            return await self.cache_manager.set(cache_key, existing_session)
        
        return False
    
    async def delete_session(self, session_id: str) -> bool:
        """Delete session."""
        
        cache_key = f"{self.session_prefix}:{session_id}"
        return await self.cache_manager.delete(cache_key)
    
    async def cache_user_data(self, user_id: str, user_data: Dict[str, Any], 
                            ttl: int = 7200) -> bool:
        """Cache user profile data."""
        
        cache_key = f"{self.user_cache_prefix}:{user_id}"
        return await self.cache_manager.set(cache_key, user_data, ttl=ttl)
    
    async def get_user_data(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get cached user data."""
        
        cache_key = f"{self.user_cache_prefix}:{user_id}"
        return await self.cache_manager.get(cache_key)

# Global cache manager instance
cache_manager = CacheManager()

# Convenience functions
async def cache_get(key: str, default: Any = None) -> Any:
    """Convenience function for cache get."""
    return await cache_manager.get(key, default)

async def cache_set(key: str, value: Any, ttl: Optional[int] = None) -> bool:
    """Convenience function for cache set."""
    return await cache_manager.set(key, value, ttl)

async def cache_delete(key: str) -> bool:
    """Convenience function for cache delete."""
    return await cache_manager.delete(key)

# Decorators
def cached(ttl: Optional[int] = None, key_prefix: str = "func_cache"):
    """Decorator for caching function results."""
    return CacheDecorator(cache_manager, ttl=ttl, key_prefix=key_prefix)