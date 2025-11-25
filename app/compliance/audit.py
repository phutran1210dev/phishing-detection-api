"""Comprehensive audit logging system for compliance and security monitoring."""

import json
import asyncio
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from enum import Enum
from pydantic import BaseModel, Field
from loguru import logger
import hashlib
import uuid
from contextlib import asynccontextmanager
from app.core.database import DatabaseOptimizer
from app.core.cache import CacheManager
import inspect
from functools import wraps

class AuditLevel(str, Enum):
    """Audit log levels."""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"
    DEBUG = "debug"

class AuditCategory(str, Enum):
    """Audit event categories."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    DATA_ACCESS = "data_access"
    DATA_MODIFICATION = "data_modification"
    SYSTEM_CONFIG = "system_config"
    ML_MODEL = "ml_model"
    THREAT_DETECTION = "threat_detection"
    USER_ACTIVITY = "user_activity"
    API_ACCESS = "api_access"
    FILE_OPERATION = "file_operation"
    COMPLIANCE = "compliance"

class AuditEvent(BaseModel):
    """Audit event model."""
    
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    level: AuditLevel = Field(..., description="Audit level")
    category: AuditCategory = Field(..., description="Event category")
    
    # Event details
    event_type: str = Field(..., description="Specific event type")
    description: str = Field(..., description="Human-readable description")
    
    # Actor information
    user_id: Optional[str] = None
    username: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Resource information
    resource_type: Optional[str] = None
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    
    # Request context
    request_id: Optional[str] = None
    api_endpoint: Optional[str] = None
    http_method: Optional[str] = None
    
    # Event data
    event_data: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Security context
    risk_score: float = Field(default=0.0, ge=0.0, le=1.0)
    requires_investigation: bool = Field(default=False)
    
    # Data integrity
    data_hash: Optional[str] = None
    
    def calculate_hash(self) -> str:
        """Calculate integrity hash for the audit event."""
        
        # Create hash from core event data
        hash_data = {
            "timestamp": self.timestamp.isoformat(),
            "level": self.level.value,
            "category": self.category.value,
            "event_type": self.event_type,
            "user_id": self.user_id,
            "resource_type": self.resource_type,
            "resource_id": self.resource_id,
            "event_data": json.dumps(self.event_data, sort_keys=True, default=str)
        }
        
        hash_string = json.dumps(hash_data, sort_keys=True)
        return hashlib.sha256(hash_string.encode()).hexdigest()

class AuditLogger:
    """Comprehensive audit logging system."""
    
    def __init__(self, db_optimizer: DatabaseOptimizer, 
                 cache_manager: CacheManager):
        self.db_optimizer = db_optimizer
        self.cache_manager = cache_manager
        
        # Configuration
        self.retention_days = 2555  # ~7 years for compliance
        self.batch_size = 100
        self.flush_interval = 30  # seconds
        
        # Buffer for batch writes
        self.audit_buffer: List[AuditEvent] = []
        self.buffer_lock = asyncio.Lock()
        
        # Statistics
        self.stats = {
            "events_logged": 0,
            "events_flushed": 0,
            "buffer_flushes": 0,
            "errors": 0
        }
        
        # Start background flush task
        asyncio.create_task(self._flush_worker())
        
        logger.info("Audit logging system initialized")
    
    async def log_event(self, level: AuditLevel, category: AuditCategory,
                       event_type: str, description: str,
                       user_id: Optional[str] = None,
                       username: Optional[str] = None,
                       resource_type: Optional[str] = None,
                       resource_id: Optional[str] = None,
                       event_data: Optional[Dict[str, Any]] = None,
                       request_context: Optional[Dict[str, Any]] = None,
                       risk_score: float = 0.0,
                       requires_investigation: bool = False) -> str:
        """Log an audit event."""
        
        try:
            # Create audit event
            event = AuditEvent(
                event_id=f"audit_{uuid.uuid4().hex}",
                level=level,
                category=category,
                event_type=event_type,
                description=description,
                user_id=user_id,
                username=username,
                resource_type=resource_type,
                resource_id=resource_id,
                event_data=event_data or {},
                risk_score=risk_score,
                requires_investigation=requires_investigation
            )
            
            # Add request context if provided
            if request_context:
                event.session_id = request_context.get("session_id")
                event.ip_address = request_context.get("ip_address")
                event.user_agent = request_context.get("user_agent")
                event.request_id = request_context.get("request_id")
                event.api_endpoint = request_context.get("api_endpoint")
                event.http_method = request_context.get("http_method")
                event.metadata.update(request_context.get("metadata", {}))
            
            # Calculate integrity hash
            event.data_hash = event.calculate_hash()
            
            # Add to buffer
            async with self.buffer_lock:
                self.audit_buffer.append(event)
                self.stats["events_logged"] += 1
            
            # Check if immediate flush is needed for critical events
            if (level == AuditLevel.CRITICAL or 
                requires_investigation or 
                len(self.audit_buffer) >= self.batch_size):
                await self._flush_buffer()
            
            return event.event_id
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Error logging audit event: {e}")
            raise
    
    async def search_events(self, filters: Dict[str, Any],
                          start_date: Optional[datetime] = None,
                          end_date: Optional[datetime] = None,
                          limit: int = 1000) -> List[AuditEvent]:
        """Search audit events with advanced filtering."""
        
        try:
            # Build query
            query_filters = {}
            
            # Date range filter
            if start_date or end_date:
                date_filter = {}
                if start_date:
                    date_filter["$gte"] = start_date
                if end_date:
                    date_filter["$lte"] = end_date
                query_filters["timestamp"] = date_filter
            
            # Add other filters
            for key, value in filters.items():
                if key in ["level", "category", "event_type", "user_id", "resource_type"]:
                    query_filters[key] = value
                elif key == "ip_address":
                    query_filters["ip_address"] = value
                elif key == "requires_investigation":
                    query_filters["requires_investigation"] = bool(value)
                elif key == "min_risk_score":
                    query_filters["risk_score"] = {"$gte": float(value)}
            
            # Execute search
            events_data = await self.db_optimizer.optimize_query(
                "audit_logs",
                query_filters,
                sort=[("timestamp", -1)],
                limit=limit,
                use_cache=True,
                cache_ttl=300
            )
            
            return [AuditEvent(**event) for event in events_data]
            
        except Exception as e:
            logger.error(f"Error searching audit events: {e}")
            return []
    
    async def get_audit_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get audit statistics for the specified period."""
        
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Aggregation pipeline for statistics
            pipeline = [
                {"$match": {"timestamp": {"$gte": start_date}}},
                {
                    "$group": {
                        "_id": {
                            "level": "$level",
                            "category": "$category"
                        },
                        "count": {"$sum": 1},
                        "avg_risk_score": {"$avg": "$risk_score"},
                        "investigation_required": {
                            "$sum": {"$cond": [{"$eq": ["$requires_investigation", True]}, 1, 0]}
                        }
                    }
                },
                {"$sort": {"count": -1}}
            ]
            
            stats_result = await self.db_optimizer.aggregate_with_cache(
                "audit_logs",
                pipeline,
                use_cache=True,
                cache_ttl=600
            )
            
            # Process results
            statistics = {
                "period_days": days,
                "total_events": sum(stat["count"] for stat in stats_result),
                "events_requiring_investigation": sum(stat["investigation_required"] for stat in stats_result),
                "by_level": {},
                "by_category": {},
                "risk_distribution": {}
            }
            
            for stat in stats_result:
                level = stat["_id"]["level"]
                category = stat["_id"]["category"]
                count = stat["count"]
                
                if level not in statistics["by_level"]:
                    statistics["by_level"][level] = 0
                statistics["by_level"][level] += count
                
                if category not in statistics["by_category"]:
                    statistics["by_category"][category] = 0
                statistics["by_category"][category] += count
            
            return statistics
            
        except Exception as e:
            logger.error(f"Error getting audit statistics: {e}")
            return {}
    
    async def export_audit_trail(self, filters: Dict[str, Any],
                               start_date: Optional[datetime] = None,
                               end_date: Optional[datetime] = None,
                               format: str = "json") -> str:
        """Export audit trail for compliance purposes."""
        
        try:
            # Get events
            events = await self.search_events(filters, start_date, end_date, limit=10000)
            
            if format.lower() == "csv":
                return self._export_to_csv(events)
            else:
                return self._export_to_json(events)
                
        except Exception as e:
            logger.error(f"Error exporting audit trail: {e}")
            raise
    
    async def verify_integrity(self, event_ids: List[str]) -> Dict[str, bool]:
        """Verify integrity of audit events."""
        
        try:
            results = {}
            
            for event_id in event_ids:
                event_data = await self.db_optimizer.database["audit_logs"].find_one(
                    {"event_id": event_id}
                )
                
                if not event_data:
                    results[event_id] = False
                    continue
                
                event = AuditEvent(**event_data)
                calculated_hash = event.calculate_hash()
                
                results[event_id] = (calculated_hash == event.data_hash)
            
            return results
            
        except Exception as e:
            logger.error(f"Error verifying audit integrity: {e}")
            return {event_id: False for event_id in event_ids}
    
    async def cleanup_old_events(self) -> int:
        """Clean up old audit events based on retention policy."""
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=self.retention_days)
            
            result = await self.db_optimizer.database["audit_logs"].delete_many(
                {"timestamp": {"$lt": cutoff_date}}
            )
            
            logger.info(f"Cleaned up {result.deleted_count} old audit events")
            return result.deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up audit events: {e}")
            return 0
    
    async def _flush_buffer(self):
        """Flush audit buffer to database."""
        
        async with self.buffer_lock:
            if not self.audit_buffer:
                return
            
            events_to_flush = self.audit_buffer.copy()
            self.audit_buffer.clear()
        
        try:
            # Insert events in batch
            events_data = [event.dict() for event in events_to_flush]
            
            await self.db_optimizer.bulk_insert_optimized(
                "audit_logs",
                events_data,
                batch_size=self.batch_size
            )
            
            self.stats["events_flushed"] += len(events_to_flush)
            self.stats["buffer_flushes"] += 1
            
        except Exception as e:
            self.stats["errors"] += 1
            logger.error(f"Error flushing audit buffer: {e}")
            
            # Re-add events to buffer if flush failed
            async with self.buffer_lock:
                self.audit_buffer.extend(events_to_flush)
    
    async def _flush_worker(self):
        """Background worker to periodically flush audit buffer."""
        
        while True:
            try:
                await asyncio.sleep(self.flush_interval)
                await self._flush_buffer()
                
            except Exception as e:
                logger.error(f"Audit flush worker error: {e}")
    
    def _export_to_json(self, events: List[AuditEvent]) -> str:
        """Export events to JSON format."""
        
        events_data = [event.dict() for event in events]
        return json.dumps(events_data, indent=2, default=str)
    
    def _export_to_csv(self, events: List[AuditEvent]) -> str:
        """Export events to CSV format."""
        
        import csv
        import io
        
        output = io.StringIO()
        
        if not events:
            return ""
        
        # Define CSV columns
        columns = [
            "event_id", "timestamp", "level", "category", "event_type",
            "description", "user_id", "username", "ip_address",
            "resource_type", "resource_id", "risk_score", "requires_investigation"
        ]
        
        writer = csv.DictWriter(output, fieldnames=columns)
        writer.writeheader()
        
        for event in events:
            row = {col: getattr(event, col, "") for col in columns}
            row["timestamp"] = event.timestamp.isoformat()
            writer.writerow(row)
        
        return output.getvalue()

class ComplianceAuditor:
    """Specialized auditing for compliance requirements."""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
    
    async def log_data_access(self, user_id: str, resource_type: str,
                            resource_id: str, action: str,
                            request_context: Optional[Dict[str, Any]] = None):
        """Log data access for GDPR compliance."""
        
        await self.audit_logger.log_event(
            level=AuditLevel.INFO,
            category=AuditCategory.DATA_ACCESS,
            event_type=f"data_access_{action}",
            description=f"User {user_id} performed {action} on {resource_type}",
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_data={"action": action},
            request_context=request_context
        )
    
    async def log_data_modification(self, user_id: str, resource_type: str,
                                  resource_id: str, changes: Dict[str, Any],
                                  request_context: Optional[Dict[str, Any]] = None):
        """Log data modifications for audit trail."""
        
        await self.audit_logger.log_event(
            level=AuditLevel.INFO,
            category=AuditCategory.DATA_MODIFICATION,
            event_type="data_modification",
            description=f"User {user_id} modified {resource_type} {resource_id}",
            user_id=user_id,
            resource_type=resource_type,
            resource_id=resource_id,
            event_data={"changes": changes},
            request_context=request_context
        )
    
    async def log_authentication_event(self, user_id: str, event_type: str,
                                     success: bool, 
                                     request_context: Optional[Dict[str, Any]] = None,
                                     risk_factors: Optional[List[str]] = None):
        """Log authentication events for security compliance."""
        
        risk_score = 0.0
        if risk_factors:
            risk_score = min(len(risk_factors) * 0.2, 1.0)
        
        level = AuditLevel.WARNING if not success else AuditLevel.INFO
        
        await self.audit_logger.log_event(
            level=level,
            category=AuditCategory.AUTHENTICATION,
            event_type=event_type,
            description=f"Authentication {event_type} for user {user_id}: {'success' if success else 'failed'}",
            user_id=user_id,
            event_data={
                "success": success,
                "risk_factors": risk_factors or []
            },
            request_context=request_context,
            risk_score=risk_score,
            requires_investigation=not success and risk_score > 0.5
        )
    
    async def log_model_operation(self, user_id: str, model_id: str,
                                operation: str, result: Dict[str, Any],
                                request_context: Optional[Dict[str, Any]] = None):
        """Log ML model operations for model governance."""
        
        await self.audit_logger.log_event(
            level=AuditLevel.INFO,
            category=AuditCategory.ML_MODEL,
            event_type=f"model_{operation}",
            description=f"Model {model_id} {operation} by user {user_id}",
            user_id=user_id,
            resource_type="ml_model",
            resource_id=model_id,
            event_data={"operation": operation, "result": result},
            request_context=request_context
        )
    
    async def log_threat_detection(self, detection_result: Dict[str, Any],
                                 source: str = "system"):
        """Log threat detections for security compliance."""
        
        risk_score = detection_result.get("confidence", 0.0)
        is_phishing = detection_result.get("is_phishing", False)
        
        await self.audit_logger.log_event(
            level=AuditLevel.WARNING if is_phishing else AuditLevel.INFO,
            category=AuditCategory.THREAT_DETECTION,
            event_type="phishing_detection" if is_phishing else "legitimate_detection",
            description=f"Threat detection: {'Phishing' if is_phishing else 'Legitimate'} URL detected",
            resource_type="url",
            resource_id=detection_result.get("url", "unknown"),
            event_data=detection_result,
            metadata={"source": source},
            risk_score=risk_score if is_phishing else 0.0,
            requires_investigation=is_phishing and risk_score > 0.8
        )

# Audit decorators for automatic logging
class AuditDecorator:
    """Decorators for automatic audit logging."""
    
    def __init__(self, audit_logger: AuditLogger):
        self.audit_logger = audit_logger
    
    def audit_api_call(self, category: AuditCategory = AuditCategory.API_ACCESS,
                      log_request_data: bool = False,
                      log_response_data: bool = False):
        """Decorator to audit API calls."""
        
        def decorator(func):
            @wraps(func)
            async def async_wrapper(*args, **kwargs):
                # Extract request context if available
                request_context = {}
                for arg in args:
                    if hasattr(arg, 'client'):  # FastAPI Request object
                        request_context = {
                            "ip_address": getattr(arg.client, 'host', None),
                            "user_agent": arg.headers.get('user-agent'),
                            "api_endpoint": str(arg.url.path),
                            "http_method": arg.method,
                            "request_id": arg.headers.get('x-request-id')
                        }
                        break
                
                # Get user context from kwargs
                user_id = None
                for key, value in kwargs.items():
                    if key in ['current_user', 'user'] and hasattr(value, 'id'):
                        user_id = value.id
                        break
                
                event_data = {}
                if log_request_data:
                    event_data["request_args"] = str(args)[:500]
                    event_data["request_kwargs"] = {k: str(v)[:200] for k, v in kwargs.items()}
                
                start_time = datetime.utcnow()
                
                try:
                    # Execute function
                    if inspect.iscoroutinefunction(func):
                        result = await func(*args, **kwargs)
                    else:
                        result = func(*args, **kwargs)
                    
                    # Log successful call
                    duration = (datetime.utcnow() - start_time).total_seconds()
                    
                    if log_response_data:
                        event_data["response"] = str(result)[:500]
                    
                    event_data["duration_seconds"] = duration
                    
                    await self.audit_logger.log_event(
                        level=AuditLevel.INFO,
                        category=category,
                        event_type="api_call_success",
                        description=f"API call to {func.__name__} successful",
                        user_id=user_id,
                        event_data=event_data,
                        request_context=request_context
                    )
                    
                    return result
                    
                except Exception as e:
                    # Log failed call
                    duration = (datetime.utcnow() - start_time).total_seconds()
                    event_data["error"] = str(e)
                    event_data["duration_seconds"] = duration
                    
                    await self.audit_logger.log_event(
                        level=AuditLevel.ERROR,
                        category=category,
                        event_type="api_call_error",
                        description=f"API call to {func.__name__} failed: {str(e)}",
                        user_id=user_id,
                        event_data=event_data,
                        request_context=request_context,
                        requires_investigation=True
                    )
                    
                    raise
            
            @wraps(func)
            def sync_wrapper(*args, **kwargs):
                return asyncio.run(async_wrapper(*args, **kwargs))
            
            if inspect.iscoroutinefunction(func):
                return async_wrapper
            else:
                return sync_wrapper
        
        return decorator
    
    def audit_data_access(self, resource_type: str):
        """Decorator to audit data access operations."""
        
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Extract resource ID and user ID from arguments
                resource_id = kwargs.get('id') or kwargs.get('resource_id') or 'unknown'
                user_id = None
                
                # Look for user in args/kwargs
                for key, value in kwargs.items():
                    if key in ['current_user', 'user'] and hasattr(value, 'id'):
                        user_id = value.id
                        break
                
                # Log data access
                await self.audit_logger.log_event(
                    level=AuditLevel.INFO,
                    category=AuditCategory.DATA_ACCESS,
                    event_type="data_access",
                    description=f"Data access to {resource_type} {resource_id}",
                    user_id=user_id,
                    resource_type=resource_type,
                    resource_id=str(resource_id)
                )
                
                # Execute function
                if inspect.iscoroutinefunction(func):
                    return await func(*args, **kwargs)
                else:
                    return func(*args, **kwargs)
            
            return wrapper
        
        return decorator

# Global audit instances
audit_logger: Optional[AuditLogger] = None
compliance_auditor: Optional[ComplianceAuditor] = None
audit_decorator: Optional[AuditDecorator] = None

def initialize_audit_system(db_optimizer: DatabaseOptimizer,
                          cache_manager: CacheManager):
    """Initialize global audit system."""
    
    global audit_logger, compliance_auditor, audit_decorator
    
    audit_logger = AuditLogger(db_optimizer, cache_manager)
    compliance_auditor = ComplianceAuditor(audit_logger)
    audit_decorator = AuditDecorator(audit_logger)
    
    logger.info("Audit system initialized")