"""GraphQL API endpoint with advanced querying capabilities."""

import strawberry
from typing import List, Optional, Union
from datetime import datetime
import asyncio
from strawberry.fastapi import GraphQLRouter
from strawberry.types import Info
from loguru import logger
from app.core.database import DatabaseOptimizer
from app.core.cache import CacheManager
from app.security.auth import get_current_user, require_permission, Permission
from app.ml.models.transformer_model import PhishingTransformerModel
from app.intelligence.threat_intelligence import ThreatIntelligenceFeeds

# GraphQL Types
@strawberry.type
class DetectionResult:
    """GraphQL type for phishing detection results."""
    id: str
    url: str
    is_phishing: bool
    confidence: float
    timestamp: datetime
    model_version: str
    risk_factors: List[str]
    metadata: Optional[str] = None

@strawberry.type
class ThreatIntelligence:
    """GraphQL type for threat intelligence data."""
    id: str
    indicator: str
    type: str
    confidence: float
    first_seen: datetime
    last_seen: datetime
    source: str
    tags: List[str]

@strawberry.type
class ModelMetrics:
    """GraphQL type for model performance metrics."""
    model_id: str
    version: str
    accuracy: float
    precision: float
    recall: float
    f1_score: float
    training_date: datetime
    samples_count: int

@strawberry.type
class SystemStats:
    """GraphQL type for system statistics."""
    total_detections: int
    phishing_count: int
    legitimate_count: int
    average_confidence: float
    detection_rate_24h: int
    active_threats: int

@strawberry.type
class BulkProcessingResult:
    """GraphQL type for bulk processing results."""
    job_id: str
    status: str
    total_items: int
    processed_items: int
    success_count: int
    error_count: int
    started_at: datetime
    completed_at: Optional[datetime] = None
    results: List[DetectionResult]

# Input Types
@strawberry.input
class DetectionFilter:
    """GraphQL input for filtering detection results."""
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    is_phishing: Optional[bool] = None
    min_confidence: Optional[float] = None
    model_version: Optional[str] = None
    url_pattern: Optional[str] = None
    limit: Optional[int] = 100

@strawberry.input
class BulkDetectionInput:
    """GraphQL input for bulk detection processing."""
    urls: List[str]
    priority: Optional[str] = "normal"  # low, normal, high
    callback_url: Optional[str] = None
    metadata: Optional[str] = None

@strawberry.input
class ThreatFilter:
    """GraphQL input for filtering threat intelligence."""
    type: Optional[str] = None
    min_confidence: Optional[float] = None
    source: Optional[str] = None
    since: Optional[datetime] = None
    tags: Optional[List[str]] = None

# GraphQL Query Class
@strawberry.type
class Query:
    """GraphQL Query resolver."""
    
    @strawberry.field
    async def detection_results(
        self,
        info: Info,
        filters: Optional[DetectionFilter] = None
    ) -> List[DetectionResult]:
        """Get phishing detection results with advanced filtering."""
        
        try:
            # Get database optimizer from context
            db_optimizer: DatabaseOptimizer = info.context["db_optimizer"]
            
            # Build query filters
            query_filters = {}
            if filters:
                if filters.start_date or filters.end_date:
                    time_filter = {}
                    if filters.start_date:
                        time_filter["$gte"] = filters.start_date
                    if filters.end_date:
                        time_filter["$lte"] = filters.end_date
                    query_filters["timestamp"] = time_filter
                
                if filters.is_phishing is not None:
                    query_filters["is_phishing"] = filters.is_phishing
                
                if filters.min_confidence:
                    query_filters["confidence"] = {"$gte": filters.min_confidence}
                
                if filters.model_version:
                    query_filters["model_version"] = filters.model_version
                
                if filters.url_pattern:
                    query_filters["url"] = {
                        "$regex": filters.url_pattern, 
                        "$options": "i"
                    }
            
            # Execute optimized query
            results = await db_optimizer.optimize_query(
                "detection_results",
                query_filters,
                sort=[("timestamp", -1)],
                limit=filters.limit if filters else 100,
                use_cache=True,
                cache_ttl=300
            )
            
            # Convert to GraphQL types
            detection_results = []
            for result in results:
                detection_results.append(DetectionResult(
                    id=result.get("_id", ""),
                    url=result.get("url", ""),
                    is_phishing=result.get("is_phishing", False),
                    confidence=result.get("confidence", 0.0),
                    timestamp=result.get("timestamp", datetime.utcnow()),
                    model_version=result.get("model_version", ""),
                    risk_factors=result.get("risk_factors", []),
                    metadata=result.get("metadata")
                ))
            
            return detection_results
            
        except Exception as e:
            logger.error(f"GraphQL detection_results error: {e}")
            raise
    
    @strawberry.field
    async def threat_intelligence(
        self,
        info: Info,
        filters: Optional[ThreatFilter] = None
    ) -> List[ThreatIntelligence]:
        """Get threat intelligence data with filtering."""
        
        try:
            db_optimizer: DatabaseOptimizer = info.context["db_optimizer"]
            
            # Build query filters
            query_filters = {}
            if filters:
                if filters.type:
                    query_filters["type"] = filters.type
                
                if filters.min_confidence:
                    query_filters["confidence"] = {"$gte": filters.min_confidence}
                
                if filters.source:
                    query_filters["source"] = filters.source
                
                if filters.since:
                    query_filters["last_seen"] = {"$gte": filters.since}
                
                if filters.tags:
                    query_filters["tags"] = {"$in": filters.tags}
            
            results = await db_optimizer.optimize_query(
                "threat_intelligence",
                query_filters,
                sort=[("confidence", -1), ("last_seen", -1)],
                limit=200,
                use_cache=True,
                cache_ttl=600
            )
            
            # Convert to GraphQL types
            threat_data = []
            for result in results:
                threat_data.append(ThreatIntelligence(
                    id=result.get("_id", ""),
                    indicator=result.get("indicator", ""),
                    type=result.get("type", ""),
                    confidence=result.get("confidence", 0.0),
                    first_seen=result.get("first_seen", datetime.utcnow()),
                    last_seen=result.get("last_seen", datetime.utcnow()),
                    source=result.get("source", ""),
                    tags=result.get("tags", [])
                ))
            
            return threat_data
            
        except Exception as e:
            logger.error(f"GraphQL threat_intelligence error: {e}")
            raise
    
    @strawberry.field
    async def model_metrics(
        self,
        info: Info,
        model_id: Optional[str] = None
    ) -> List[ModelMetrics]:
        """Get ML model performance metrics."""
        
        try:
            db_optimizer: DatabaseOptimizer = info.context["db_optimizer"]
            
            query_filters = {}
            if model_id:
                query_filters["model_id"] = model_id
            
            results = await db_optimizer.optimize_query(
                "models",
                query_filters,
                sort=[("created_at", -1)],
                limit=50,
                use_cache=True,
                cache_ttl=1800  # 30 minutes
            )
            
            # Convert to GraphQL types
            model_data = []
            for result in results:
                performance = result.get("performance", {})
                model_data.append(ModelMetrics(
                    model_id=result.get("model_id", ""),
                    version=result.get("version", ""),
                    accuracy=performance.get("accuracy", 0.0),
                    precision=performance.get("precision", 0.0),
                    recall=performance.get("recall", 0.0),
                    f1_score=performance.get("f1_score", 0.0),
                    training_date=result.get("created_at", datetime.utcnow()),
                    samples_count=result.get("training_samples", 0)
                ))
            
            return model_data
            
        except Exception as e:
            logger.error(f"GraphQL model_metrics error: {e}")
            raise
    
    @strawberry.field
    async def system_stats(self, info: Info) -> SystemStats:
        """Get comprehensive system statistics."""
        
        try:
            db_optimizer: DatabaseOptimizer = info.context["db_optimizer"]
            
            # Use aggregation pipeline for efficient stats calculation
            stats_pipeline = [
                {
                    "$group": {
                        "_id": None,
                        "total_detections": {"$sum": 1},
                        "phishing_count": {
                            "$sum": {"$cond": [{"$eq": ["$is_phishing", True]}, 1, 0]}
                        },
                        "legitimate_count": {
                            "$sum": {"$cond": [{"$eq": ["$is_phishing", False]}, 1, 0]}
                        },
                        "average_confidence": {"$avg": "$confidence"}
                    }
                }
            ]
            
            stats_result = await db_optimizer.aggregate_with_cache(
                "detection_results",
                stats_pipeline,
                use_cache=True,
                cache_ttl=300
            )
            
            # Get 24-hour detection rate
            yesterday = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            recent_pipeline = [
                {"$match": {"timestamp": {"$gte": yesterday}}},
                {"$count": "detection_rate_24h"}
            ]
            
            recent_result = await db_optimizer.aggregate_with_cache(
                "detection_results",
                recent_pipeline,
                use_cache=True,
                cache_ttl=300
            )
            
            # Get active threat count
            threat_pipeline = [
                {
                    "$match": {
                        "last_seen": {"$gte": yesterday},
                        "confidence": {"$gte": 0.7}
                    }
                },
                {"$count": "active_threats"}
            ]
            
            threat_result = await db_optimizer.aggregate_with_cache(
                "threat_intelligence",
                threat_pipeline,
                use_cache=True,
                cache_ttl=600
            )
            
            # Compile results
            stats = stats_result[0] if stats_result else {}
            detection_rate = recent_result[0]["detection_rate_24h"] if recent_result else 0
            active_threats = threat_result[0]["active_threats"] if threat_result else 0
            
            return SystemStats(
                total_detections=stats.get("total_detections", 0),
                phishing_count=stats.get("phishing_count", 0),
                legitimate_count=stats.get("legitimate_count", 0),
                average_confidence=round(stats.get("average_confidence", 0.0), 3),
                detection_rate_24h=detection_rate,
                active_threats=active_threats
            )
            
        except Exception as e:
            logger.error(f"GraphQL system_stats error: {e}")
            raise

# GraphQL Mutation Class
@strawberry.type
class Mutation:
    """GraphQL Mutation resolver."""
    
    @strawberry.field
    async def detect_phishing(
        self,
        info: Info,
        url: str,
        analyze_content: Optional[bool] = True
    ) -> DetectionResult:
        """Perform single phishing detection."""
        
        try:
            # Get ML model from context
            ml_model: PhishingTransformerModel = info.context["ml_model"]
            
            # Perform detection
            result = await ml_model.predict(url, analyze_content=analyze_content)
            
            # Store result in database
            db_optimizer: DatabaseOptimizer = info.context["db_optimizer"]
            detection_data = {
                "url": url,
                "is_phishing": result["is_phishing"],
                "confidence": result["confidence"],
                "timestamp": datetime.utcnow(),
                "model_version": result.get("model_version", "transformer_v1"),
                "risk_factors": result.get("risk_factors", []),
                "metadata": result.get("metadata")
            }
            
            await db_optimizer.database["detection_results"].insert_one(detection_data)
            
            return DetectionResult(
                id=str(detection_data.get("_id", "")),
                url=url,
                is_phishing=result["is_phishing"],
                confidence=result["confidence"],
                timestamp=detection_data["timestamp"],
                model_version=detection_data["model_version"],
                risk_factors=detection_data["risk_factors"],
                metadata=detection_data.get("metadata")
            )
            
        except Exception as e:
            logger.error(f"GraphQL detect_phishing error: {e}")
            raise
    
    @strawberry.field
    async def bulk_detection(
        self,
        info: Info,
        input_data: BulkDetectionInput
    ) -> BulkProcessingResult:
        """Start bulk phishing detection job."""
        
        try:
            # Get services from context
            bulk_processor = info.context["bulk_processor"]
            
            # Start bulk processing job
            job_id = await bulk_processor.start_bulk_detection(
                urls=input_data.urls,
                priority=input_data.priority,
                callback_url=input_data.callback_url,
                metadata=input_data.metadata
            )
            
            return BulkProcessingResult(
                job_id=job_id,
                status="started",
                total_items=len(input_data.urls),
                processed_items=0,
                success_count=0,
                error_count=0,
                started_at=datetime.utcnow(),
                results=[]
            )
            
        except Exception as e:
            logger.error(f"GraphQL bulk_detection error: {e}")
            raise
    
    @strawberry.field
    async def update_threat_intelligence(
        self,
        info: Info,
        indicator: str,
        type: str,
        confidence: float,
        source: str,
        tags: Optional[List[str]] = None
    ) -> ThreatIntelligence:
        """Update threat intelligence data."""
        
        try:
            # Check permissions
            user = info.context.get("current_user")
            if not user or not hasattr(user, "permissions"):
                raise Exception("Authentication required")
            
            # Get threat intelligence service
            threat_feeds: ThreatIntelligenceFeeds = info.context["threat_feeds"]
            
            # Update threat data
            threat_data = {
                "indicator": indicator,
                "type": type,
                "confidence": confidence,
                "source": source,
                "tags": tags or [],
                "last_seen": datetime.utcnow(),
                "updated_by": user.username
            }
            
            result = await threat_feeds.add_custom_threat(threat_data)
            
            return ThreatIntelligence(
                id=str(result.get("_id", "")),
                indicator=indicator,
                type=type,
                confidence=confidence,
                first_seen=result.get("first_seen", datetime.utcnow()),
                last_seen=datetime.utcnow(),
                source=source,
                tags=tags or []
            )
            
        except Exception as e:
            logger.error(f"GraphQL update_threat_intelligence error: {e}")
            raise

# GraphQL Subscription Class (for real-time updates)
@strawberry.type
class Subscription:
    """GraphQL Subscription resolver for real-time updates."""
    
    @strawberry.subscription
    async def detection_updates(
        self,
        info: Info,
        min_confidence: Optional[float] = 0.7
    ) -> DetectionResult:
        """Subscribe to real-time detection updates."""
        
        try:
            # This would integrate with WebSocket or message queue
            # For demonstration, we'll simulate with a simple async generator
            
            while True:
                # In real implementation, this would listen to actual detection events
                await asyncio.sleep(5)  # Simulate delay
                
                # Yield new detection (this is just a placeholder)
                yield DetectionResult(
                    id="realtime_detection",
                    url="https://example-phishing.com",
                    is_phishing=True,
                    confidence=0.95,
                    timestamp=datetime.utcnow(),
                    model_version="transformer_v1",
                    risk_factors=["suspicious_domain", "fake_login_form"],
                    metadata=None
                )
                
        except Exception as e:
            logger.error(f"GraphQL detection_updates subscription error: {e}")
            raise
    
    @strawberry.subscription
    async def threat_alerts(
        self,
        info: Info,
        min_confidence: Optional[float] = 0.8
    ) -> ThreatIntelligence:
        """Subscribe to real-time threat intelligence alerts."""
        
        try:
            while True:
                await asyncio.sleep(10)  # Simulate delay
                
                # Yield new threat alert (placeholder)
                yield ThreatIntelligence(
                    id="realtime_threat",
                    indicator="malicious-domain.com",
                    type="domain",
                    confidence=0.9,
                    first_seen=datetime.utcnow(),
                    last_seen=datetime.utcnow(),
                    source="realtime_feeds",
                    tags=["phishing", "credential_theft"]
                )
                
        except Exception as e:
            logger.error(f"GraphQL threat_alerts subscription error: {e}")
            raise

# Create GraphQL schema
schema = strawberry.Schema(
    query=Query,
    mutation=Mutation,
    subscription=Subscription
)

# Create FastAPI router
def create_graphql_router(
    db_optimizer: DatabaseOptimizer,
    cache_manager: CacheManager,
    ml_model: PhishingTransformerModel,
    threat_feeds: ThreatIntelligenceFeeds,
    bulk_processor
) -> GraphQLRouter:
    """Create GraphQL router with dependency injection."""
    
    async def get_context() -> dict:
        """Get GraphQL context with injected dependencies."""
        return {
            "db_optimizer": db_optimizer,
            "cache_manager": cache_manager,
            "ml_model": ml_model,
            "threat_feeds": threat_feeds,
            "bulk_processor": bulk_processor
        }
    
    return GraphQLRouter(
        schema,
        context_getter=get_context,
        graphiql=True  # Enable GraphiQL interface for development
    )

# GraphQL utilities
class GraphQLUtils:
    """Utility functions for GraphQL operations."""
    
    @staticmethod
    def format_error(error: Exception) -> dict:
        """Format GraphQL error response."""
        
        return {
            "message": str(error),
            "type": type(error).__name__,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    @staticmethod
    def validate_pagination(limit: Optional[int], offset: Optional[int]) -> tuple:
        """Validate and normalize pagination parameters."""
        
        # Default and maximum limits
        default_limit = 50
        max_limit = 1000
        
        # Normalize limit
        if limit is None:
            limit = default_limit
        elif limit > max_limit:
            limit = max_limit
        elif limit < 1:
            limit = default_limit
        
        # Normalize offset
        if offset is None or offset < 0:
            offset = 0
        
        return limit, offset
    
    @staticmethod
    def build_sort_specification(sort_fields: Optional[List[str]]) -> List[tuple]:
        """Build MongoDB sort specification from GraphQL input."""
        
        if not sort_fields:
            return [("timestamp", -1)]  # Default sort
        
        sort_spec = []
        for field in sort_fields:
            if field.startswith("-"):
                # Descending sort
                sort_spec.append((field[1:], -1))
            else:
                # Ascending sort
                sort_spec.append((field, 1))
        
        return sort_spec