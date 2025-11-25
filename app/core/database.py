"""Database optimization and query performance enhancements."""

import asyncio
import time
from typing import Dict, List, Any, Optional, Union
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
from pymongo import IndexModel, ASCENDING, DESCENDING, TEXT
from pymongo.errors import DuplicateKeyError
from loguru import logger
import json
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
from app.core.cache import CacheManager, ModelCache
import hashlib

class DatabaseOptimizer:
    """Optimize database operations and queries."""
    
    def __init__(self, database: AsyncIOMotorDatabase, cache_manager: CacheManager):
        self.database = database
        self.cache_manager = cache_manager
        self.model_cache = ModelCache(cache_manager)
        
        # Query performance tracking
        self.query_stats = {}
        self.slow_queries = []
        
        logger.info("Database optimizer initialized")
    
    async def setup_indexes(self):
        """Set up optimized database indexes."""
        
        try:
            # Detection results indexes
            detection_collection = self.database.detection_results
            detection_indexes = [
                IndexModel([("timestamp", DESCENDING)]),
                IndexModel([("url_hash", ASCENDING)]),
                IndexModel([("is_phishing", ASCENDING)]),
                IndexModel([("confidence", DESCENDING)]),
                IndexModel([("model_version", ASCENDING)]),
                IndexModel([("timestamp", DESCENDING), ("is_phishing", ASCENDING)]),
                IndexModel([("url", TEXT), ("content", TEXT)])  # Text search
            ]
            
            await detection_collection.create_indexes(detection_indexes)
            logger.info("Detection results indexes created")
            
            # Training data indexes
            training_collection = self.database.training_data
            training_indexes = [
                IndexModel([("label", ASCENDING)]),
                IndexModel([("created_at", DESCENDING)]),
                IndexModel([("url_hash", ASCENDING)]),
                IndexModel([("is_verified", ASCENDING)]),
                IndexModel([("data_source", ASCENDING)])
            ]
            
            await training_collection.create_indexes(training_indexes)
            logger.info("Training data indexes created")
            
            # Model metadata indexes
            models_collection = self.database.models
            model_indexes = [
                IndexModel([("model_id", ASCENDING)], unique=True),
                IndexModel([("version", DESCENDING)]),
                IndexModel([("created_at", DESCENDING)]),
                IndexModel([("performance.accuracy", DESCENDING)]),
                IndexModel([("is_active", ASCENDING)])
            ]
            
            await models_collection.create_indexes(model_indexes)
            logger.info("Model metadata indexes created")
            
            # User activity indexes (for security and monitoring)
            activity_collection = self.database.user_activity
            activity_indexes = [
                IndexModel([("user_id", ASCENDING)]),
                IndexModel([("timestamp", DESCENDING)]),
                IndexModel([("ip_address", ASCENDING)]),
                IndexModel([("action", ASCENDING)]),
                IndexModel([("timestamp", DESCENDING), ("user_id", ASCENDING)])
            ]
            
            await activity_collection.create_indexes(activity_indexes)
            logger.info("User activity indexes created")
            
            # Threat intelligence indexes
            threats_collection = self.database.threat_intelligence
            threat_indexes = [
                IndexModel([("indicator", ASCENDING)], unique=True),
                IndexModel([("type", ASCENDING)]),
                IndexModel([("confidence", DESCENDING)]),
                IndexModel([("first_seen", DESCENDING)]),
                IndexModel([("last_seen", DESCENDING)]),
                IndexModel([("source", ASCENDING)])
            ]
            
            await threats_collection.create_indexes(threat_indexes)
            logger.info("Threat intelligence indexes created")
            
        except Exception as e:
            logger.error(f"Error setting up indexes: {e}")
            raise
    
    async def optimize_query(self, collection_name: str, query: Dict[str, Any],
                           projection: Optional[Dict[str, Any]] = None,
                           sort: Optional[List[tuple]] = None,
                           limit: Optional[int] = None,
                           use_cache: bool = True,
                           cache_ttl: int = 300) -> List[Dict[str, Any]]:
        """Optimized query execution with caching."""
        
        start_time = time.time()
        
        try:
            # Generate cache key
            cache_key = None
            if use_cache:
                cache_key = self._generate_query_cache_key(
                    collection_name, query, projection, sort, limit
                )
                
                # Try to get from cache
                cached_result = await self.cache_manager.get(cache_key)
                if cached_result is not None:
                    logger.debug(f"Cache hit for query in {collection_name}")
                    return cached_result
            
            # Execute query
            collection = self.database[collection_name]
            
            # Build query pipeline
            pipeline_parts = []
            if query:
                pipeline_parts.append({"$match": query})
            
            if projection:
                pipeline_parts.append({"$project": projection})
            
            if sort:
                sort_spec = {field: direction for field, direction in sort}
                pipeline_parts.append({"$sort": sort_spec})
            
            if limit:
                pipeline_parts.append({"$limit": limit})
            
            # Execute aggregation pipeline or find query
            if pipeline_parts:
                cursor = collection.aggregate(pipeline_parts, allowDiskUse=True)
                results = await cursor.to_list(length=None)
            else:
                cursor = collection.find(query, projection)
                if sort:
                    cursor = cursor.sort(sort)
                if limit:
                    cursor = cursor.limit(limit)
                results = await cursor.to_list(length=None)
            
            # Convert ObjectId to string for JSON serialization
            for result in results:
                if '_id' in result:
                    result['_id'] = str(result['_id'])
            
            # Cache result
            if use_cache and cache_key:
                await self.cache_manager.set(cache_key, results, ttl=cache_ttl)
            
            # Record performance
            duration = time.time() - start_time
            self._record_query_performance(collection_name, query, duration, len(results))
            
            return results
            
        except Exception as e:
            logger.error(f"Query optimization error in {collection_name}: {e}")
            raise
    
    async def bulk_insert_optimized(self, collection_name: str, 
                                  documents: List[Dict[str, Any]],
                                  batch_size: int = 1000,
                                  ordered: bool = False) -> Dict[str, Any]:
        """Optimized bulk insert with batching."""
        
        if not documents:
            return {"inserted_count": 0, "errors": []}
        
        collection = self.database[collection_name]
        total_inserted = 0
        errors = []
        
        # Process in batches
        for i in range(0, len(documents), batch_size):
            batch = documents[i:i + batch_size]
            
            try:
                result = await collection.insert_many(batch, ordered=ordered)
                total_inserted += len(result.inserted_ids)
                
            except Exception as e:
                logger.error(f"Batch insert error: {e}")
                errors.append(str(e))
                
                # If ordered, break on error
                if ordered:
                    break
        
        # Invalidate related caches
        await self._invalidate_collection_cache(collection_name)
        
        return {
            "inserted_count": total_inserted,
            "total_documents": len(documents),
            "errors": errors
        }
    
    async def update_with_cache_invalidation(self, collection_name: str,
                                           filter_query: Dict[str, Any],
                                           update_data: Dict[str, Any],
                                           upsert: bool = False) -> Dict[str, Any]:
        """Update documents and invalidate relevant cache."""
        
        collection = self.database[collection_name]
        
        try:
            result = await collection.update_many(filter_query, update_data, upsert=upsert)
            
            # Invalidate cache
            await self._invalidate_collection_cache(collection_name)
            
            return {
                "matched_count": result.matched_count,
                "modified_count": result.modified_count,
                "upserted_id": str(result.upserted_id) if result.upserted_id else None
            }
            
        except Exception as e:
            logger.error(f"Update error in {collection_name}: {e}")
            raise
    
    async def aggregate_with_cache(self, collection_name: str,
                                 pipeline: List[Dict[str, Any]],
                                 use_cache: bool = True,
                                 cache_ttl: int = 600) -> List[Dict[str, Any]]:
        """Execute aggregation pipeline with caching."""
        
        start_time = time.time()
        
        try:
            # Generate cache key
            cache_key = None
            if use_cache:
                cache_key = self._generate_pipeline_cache_key(collection_name, pipeline)
                
                # Try cache
                cached_result = await self.cache_manager.get(cache_key)
                if cached_result is not None:
                    return cached_result
            
            # Execute aggregation
            collection = self.database[collection_name]
            cursor = collection.aggregate(pipeline, allowDiskUse=True)
            results = await cursor.to_list(length=None)
            
            # Convert ObjectId to string
            for result in results:
                if isinstance(result, dict):
                    for key, value in result.items():
                        if hasattr(value, 'generation_time'):  # ObjectId
                            result[key] = str(value)
            
            # Cache result
            if use_cache and cache_key:
                await self.cache_manager.set(cache_key, results, ttl=cache_ttl)
            
            # Record performance
            duration = time.time() - start_time
            self._record_query_performance(collection_name, pipeline, duration, len(results))
            
            return results
            
        except Exception as e:
            logger.error(f"Aggregation error in {collection_name}: {e}")
            raise
    
    async def get_collection_stats(self, collection_name: str) -> Dict[str, Any]:
        """Get collection statistics for optimization."""
        
        try:
            collection = self.database[collection_name]
            
            # Get basic stats
            stats = await self.database.command("collStats", collection_name)
            
            # Get index information
            indexes = await collection.list_indexes().to_list(length=None)
            
            # Calculate additional metrics
            document_count = await collection.count_documents({})
            
            return {
                "collection_name": collection_name,
                "document_count": document_count,
                "storage_size_mb": round(stats.get("storageSize", 0) / (1024 * 1024), 2),
                "total_index_size_mb": round(stats.get("totalIndexSize", 0) / (1024 * 1024), 2),
                "average_document_size": stats.get("avgObjSize", 0),
                "indexes": [
                    {
                        "name": idx["name"],
                        "keys": idx["key"],
                        "unique": idx.get("unique", False),
                        "sparse": idx.get("sparse", False)
                    }
                    for idx in indexes
                ],
                "query_stats": self.query_stats.get(collection_name, {})
            }
            
        except Exception as e:
            logger.error(f"Error getting stats for {collection_name}: {e}")
            return {}
    
    async def cleanup_old_data(self, collection_name: str, 
                             date_field: str = "timestamp",
                             retention_days: int = 30) -> int:
        """Clean up old data based on retention policy."""
        
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=retention_days)
            
            collection = self.database[collection_name]
            result = await collection.delete_many({
                date_field: {"$lt": cutoff_date}
            })
            
            # Invalidate cache
            await self._invalidate_collection_cache(collection_name)
            
            logger.info(f"Cleaned up {result.deleted_count} old records from {collection_name}")
            return result.deleted_count
            
        except Exception as e:
            logger.error(f"Cleanup error in {collection_name}: {e}")
            return 0
    
    def _generate_query_cache_key(self, collection_name: str, query: Dict[str, Any],
                                projection: Optional[Dict[str, Any]],
                                sort: Optional[List[tuple]],
                                limit: Optional[int]) -> str:
        """Generate cache key for query."""
        
        cache_data = {
            "collection": collection_name,
            "query": query,
            "projection": projection,
            "sort": sort,
            "limit": limit
        }
        
        cache_str = json.dumps(cache_data, sort_keys=True, default=str)
        return f"db_query:{hashlib.md5(cache_str.encode()).hexdigest()}"
    
    def _generate_pipeline_cache_key(self, collection_name: str,
                                   pipeline: List[Dict[str, Any]]) -> str:
        """Generate cache key for aggregation pipeline."""
        
        cache_data = {
            "collection": collection_name,
            "pipeline": pipeline
        }
        
        cache_str = json.dumps(cache_data, sort_keys=True, default=str)
        return f"db_pipeline:{hashlib.md5(cache_str.encode()).hexdigest()}"
    
    def _record_query_performance(self, collection_name: str, query: Any,
                                duration: float, result_count: int):
        """Record query performance metrics."""
        
        if collection_name not in self.query_stats:
            self.query_stats[collection_name] = {
                "total_queries": 0,
                "total_duration": 0,
                "average_duration": 0,
                "slow_queries": 0
            }
        
        stats = self.query_stats[collection_name]
        stats["total_queries"] += 1
        stats["total_duration"] += duration
        stats["average_duration"] = stats["total_duration"] / stats["total_queries"]
        
        # Track slow queries (> 1 second)
        if duration > 1.0:
            stats["slow_queries"] += 1
            
            self.slow_queries.append({
                "collection": collection_name,
                "query": str(query)[:200],  # Truncate long queries
                "duration": duration,
                "result_count": result_count,
                "timestamp": datetime.utcnow()
            })
            
            # Keep only recent slow queries
            if len(self.slow_queries) > 100:
                self.slow_queries = self.slow_queries[-100:]
    
    async def _invalidate_collection_cache(self, collection_name: str):
        """Invalidate all cache entries related to a collection."""
        
        await self.cache_manager.clear_pattern(f"*{collection_name}*")
        logger.debug(f"Cache invalidated for collection: {collection_name}")
    
    async def analyze_query_performance(self) -> Dict[str, Any]:
        """Analyze query performance and provide optimization suggestions."""
        
        suggestions = []
        
        for collection_name, stats in self.query_stats.items():
            if stats["average_duration"] > 0.5:  # 500ms threshold
                suggestions.append(
                    f"Collection '{collection_name}' has slow average query time: "
                    f"{stats['average_duration']:.3f}s. Consider adding indexes."
                )
            
            if stats["slow_queries"] > stats["total_queries"] * 0.1:  # >10% slow queries
                suggestions.append(
                    f"Collection '{collection_name}' has {stats['slow_queries']} slow queries "
                    f"out of {stats['total_queries']} total. Review query patterns."
                )
        
        return {
            "query_statistics": self.query_stats,
            "slow_queries": self.slow_queries[-20:],  # Recent slow queries
            "optimization_suggestions": suggestions,
            "total_collections_analyzed": len(self.query_stats)
        }

class QueryBuilder:
    """Build optimized MongoDB queries."""
    
    @staticmethod
    def build_detection_query(filters: Dict[str, Any]) -> Dict[str, Any]:
        """Build optimized query for detection results."""
        
        query = {}
        
        # Time range filter (most selective)
        if filters.get("start_date") or filters.get("end_date"):
            time_filter = {}
            if filters.get("start_date"):
                time_filter["$gte"] = filters["start_date"]
            if filters.get("end_date"):
                time_filter["$lte"] = filters["end_date"]
            query["timestamp"] = time_filter
        
        # Phishing status filter
        if filters.get("is_phishing") is not None:
            query["is_phishing"] = filters["is_phishing"]
        
        # Confidence threshold
        if filters.get("min_confidence"):
            query["confidence"] = {"$gte": filters["min_confidence"]}
        
        # Model version
        if filters.get("model_version"):
            query["model_version"] = filters["model_version"]
        
        # URL pattern search
        if filters.get("url_pattern"):
            query["url"] = {"$regex": filters["url_pattern"], "$options": "i"}
        
        return query
    
    @staticmethod
    def build_aggregation_pipeline(collection_name: str,
                                 operation: str,
                                 filters: Dict[str, Any] = None,
                                 group_by: str = None,
                                 time_bucket: str = None) -> List[Dict[str, Any]]:
        """Build optimized aggregation pipeline."""
        
        pipeline = []
        
        # Match stage (should be first for performance)
        if filters:
            if collection_name == "detection_results":
                match_query = QueryBuilder.build_detection_query(filters)
            else:
                match_query = filters
            
            if match_query:
                pipeline.append({"$match": match_query})
        
        # Time bucketing for analytics
        if time_bucket and time_bucket in ["hour", "day", "week", "month"]:
            if time_bucket == "hour":
                date_format = "%Y-%m-%d %H:00:00"
            elif time_bucket == "day":
                date_format = "%Y-%m-%d"
            elif time_bucket == "week":
                date_format = "%Y-W%U"  # Year-Week
            else:  # month
                date_format = "%Y-%m"
            
            pipeline.append({
                "$addFields": {
                    "time_bucket": {
                        "$dateToString": {
                            "format": date_format,
                            "date": "$timestamp"
                        }
                    }
                }
            })
            group_by = "time_bucket"
        
        # Group stage
        if group_by:
            group_stage = {"$group": {"_id": f"${group_by}"}}
            
            if operation == "count":
                group_stage["$group"]["count"] = {"$sum": 1}
            elif operation == "average_confidence":
                group_stage["$group"]["avg_confidence"] = {"$avg": "$confidence"}
            elif operation == "sum":
                group_stage["$group"]["total"] = {"$sum": "$value"}
            
            pipeline.append(group_stage)
        
        # Sort stage (after grouping for performance)
        pipeline.append({"$sort": {"_id": -1}})
        
        return pipeline

# Database connection manager
class DatabaseManager:
    """Manage database connections and optimization."""
    
    def __init__(self, connection_string: str, database_name: str,
                 cache_manager: CacheManager):
        self.connection_string = connection_string
        self.database_name = database_name
        self.cache_manager = cache_manager
        self.client = None
        self.database = None
        self.optimizer = None
        
    async def initialize(self):
        """Initialize database connection and optimizer."""
        
        try:
            # Create MongoDB client with optimizations
            self.client = AsyncIOMotorClient(
                self.connection_string,
                maxPoolSize=20,
                minPoolSize=5,
                maxIdleTimeMS=30000,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=10000,
                socketTimeoutMS=20000,
                retryWrites=True,
                w="majority"
            )
            
            self.database = self.client[self.database_name]
            
            # Test connection
            await self.client.admin.command('ping')
            
            # Initialize optimizer
            self.optimizer = DatabaseOptimizer(self.database, self.cache_manager)
            await self.optimizer.setup_indexes()
            
            logger.info("Database connection and optimization initialized")
            
        except Exception as e:
            logger.error(f"Database initialization error: {e}")
            raise
    
    async def close(self):
        """Close database connection."""
        
        if self.client:
            self.client.close()
            logger.info("Database connection closed")
    
    @asynccontextmanager
    async def get_session(self):
        """Get database session for transactions."""
        
        async with await self.client.start_session() as session:
            yield session