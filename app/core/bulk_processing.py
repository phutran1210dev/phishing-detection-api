"""Bulk processing system for handling large-scale operations."""

import asyncio
import uuid
import json
from typing import Dict, List, Any, Optional, Callable, Union
from datetime import datetime, timedelta
from enum import Enum
from pydantic import BaseModel, Field
from loguru import logger
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.core.cache import CacheManager
from app.core.database import DatabaseOptimizer
from app.core.performance import AsyncOptimizer
from app.api.webhooks import WebhookEvents
import aiofiles

class JobStatus(str, Enum):
    """Bulk job status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    PAUSED = "paused"

class JobPriority(str, Enum):
    """Job priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"

class ProcessingMode(str, Enum):
    """Processing mode for bulk operations."""
    SEQUENTIAL = "sequential"
    PARALLEL = "parallel"
    BATCH = "batch"

class BulkJob(BaseModel):
    """Bulk processing job model."""
    
    job_id: str = Field(..., description="Unique job identifier")
    job_type: str = Field(..., description="Type of bulk job")
    status: JobStatus = Field(default=JobStatus.PENDING)
    priority: JobPriority = Field(default=JobPriority.NORMAL)
    processing_mode: ProcessingMode = Field(default=ProcessingMode.BATCH)
    
    # Job configuration
    total_items: int = Field(..., description="Total number of items to process")
    batch_size: int = Field(default=50, description="Items per batch")
    max_concurrent: int = Field(default=10, description="Maximum concurrent operations")
    timeout_seconds: int = Field(default=300, description="Job timeout")
    
    # Progress tracking
    processed_items: int = Field(default=0)
    success_count: int = Field(default=0)
    error_count: int = Field(default=0)
    
    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Configuration and metadata
    input_data: Dict[str, Any] = Field(default_factory=dict)
    output_data: Dict[str, Any] = Field(default_factory=dict)
    error_details: List[Dict[str, Any]] = Field(default_factory=list)
    callback_url: Optional[str] = None
    user_id: Optional[str] = None
    
    def progress_percentage(self) -> float:
        """Calculate progress percentage."""
        if self.total_items == 0:
            return 0.0
        return (self.processed_items / self.total_items) * 100
    
    def estimated_completion(self) -> Optional[datetime]:
        """Estimate completion time based on current progress."""
        if not self.started_at or self.processed_items == 0:
            return None
        
        elapsed = datetime.utcnow() - self.started_at
        items_per_second = self.processed_items / elapsed.total_seconds()
        
        if items_per_second > 0:
            remaining_items = self.total_items - self.processed_items
            remaining_seconds = remaining_items / items_per_second
            return datetime.utcnow() + timedelta(seconds=remaining_seconds)
        
        return None

class BulkProcessor:
    """Advanced bulk processing system."""
    
    def __init__(self, db_optimizer: DatabaseOptimizer, 
                 cache_manager: CacheManager,
                 webhook_events: Optional[WebhookEvents] = None):
        self.db_optimizer = db_optimizer
        self.cache_manager = cache_manager
        self.webhook_events = webhook_events
        self.async_optimizer = AsyncOptimizer(max_concurrent_tasks=100)
        
        # Job management
        self.active_jobs: Dict[str, BulkJob] = {}
        self.job_processors: Dict[str, Callable] = {}
        self.job_queue = asyncio.PriorityQueue()
        
        # Worker management
        self.workers_count = 5
        self.workers_running = False
        
        # Performance tracking
        self.performance_stats = {
            "total_jobs": 0,
            "completed_jobs": 0,
            "failed_jobs": 0,
            "total_items_processed": 0,
            "average_processing_time": 0.0
        }
        
        logger.info("Bulk processor initialized")
    
    async def start_workers(self):
        """Start background worker tasks."""
        
        if self.workers_running:
            return
        
        self.workers_running = True
        
        # Start worker tasks
        for i in range(self.workers_count):
            asyncio.create_task(self._worker(f"worker-{i}"))
        
        logger.info(f"Started {self.workers_count} bulk processing workers")
    
    async def stop_workers(self):
        """Stop background workers."""
        
        self.workers_running = False
        logger.info("Bulk processing workers stopped")
    
    def register_processor(self, job_type: str, processor: Callable):
        """Register a job processor function."""
        
        self.job_processors[job_type] = processor
        logger.info(f"Registered processor for job type: {job_type}")
    
    async def submit_job(self, job_type: str, items: List[Any],
                        priority: JobPriority = JobPriority.NORMAL,
                        processing_mode: ProcessingMode = ProcessingMode.BATCH,
                        batch_size: int = 50,
                        max_concurrent: int = 10,
                        callback_url: Optional[str] = None,
                        user_id: Optional[str] = None,
                        **kwargs) -> str:
        """Submit a bulk processing job."""
        
        try:
            # Generate job ID
            job_id = f"bulk_{job_type}_{uuid.uuid4().hex[:8]}"
            
            # Create job
            job = BulkJob(
                job_id=job_id,
                job_type=job_type,
                priority=priority,
                processing_mode=processing_mode,
                total_items=len(items),
                batch_size=batch_size,
                max_concurrent=max_concurrent,
                callback_url=callback_url,
                user_id=user_id,
                input_data={
                    "items": items[:1000],  # Store sample for monitoring
                    "kwargs": kwargs
                }
            )
            
            # Store job in database
            await self._save_job(job)
            
            # Cache job data
            await self.cache_manager.set(
                f"bulk_job:{job_id}",
                job.dict(),
                ttl=86400  # 24 hours
            )
            
            # Store full items list in cache (temporary)
            await self.cache_manager.set(
                f"bulk_job_items:{job_id}",
                items,
                ttl=7200  # 2 hours
            )
            
            # Add to active jobs
            self.active_jobs[job_id] = job
            
            # Queue job with priority
            priority_value = {
                JobPriority.LOW: 4,
                JobPriority.NORMAL: 3,
                JobPriority.HIGH: 2,
                JobPriority.URGENT: 1
            }.get(priority, 3)
            
            await self.job_queue.put((priority_value, time.time(), job_id))
            
            logger.info(f"Bulk job submitted: {job_id} ({len(items)} items)")
            return job_id
            
        except Exception as e:
            logger.error(f"Error submitting bulk job: {e}")
            raise
    
    async def get_job_status(self, job_id: str) -> Optional[BulkJob]:
        """Get job status and progress."""
        
        # Try active jobs first
        if job_id in self.active_jobs:
            return self.active_jobs[job_id]
        
        # Try cache
        cached_job = await self.cache_manager.get(f"bulk_job:{job_id}")
        if cached_job:
            return BulkJob(**cached_job)
        
        # Try database
        try:
            job_data = await self.db_optimizer.database["bulk_jobs"].find_one(
                {"job_id": job_id}
            )
            
            if job_data:
                return BulkJob(**job_data)
                
        except Exception as e:
            logger.error(f"Error getting job status {job_id}: {e}")
        
        return None
    
    async def cancel_job(self, job_id: str) -> bool:
        """Cancel a bulk job."""
        
        try:
            job = await self.get_job_status(job_id)
            if not job:
                return False
            
            if job.status in [JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED]:
                return False
            
            # Update job status
            job.status = JobStatus.CANCELLED
            job.completed_at = datetime.utcnow()
            
            # Update in database and cache
            await self._save_job(job)
            await self.cache_manager.set(f"bulk_job:{job_id}", job.dict(), ttl=86400)
            
            # Remove from active jobs
            if job_id in self.active_jobs:
                del self.active_jobs[job_id]
            
            logger.info(f"Job cancelled: {job_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error cancelling job {job_id}: {e}")
            return False
    
    async def pause_job(self, job_id: str) -> bool:
        """Pause a running job."""
        
        try:
            job = await self.get_job_status(job_id)
            if not job or job.status != JobStatus.RUNNING:
                return False
            
            job.status = JobStatus.PAUSED
            await self._save_job(job)
            
            logger.info(f"Job paused: {job_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error pausing job {job_id}: {e}")
            return False
    
    async def resume_job(self, job_id: str) -> bool:
        """Resume a paused job."""
        
        try:
            job = await self.get_job_status(job_id)
            if not job or job.status != JobStatus.PAUSED:
                return False
            
            job.status = JobStatus.PENDING
            
            # Re-queue job
            priority_value = {
                JobPriority.LOW: 4,
                JobPriority.NORMAL: 3,
                JobPriority.HIGH: 2,
                JobPriority.URGENT: 1
            }.get(job.priority, 3)
            
            await self.job_queue.put((priority_value, time.time(), job_id))
            await self._save_job(job)
            
            logger.info(f"Job resumed: {job_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error resuming job {job_id}: {e}")
            return False
    
    async def get_job_list(self, user_id: Optional[str] = None,
                          status: Optional[JobStatus] = None,
                          limit: int = 50) -> List[BulkJob]:
        """Get list of bulk jobs with filtering."""
        
        try:
            query_filters = {}
            
            if user_id:
                query_filters["user_id"] = user_id
            
            if status:
                query_filters["status"] = status.value
            
            jobs_data = await self.db_optimizer.optimize_query(
                "bulk_jobs",
                query_filters,
                sort=[("created_at", -1)],
                limit=limit,
                use_cache=True,
                cache_ttl=300
            )
            
            return [BulkJob(**job) for job in jobs_data]
            
        except Exception as e:
            logger.error(f"Error getting job list: {e}")
            return []
    
    async def _worker(self, worker_name: str):
        """Background worker for processing jobs."""
        
        logger.info(f"Bulk processing worker started: {worker_name}")
        
        while self.workers_running:
            try:
                # Get job from queue (with timeout)
                try:
                    priority, timestamp, job_id = await asyncio.wait_for(
                        self.job_queue.get(), timeout=1.0
                    )
                except asyncio.TimeoutError:
                    continue
                
                # Get job details
                job = await self.get_job_status(job_id)
                if not job or job.status != JobStatus.PENDING:
                    continue
                
                logger.info(f"Worker {worker_name} processing job: {job_id}")
                
                # Process the job
                await self._process_job(job, worker_name)
                
                # Mark queue task as done
                self.job_queue.task_done()
                
            except Exception as e:
                logger.error(f"Worker {worker_name} error: {e}")
                await asyncio.sleep(1)
        
        logger.info(f"Bulk processing worker stopped: {worker_name}")
    
    async def _process_job(self, job: BulkJob, worker_name: str):
        """Process a bulk job."""
        
        start_time = time.time()
        
        try:
            # Check if processor is registered
            if job.job_type not in self.job_processors:
                raise ValueError(f"No processor registered for job type: {job.job_type}")
            
            processor = self.job_processors[job.job_type]
            
            # Update job status
            job.status = JobStatus.RUNNING
            job.started_at = datetime.utcnow()
            await self._save_job(job)
            
            # Get items to process
            items = await self.cache_manager.get(f"bulk_job_items:{job.job_id}")
            if not items:
                # Try to reconstruct from input_data
                items = job.input_data.get("items", [])
                if not items:
                    raise ValueError("No items found for processing")
            
            # Process based on mode
            if job.processing_mode == ProcessingMode.SEQUENTIAL:
                await self._process_sequential(job, items, processor, worker_name)
            elif job.processing_mode == ProcessingMode.PARALLEL:
                await self._process_parallel(job, items, processor, worker_name)
            else:  # BATCH mode
                await self._process_batch(job, items, processor, worker_name)
            
            # Complete job
            job.status = JobStatus.COMPLETED
            job.completed_at = datetime.utcnow()
            
            # Calculate performance stats
            processing_time = time.time() - start_time
            self.performance_stats["total_jobs"] += 1
            self.performance_stats["completed_jobs"] += 1
            self.performance_stats["total_items_processed"] += job.processed_items
            
            # Update average processing time
            total_completed = self.performance_stats["completed_jobs"]
            current_avg = self.performance_stats["average_processing_time"]
            self.performance_stats["average_processing_time"] = (
                (current_avg * (total_completed - 1) + processing_time) / total_completed
            )
            
            logger.info(f"Job completed: {job.job_id} ({processing_time:.2f}s)")
            
        except Exception as e:
            # Mark job as failed
            job.status = JobStatus.FAILED
            job.completed_at = datetime.utcnow()
            job.error_details.append({
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
                "worker": worker_name
            })
            
            self.performance_stats["failed_jobs"] += 1
            
            logger.error(f"Job failed: {job.job_id} - {e}")
        
        finally:
            # Save final job state
            await self._save_job(job)
            
            # Remove from active jobs
            if job.job_id in self.active_jobs:
                del self.active_jobs[job.job_id]
            
            # Clean up cache
            await self.cache_manager.delete(f"bulk_job_items:{job.job_id}")
            
            # Send webhook notification
            if self.webhook_events:
                await self.webhook_events.bulk_job_completed({
                    "job_id": job.job_id,
                    "job_type": job.job_type,
                    "status": job.status.value,
                    "total_items": job.total_items,
                    "processed_items": job.processed_items,
                    "success_count": job.success_count,
                    "error_count": job.error_count,
                    "duration_seconds": (
                        (job.completed_at - job.started_at).total_seconds()
                        if job.started_at and job.completed_at else 0
                    )
                })
    
    async def _process_sequential(self, job: BulkJob, items: List[Any],
                                processor: Callable, worker_name: str):
        """Process items sequentially."""
        
        for i, item in enumerate(items):
            if job.status == JobStatus.CANCELLED:
                break
            
            try:
                # Process single item
                result = await self._process_single_item(item, processor, job.input_data.get("kwargs", {}))
                
                job.processed_items += 1
                job.success_count += 1
                
                # Store result sample
                if i < 10:  # Store first 10 results as samples
                    if "results" not in job.output_data:
                        job.output_data["results"] = []
                    job.output_data["results"].append(result)
                
            except Exception as e:
                job.processed_items += 1
                job.error_count += 1
                job.error_details.append({
                    "item_index": i,
                    "item": str(item)[:200],
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            # Update progress periodically
            if i % 10 == 0:
                await self._save_job(job)
    
    async def _process_parallel(self, job: BulkJob, items: List[Any],
                              processor: Callable, worker_name: str):
        """Process items in parallel."""
        
        semaphore = asyncio.Semaphore(job.max_concurrent)
        
        async def process_with_semaphore(item, index):
            async with semaphore:
                try:
                    result = await self._process_single_item(
                        item, processor, job.input_data.get("kwargs", {})
                    )
                    
                    job.processed_items += 1
                    job.success_count += 1
                    
                    return {"index": index, "result": result, "success": True}
                    
                except Exception as e:
                    job.processed_items += 1
                    job.error_count += 1
                    
                    return {
                        "index": index,
                        "item": str(item)[:200],
                        "error": str(e),
                        "success": False
                    }
        
        # Create tasks for all items
        tasks = [
            process_with_semaphore(item, i)
            for i, item in enumerate(items)
        ]
        
        # Process in chunks to avoid overwhelming
        chunk_size = 100
        for i in range(0, len(tasks), chunk_size):
            if job.status == JobStatus.CANCELLED:
                break
            
            chunk_tasks = tasks[i:i + chunk_size]
            chunk_results = await asyncio.gather(*chunk_tasks, return_exceptions=True)
            
            # Process results
            for result in chunk_results:
                if isinstance(result, dict):
                    if result["success"]:
                        # Store successful result sample
                        if len(job.output_data.get("results", [])) < 10:
                            if "results" not in job.output_data:
                                job.output_data["results"] = []
                            job.output_data["results"].append(result["result"])
                    else:
                        # Store error details
                        job.error_details.append({
                            "item_index": result["index"],
                            "item": result["item"],
                            "error": result["error"],
                            "timestamp": datetime.utcnow().isoformat()
                        })
            
            # Update progress
            await self._save_job(job)
    
    async def _process_batch(self, job: BulkJob, items: List[Any],
                           processor: Callable, worker_name: str):
        """Process items in batches."""
        
        for batch_start in range(0, len(items), job.batch_size):
            if job.status == JobStatus.CANCELLED:
                break
            
            batch_end = min(batch_start + job.batch_size, len(items))
            batch = items[batch_start:batch_end]
            
            try:
                # Process entire batch
                batch_results = await self._process_batch_items(
                    batch, processor, job.input_data.get("kwargs", {})
                )
                
                # Update counters
                job.processed_items += len(batch)
                
                for result in batch_results:
                    if result.get("success", True):
                        job.success_count += 1
                    else:
                        job.error_count += 1
                        job.error_details.append({
                            "batch_start": batch_start,
                            "error": result.get("error", "Unknown error"),
                            "timestamp": datetime.utcnow().isoformat()
                        })
                
                # Store result samples
                if len(job.output_data.get("results", [])) < 10:
                    if "results" not in job.output_data:
                        job.output_data["results"] = []
                    
                    successful_results = [
                        r for r in batch_results 
                        if r.get("success", True) and "result" in r
                    ]
                    
                    job.output_data["results"].extend([
                        r["result"] for r in successful_results[:5]
                    ])
                
            except Exception as e:
                job.processed_items += len(batch)
                job.error_count += len(batch)
                job.error_details.append({
                    "batch_start": batch_start,
                    "batch_size": len(batch),
                    "error": str(e),
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            # Update progress
            await self._save_job(job)
            
            # Small delay between batches
            await asyncio.sleep(0.1)
    
    async def _process_single_item(self, item: Any, processor: Callable,
                                 kwargs: Dict[str, Any]) -> Any:
        """Process a single item."""
        
        if asyncio.iscoroutinefunction(processor):
            return await processor(item, **kwargs)
        else:
            # Run in thread pool for sync functions
            loop = asyncio.get_event_loop()
            return await loop.run_in_executor(
                None, lambda: processor(item, **kwargs)
            )
    
    async def _process_batch_items(self, batch: List[Any], processor: Callable,
                                 kwargs: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Process a batch of items."""
        
        # Check if processor supports batch processing
        if hasattr(processor, 'process_batch'):
            if asyncio.iscoroutinefunction(processor.process_batch):
                return await processor.process_batch(batch, **kwargs)
            else:
                loop = asyncio.get_event_loop()
                return await loop.run_in_executor(
                    None, lambda: processor.process_batch(batch, **kwargs)
                )
        else:
            # Fall back to processing items individually
            results = []
            for item in batch:
                try:
                    result = await self._process_single_item(item, processor, kwargs)
                    results.append({"result": result, "success": True})
                except Exception as e:
                    results.append({"error": str(e), "success": False})
            
            return results
    
    async def _save_job(self, job: BulkJob):
        """Save job to database and cache."""
        
        try:
            # Update in database
            await self.db_optimizer.database["bulk_jobs"].update_one(
                {"job_id": job.job_id},
                {"$set": job.dict()},
                upsert=True
            )
            
            # Update cache
            await self.cache_manager.set(
                f"bulk_job:{job.job_id}",
                job.dict(),
                ttl=86400
            )
            
        except Exception as e:
            logger.error(f"Error saving job {job.job_id}: {e}")
    
    def get_performance_stats(self) -> Dict[str, Any]:
        """Get bulk processor performance statistics."""
        
        return {
            **self.performance_stats,
            "active_jobs": len(self.active_jobs),
            "queue_size": self.job_queue.qsize(),
            "workers_running": self.workers_running,
            "workers_count": self.workers_count,
            "registered_processors": list(self.job_processors.keys())
        }

# Global bulk processor instance
bulk_processor: Optional[BulkProcessor] = None

def initialize_bulk_processor(db_optimizer: DatabaseOptimizer,
                            cache_manager: CacheManager,
                            webhook_events: Optional[WebhookEvents] = None):
    """Initialize global bulk processor."""
    
    global bulk_processor
    
    bulk_processor = BulkProcessor(db_optimizer, cache_manager, webhook_events)
    
    logger.info("Bulk processor system initialized")