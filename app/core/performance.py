"""Performance optimization utilities and async enhancements."""

import asyncio
import time
import psutil
import gc
from typing import Any, Dict, List, Optional, Callable, Awaitable
from contextlib import asynccontextmanager
from functools import wraps
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from multiprocessing import cpu_count
from loguru import logger
import weakref
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class PerformanceMetrics:
    """Performance metrics data structure."""
    start_time: float
    end_time: float
    duration: float
    memory_usage: float
    cpu_usage: float
    function_name: str
    args_size: int
    result_size: int

class PerformanceMonitor:
    """Monitor and optimize performance."""
    
    def __init__(self):
        self.metrics_history: List[PerformanceMetrics] = []
        self.slow_functions: Dict[str, List[float]] = {}
        self.memory_threshold = 80.0  # Percentage
        self.cpu_threshold = 80.0  # Percentage
        
        # Thread pools for different types of work
        self.io_pool = ThreadPoolExecutor(max_workers=min(32, cpu_count() * 4))
        self.cpu_pool = ThreadPoolExecutor(max_workers=cpu_count())
        self.process_pool = ProcessPoolExecutor(max_workers=cpu_count())
        
        logger.info(f"Performance monitor initialized with {cpu_count()} CPU cores")
    
    def monitor_performance(self, func: Callable) -> Callable:
        """Decorator to monitor function performance."""
        
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            start_memory = psutil.virtual_memory().percent
            start_cpu = psutil.cpu_percent()
            
            try:
                # Execute function
                if asyncio.iscoroutinefunction(func):
                    result = await func(*args, **kwargs)
                else:
                    result = func(*args, **kwargs)
                
                # Record metrics
                end_time = time.time()
                end_memory = psutil.virtual_memory().percent
                end_cpu = psutil.cpu_percent()
                
                duration = end_time - start_time
                
                metrics = PerformanceMetrics(
                    start_time=start_time,
                    end_time=end_time,
                    duration=duration,
                    memory_usage=max(start_memory, end_memory),
                    cpu_usage=max(start_cpu, end_cpu),
                    function_name=func.__name__,
                    args_size=len(str(args) + str(kwargs)),
                    result_size=len(str(result)) if result else 0
                )
                
                self.record_metrics(metrics)
                
                # Log slow functions
                if duration > 5.0:  # 5 seconds threshold
                    self.record_slow_function(func.__name__, duration)
                
                return result
                
            except Exception as e:
                logger.error(f"Performance monitoring error in {func.__name__}: {e}")
                raise
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            return asyncio.run(async_wrapper(*args, **kwargs))
        
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    def record_metrics(self, metrics: PerformanceMetrics):
        """Record performance metrics."""
        
        self.metrics_history.append(metrics)
        
        # Keep only recent metrics (last 1000)
        if len(self.metrics_history) > 1000:
            self.metrics_history = self.metrics_history[-1000:]
        
        # Check for performance issues
        if metrics.memory_usage > self.memory_threshold:
            logger.warning(f"High memory usage ({metrics.memory_usage:.1f}%) in {metrics.function_name}")
        
        if metrics.cpu_usage > self.cpu_threshold:
            logger.warning(f"High CPU usage ({metrics.cpu_usage:.1f}%) in {metrics.function_name}")
    
    def record_slow_function(self, function_name: str, duration: float):
        """Record slow function execution."""
        
        if function_name not in self.slow_functions:
            self.slow_functions[function_name] = []
        
        self.slow_functions[function_name].append(duration)
        
        # Keep only recent slow executions
        if len(self.slow_functions[function_name]) > 50:
            self.slow_functions[function_name] = self.slow_functions[function_name][-50:]
        
        logger.warning(f"Slow function detected: {function_name} took {duration:.2f}s")
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary."""
        
        if not self.metrics_history:
            return {"message": "No performance data available"}
        
        # Calculate averages
        total_metrics = len(self.metrics_history)
        avg_duration = sum(m.duration for m in self.metrics_history) / total_metrics
        avg_memory = sum(m.memory_usage for m in self.metrics_history) / total_metrics
        avg_cpu = sum(m.cpu_usage for m in self.metrics_history) / total_metrics
        
        # Find slowest functions
        slowest_functions = []
        for func_name, durations in self.slow_functions.items():
            avg_duration = sum(durations) / len(durations)
            slowest_functions.append({
                "function": func_name,
                "avg_duration": round(avg_duration, 2),
                "slow_executions": len(durations)
            })
        
        slowest_functions.sort(key=lambda x: x["avg_duration"], reverse=True)
        
        return {
            "total_metrics": total_metrics,
            "average_duration": round(avg_duration, 3),
            "average_memory_usage": round(avg_memory, 1),
            "average_cpu_usage": round(avg_cpu, 1),
            "slowest_functions": slowest_functions[:10],
            "system_info": self.get_system_info()
        }
    
    def get_system_info(self) -> Dict[str, Any]:
        """Get current system performance info."""
        
        memory = psutil.virtual_memory()
        cpu_info = psutil.cpu_freq()
        
        return {
            "cpu_count": cpu_count(),
            "cpu_percent": psutil.cpu_percent(interval=1),
            "cpu_frequency": cpu_info.current if cpu_info else None,
            "memory_total_gb": round(memory.total / (1024**3), 2),
            "memory_used_gb": round(memory.used / (1024**3), 2),
            "memory_percent": memory.percent,
            "disk_usage": {
                "total_gb": round(psutil.disk_usage('/').total / (1024**3), 2),
                "used_gb": round(psutil.disk_usage('/').used / (1024**3), 2),
                "free_gb": round(psutil.disk_usage('/').free / (1024**3), 2)
            }
        }

class AsyncOptimizer:
    """Optimize async operations and concurrency."""
    
    def __init__(self, max_concurrent_tasks: int = 100):
        self.max_concurrent_tasks = max_concurrent_tasks
        self.semaphore = asyncio.Semaphore(max_concurrent_tasks)
        self.active_tasks: weakref.WeakSet = weakref.WeakSet()
        
    async def run_with_semaphore(self, coro: Awaitable[Any]) -> Any:
        """Run coroutine with semaphore control."""
        
        async with self.semaphore:
            return await coro
    
    async def batch_process(self, items: List[Any], processor: Callable,
                          batch_size: int = 50, delay: float = 0.1) -> List[Any]:
        """Process items in batches to prevent overwhelming."""
        
        results = []
        
        for i in range(0, len(items), batch_size):
            batch = items[i:i + batch_size]
            
            # Process batch
            batch_tasks = [
                self.run_with_semaphore(processor(item))
                if asyncio.iscoroutinefunction(processor)
                else processor(item)
                for item in batch
            ]
            
            if asyncio.iscoroutinefunction(processor):
                batch_results = await asyncio.gather(*batch_tasks, return_exceptions=True)
            else:
                batch_results = batch_tasks
            
            results.extend(batch_results)
            
            # Add delay between batches
            if i + batch_size < len(items):
                await asyncio.sleep(delay)
        
        return results
    
    async def timeout_wrapper(self, coro: Awaitable[Any], 
                            timeout: float) -> Optional[Any]:
        """Wrap coroutine with timeout."""
        
        try:
            return await asyncio.wait_for(coro, timeout=timeout)
        except asyncio.TimeoutError:
            logger.warning(f"Operation timed out after {timeout}s")
            return None
    
    def create_task_with_cleanup(self, coro: Awaitable[Any], 
                               name: str = None) -> asyncio.Task:
        """Create task with automatic cleanup."""
        
        task = asyncio.create_task(coro, name=name)
        self.active_tasks.add(task)
        
        def cleanup_task(task_ref):
            if task_ref in self.active_tasks:
                self.active_tasks.remove(task_ref)
        
        task.add_done_callback(cleanup_task)
        return task
    
    async def cancel_all_tasks(self):
        """Cancel all active tasks."""
        
        tasks_to_cancel = list(self.active_tasks)
        
        for task in tasks_to_cancel:
            task.cancel()
        
        if tasks_to_cancel:
            await asyncio.gather(*tasks_to_cancel, return_exceptions=True)
            logger.info(f"Cancelled {len(tasks_to_cancel)} active tasks")

class ResourceOptimizer:
    """Optimize system resource usage."""
    
    def __init__(self):
        self.memory_cleanup_threshold = 85.0  # Percentage
        self.last_cleanup = time.time()
        self.cleanup_interval = 300  # 5 minutes
        
    def optimize_memory(self):
        """Optimize memory usage."""
        
        current_time = time.time()
        memory_usage = psutil.virtual_memory().percent
        
        # Check if cleanup is needed
        if (memory_usage > self.memory_cleanup_threshold or 
            current_time - self.last_cleanup > self.cleanup_interval):
            
            logger.info(f"Starting memory cleanup (usage: {memory_usage:.1f}%)")
            
            # Force garbage collection
            gc.collect()
            
            # Clear weakref callbacks
            gc.collect()
            
            self.last_cleanup = current_time
            
            new_memory_usage = psutil.virtual_memory().percent
            freed_memory = memory_usage - new_memory_usage
            
            logger.info(f"Memory cleanup completed. Freed: {freed_memory:.1f}%")
    
    def monitor_resources(self) -> Dict[str, Any]:
        """Monitor system resources."""
        
        memory = psutil.virtual_memory()
        cpu_percent = psutil.cpu_percent(interval=1)
        
        # Get process-specific info
        current_process = psutil.Process()
        process_memory = current_process.memory_info()
        
        return {
            "system_memory_percent": memory.percent,
            "system_cpu_percent": cpu_percent,
            "process_memory_mb": round(process_memory.rss / (1024 * 1024), 2),
            "process_cpu_percent": current_process.cpu_percent(),
            "open_files": len(current_process.open_files()),
            "threads": current_process.num_threads(),
            "memory_cleanup_needed": memory.percent > self.memory_cleanup_threshold
        }
    
    async def auto_optimize(self):
        """Automatic optimization routine."""
        
        while True:
            try:
                self.optimize_memory()
                await asyncio.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Auto-optimization error: {e}")
                await asyncio.sleep(60)

class ConnectionPool:
    """Advanced connection pooling."""
    
    def __init__(self, create_connection: Callable, 
                 max_connections: int = 20,
                 min_connections: int = 5,
                 max_idle_time: int = 300):
        self.create_connection = create_connection
        self.max_connections = max_connections
        self.min_connections = min_connections
        self.max_idle_time = max_idle_time
        
        self.pool: List[Dict[str, Any]] = []
        self.active_connections: int = 0
        self.lock = asyncio.Lock()
        
        # Initialize minimum connections
        asyncio.create_task(self._initialize_pool())
    
    async def _initialize_pool(self):
        """Initialize minimum connections in pool."""
        
        for _ in range(self.min_connections):
            try:
                connection = await self.create_connection()
                self.pool.append({
                    "connection": connection,
                    "created_at": time.time(),
                    "last_used": time.time()
                })
            except Exception as e:
                logger.error(f"Failed to initialize pool connection: {e}")
    
    async def get_connection(self):
        """Get connection from pool."""
        
        async with self.lock:
            # Try to get existing connection
            if self.pool:
                conn_info = self.pool.pop()
                conn_info["last_used"] = time.time()
                self.active_connections += 1
                return conn_info["connection"]
            
            # Create new connection if under limit
            if self.active_connections < self.max_connections:
                connection = await self.create_connection()
                self.active_connections += 1
                return connection
            
            # Pool exhausted
            raise Exception("Connection pool exhausted")
    
    async def return_connection(self, connection):
        """Return connection to pool."""
        
        async with self.lock:
            self.active_connections -= 1
            
            # Add back to pool if under max size
            if len(self.pool) < self.max_connections:
                self.pool.append({
                    "connection": connection,
                    "created_at": time.time(),
                    "last_used": time.time()
                })
            else:
                # Close excess connection
                try:
                    await connection.close()
                except Exception:
                    pass
    
    async def cleanup_idle_connections(self):
        """Clean up idle connections."""
        
        current_time = time.time()
        
        async with self.lock:
            active_pool = []
            
            for conn_info in self.pool:
                if current_time - conn_info["last_used"] < self.max_idle_time:
                    active_pool.append(conn_info)
                else:
                    # Close idle connection
                    try:
                        await conn_info["connection"].close()
                    except Exception:
                        pass
            
            self.pool = active_pool
            
            # Ensure minimum connections
            while len(self.pool) < self.min_connections:
                try:
                    connection = await self.create_connection()
                    self.pool.append({
                        "connection": connection,
                        "created_at": current_time,
                        "last_used": current_time
                    })
                except Exception as e:
                    logger.error(f"Failed to create minimum connection: {e}")
                    break
    
    @asynccontextmanager
    async def connection(self):
        """Context manager for connection handling."""
        
        conn = await self.get_connection()
        try:
            yield conn
        finally:
            await self.return_connection(conn)
    
    def get_pool_stats(self) -> Dict[str, Any]:
        """Get connection pool statistics."""
        
        return {
            "total_connections": len(self.pool),
            "active_connections": self.active_connections,
            "max_connections": self.max_connections,
            "min_connections": self.min_connections,
            "pool_utilization": (self.active_connections / self.max_connections) * 100
        }

# Global instances
performance_monitor = PerformanceMonitor()
async_optimizer = AsyncOptimizer()
resource_optimizer = ResourceOptimizer()

# Convenience decorators
def monitor_performance(func: Callable) -> Callable:
    """Decorator for performance monitoring."""
    return performance_monitor.monitor_performance(func)

def optimize_async(max_concurrent: int = 50):
    """Decorator for async optimization."""
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            optimizer = AsyncOptimizer(max_concurrent)
            return await optimizer.run_with_semaphore(func(*args, **kwargs))
        return wrapper
    return decorator

# Utility functions
async def run_cpu_bound(func: Callable, *args, **kwargs) -> Any:
    """Run CPU-bound function in process pool."""
    
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        performance_monitor.process_pool,
        func, *args
    )

async def run_io_bound(func: Callable, *args, **kwargs) -> Any:
    """Run I/O-bound function in thread pool."""
    
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(
        performance_monitor.io_pool,
        func, *args
    )

async def optimize_system_resources():
    """Optimize system resources."""
    
    resource_optimizer.optimize_memory()
    return resource_optimizer.monitor_resources()

async def get_performance_metrics() -> Dict[str, Any]:
    """Get comprehensive performance metrics."""
    
    return {
        "performance_summary": performance_monitor.get_performance_summary(),
        "system_resources": resource_optimizer.monitor_resources(),
        "async_optimizer_tasks": len(async_optimizer.active_tasks)
    }