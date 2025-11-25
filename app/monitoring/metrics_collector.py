"""Comprehensive monitoring and metrics collection system."""

import asyncio
import time
import psutil
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, asdict
import aioredis
from prometheus_client import Counter, Histogram, Gauge, generate_latest
from loguru import logger
import numpy as np

@dataclass
class PerformanceMetrics:
    """Performance metrics data structure."""
    timestamp: datetime
    cpu_usage: float
    memory_usage: float
    disk_usage: float
    response_time: float
    throughput: float
    error_rate: float
    active_connections: int

@dataclass
class SecurityMetrics:
    """Security-specific metrics."""
    timestamp: datetime
    phishing_detected: int
    legitimate_classified: int
    threats_blocked: int
    false_positives: int
    model_accuracy: float
    confidence_scores: List[float]

class MetricsCollector:
    """Collect and manage system and application metrics."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        self.redis = None
        
        # Prometheus metrics
        self.request_count = Counter('phishing_api_requests_total', 
                                   'Total API requests', ['endpoint', 'method', 'status'])
        self.request_duration = Histogram('phishing_api_request_duration_seconds',
                                        'Request duration', ['endpoint'])
        self.detection_accuracy = Gauge('phishing_detection_accuracy', 'Model accuracy')
        self.threat_level_gauge = Gauge('phishing_threat_level', 
                                      'Current threat level', ['level'])
        
        # Internal metrics storage
        self.performance_history = deque(maxlen=10000)
        self.security_history = deque(maxlen=10000)
        self.api_metrics = defaultdict(lambda: defaultdict(int))
        
        # Real-time metrics
        self.current_metrics = {
            'requests_per_second': 0,
            'average_response_time': 0,
            'active_connections': 0,
            'error_rate': 0,
            'memory_usage': 0,
            'cpu_usage': 0
        }
        
        # Monitoring configuration
        self.collection_interval = 60  # seconds
        self.retention_days = 7
        self.running = False
        
    async def start_monitoring(self):
        """Start the monitoring system."""
        
        logger.info("Starting metrics collection system")
        
        # Connect to Redis
        try:
            self.redis = aioredis.from_url(self.redis_url)
            await self.redis.ping()
            logger.info("Connected to Redis for metrics storage")
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}. Using memory storage only.")
        
        self.running = True
        
        # Start monitoring tasks
        tasks = [
            asyncio.create_task(self._collect_system_metrics()),
            asyncio.create_task(self._collect_performance_metrics()),
            asyncio.create_task(self._cleanup_old_metrics())
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def stop_monitoring(self):
        """Stop the monitoring system."""
        
        self.running = False
        
        if self.redis:
            await self.redis.close()
        
        logger.info("Monitoring system stopped")
    
    async def _collect_system_metrics(self):
        """Collect system-level metrics."""
        
        while self.running:
            try:
                # System metrics
                cpu_usage = psutil.cpu_percent(interval=1)
                memory = psutil.virtual_memory()
                disk = psutil.disk_usage('/')
                
                # Network metrics
                network = psutil.net_io_counters()
                
                # Process metrics
                process = psutil.Process()
                process_cpu = process.cpu_percent()
                process_memory = process.memory_info().rss / 1024 / 1024  # MB
                
                system_metrics = {
                    'timestamp': datetime.utcnow().isoformat(),
                    'system': {
                        'cpu_usage': cpu_usage,
                        'memory_usage': memory.percent,
                        'memory_available': memory.available / 1024 / 1024 / 1024,  # GB
                        'disk_usage': disk.percent,
                        'disk_free': disk.free / 1024 / 1024 / 1024,  # GB
                        'network_bytes_sent': network.bytes_sent,
                        'network_bytes_recv': network.bytes_recv
                    },
                    'process': {
                        'cpu_usage': process_cpu,
                        'memory_usage_mb': process_memory,
                        'num_threads': process.num_threads(),
                        'num_fds': process.num_fds() if hasattr(process, 'num_fds') else 0
                    }
                }
                
                # Update current metrics
                self.current_metrics.update({
                    'cpu_usage': cpu_usage,
                    'memory_usage': memory.percent
                })
                
                # Store metrics
                if self.redis:
                    await self._store_metrics_redis('system_metrics', system_metrics)
                
                await asyncio.sleep(30)  # Collect every 30 seconds
                
            except Exception as e:
                logger.error(f"Error collecting system metrics: {e}")
                await asyncio.sleep(60)
    
    async def _collect_performance_metrics(self):
        """Collect application performance metrics."""
        
        while self.running:
            try:
                current_time = datetime.utcnow()
                
                # Calculate performance metrics from recent data
                recent_requests = await self._get_recent_api_metrics()
                
                if recent_requests:
                    avg_response_time = np.mean([r['response_time'] for r in recent_requests])
                    requests_per_second = len(recent_requests) / 60  # per minute -> per second
                    error_count = len([r for r in recent_requests if r['status_code'] >= 400])
                    error_rate = error_count / len(recent_requests) if recent_requests else 0
                else:
                    avg_response_time = 0
                    requests_per_second = 0
                    error_rate = 0
                
                performance_metrics = PerformanceMetrics(
                    timestamp=current_time,
                    cpu_usage=self.current_metrics['cpu_usage'],
                    memory_usage=self.current_metrics['memory_usage'],
                    disk_usage=0,  # Will be updated by system metrics
                    response_time=avg_response_time,
                    throughput=requests_per_second,
                    error_rate=error_rate,
                    active_connections=0  # Will be updated by connection counter
                )
                
                # Store in memory
                self.performance_history.append(performance_metrics)
                
                # Update current metrics
                self.current_metrics.update({
                    'requests_per_second': requests_per_second,
                    'average_response_time': avg_response_time,
                    'error_rate': error_rate
                })
                
                # Store in Redis
                if self.redis:
                    await self._store_metrics_redis('performance_metrics', asdict(performance_metrics))
                
                await asyncio.sleep(self.collection_interval)
                
            except Exception as e:
                logger.error(f"Error collecting performance metrics: {e}")
                await asyncio.sleep(60)
    
    async def _get_recent_api_metrics(self) -> List[Dict[str, Any]]:
        """Get recent API request metrics."""
        
        if not self.redis:
            return []
        
        try:
            # Get recent API calls from Redis
            cutoff_time = (datetime.utcnow() - timedelta(minutes=1)).isoformat()
            
            # This would be implemented based on how API metrics are stored
            # For now, return empty list
            return []
            
        except Exception as e:
            logger.error(f"Error getting recent API metrics: {e}")
            return []
    
    async def record_api_request(self, endpoint: str, method: str, status_code: int,
                                response_time: float, **kwargs):
        """Record API request metrics."""
        
        # Update Prometheus metrics
        self.request_count.labels(endpoint=endpoint, method=method, 
                                status=str(status_code)).inc()
        self.request_duration.labels(endpoint=endpoint).observe(response_time)
        
        # Store detailed metrics
        request_data = {
            'timestamp': datetime.utcnow().isoformat(),
            'endpoint': endpoint,
            'method': method,
            'status_code': status_code,
            'response_time': response_time,
            'user_agent': kwargs.get('user_agent', ''),
            'source_ip': kwargs.get('source_ip', ''),
            'request_size': kwargs.get('request_size', 0),
            'response_size': kwargs.get('response_size', 0)
        }
        
        if self.redis:
            await self._store_metrics_redis('api_requests', request_data)
        
        # Update internal counters
        self.api_metrics[endpoint][f"{method}_{status_code}"] += 1
    
    async def record_detection_metrics(self, is_phishing: bool, probability: float,
                                     confidence: float, model_version: str, **kwargs):
        """Record phishing detection metrics."""
        
        # Update security metrics
        current_time = datetime.utcnow()
        
        detection_data = {
            'timestamp': current_time.isoformat(),
            'is_phishing': is_phishing,
            'probability': probability,
            'confidence': confidence,
            'model_version': model_version,
            'processing_time': kwargs.get('processing_time', 0),
            'features_used': kwargs.get('features_used', 0),
            'threat_intelligence_match': kwargs.get('threat_intelligence_match', False)
        }
        
        if self.redis:
            await self._store_metrics_redis('detection_metrics', detection_data)
        
        # Update Prometheus metrics
        if is_phishing:
            self.threat_level_gauge.labels(level='high').inc()
        
        # Calculate rolling accuracy (simplified)
        recent_detections = list(self.security_history)[-100:]  # Last 100 detections
        if recent_detections:
            # This would need actual ground truth for real accuracy calculation
            estimated_accuracy = 0.95  # Placeholder
            self.detection_accuracy.set(estimated_accuracy)
    
    async def _store_metrics_redis(self, metric_type: str, data: Dict[str, Any]):
        """Store metrics in Redis with TTL."""
        
        try:
            key = f"metrics:{metric_type}:{int(time.time())}"
            await self.redis.setex(key, 604800, json.dumps(data, default=str))  # 7 days TTL
            
        except Exception as e:
            logger.error(f"Error storing metrics in Redis: {e}")
    
    async def _cleanup_old_metrics(self):
        """Clean up old metrics data."""
        
        while self.running:
            try:
                # Clean up old Redis keys
                if self.redis:
                    cutoff_time = int((datetime.utcnow() - timedelta(days=self.retention_days)).timestamp())
                    
                    # Scan for old metric keys and delete them
                    cursor = 0
                    while True:
                        cursor, keys = await self.redis.scan(cursor, match="metrics:*", count=100)
                        
                        for key in keys:
                            key_str = key.decode() if isinstance(key, bytes) else key
                            try:
                                timestamp = int(key_str.split(':')[-1])
                                if timestamp < cutoff_time:
                                    await self.redis.delete(key)
                            except (ValueError, IndexError):
                                continue
                        
                        if cursor == 0:
                            break
                
                # Clean up memory storage
                cutoff_datetime = datetime.utcnow() - timedelta(days=1)
                
                self.performance_history = deque([
                    m for m in self.performance_history 
                    if m.timestamp > cutoff_datetime
                ], maxlen=10000)
                
                await asyncio.sleep(3600)  # Clean up every hour
                
            except Exception as e:
                logger.error(f"Error cleaning up metrics: {e}")
                await asyncio.sleep(3600)
    
    async def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Get metrics for monitoring dashboard."""
        
        # Current metrics
        current = self.current_metrics.copy()
        
        # Historical metrics (last hour)
        recent_performance = [
            m for m in self.performance_history
            if m.timestamp > datetime.utcnow() - timedelta(hours=1)
        ]
        
        # Calculate trends
        if len(recent_performance) > 1:
            recent_response_times = [m.response_time for m in recent_performance]
            recent_throughput = [m.throughput for m in recent_performance]
            recent_error_rates = [m.error_rate for m in recent_performance]
            
            response_time_trend = {
                'current': recent_response_times[-1] if recent_response_times else 0,
                'average': np.mean(recent_response_times) if recent_response_times else 0,
                'max': np.max(recent_response_times) if recent_response_times else 0,
                'min': np.min(recent_response_times) if recent_response_times else 0
            }
            
            throughput_trend = {
                'current': recent_throughput[-1] if recent_throughput else 0,
                'average': np.mean(recent_throughput) if recent_throughput else 0,
                'max': np.max(recent_throughput) if recent_throughput else 0
            }
            
            error_rate_trend = {
                'current': recent_error_rates[-1] if recent_error_rates else 0,
                'average': np.mean(recent_error_rates) if recent_error_rates else 0
            }
        else:
            response_time_trend = throughput_trend = error_rate_trend = {
                'current': 0, 'average': 0, 'max': 0, 'min': 0
            }
        
        # API endpoint statistics
        endpoint_stats = {}
        for endpoint, methods in self.api_metrics.items():
            total_requests = sum(methods.values())
            error_requests = sum(v for k, v in methods.items() if k.split('_')[-1].startswith(('4', '5')))
            
            endpoint_stats[endpoint] = {
                'total_requests': total_requests,
                'error_rate': error_requests / total_requests if total_requests > 0 else 0
            }
        
        return {
            'current_metrics': current,
            'trends': {
                'response_time': response_time_trend,
                'throughput': throughput_trend,
                'error_rate': error_rate_trend
            },
            'endpoint_stats': endpoint_stats,
            'system_health': {
                'status': 'healthy' if current['error_rate'] < 0.05 else 'degraded',
                'uptime_hours': (datetime.utcnow() - datetime.utcnow().replace(hour=0, minute=0, second=0)).total_seconds() / 3600,
                'total_requests_today': sum(sum(methods.values()) for methods in self.api_metrics.values())
            }
        }
    
    def get_prometheus_metrics(self) -> str:
        """Get Prometheus-formatted metrics."""
        
        return generate_latest().decode()
    
    async def get_security_dashboard(self) -> Dict[str, Any]:
        """Get security-specific dashboard metrics."""
        
        if not self.redis:
            return {'error': 'Redis not available for security metrics'}
        
        try:
            # Get recent detection metrics
            cutoff_time = (datetime.utcnow() - timedelta(hours=24)).timestamp()
            
            # This would query Redis for actual security metrics
            # For now, return placeholder data
            
            return {
                'threats_detected_24h': 42,
                'blocked_ips': 15,
                'false_positive_rate': 0.023,
                'model_accuracy': 0.952,
                'avg_confidence': 0.87,
                'threat_intelligence_matches': 8,
                'alert_summary': {
                    'critical': 2,
                    'high': 8,
                    'medium': 15,
                    'low': 17
                }
            }
            
        except Exception as e:
            logger.error(f"Error getting security dashboard: {e}")
            return {'error': str(e)}