"""Webhook system for real-time notifications and integrations."""

import asyncio
import json
import time
import hashlib
import hmac
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime, timedelta
from pydantic import BaseModel, validator, Field
from fastapi import HTTPException, Request
import httpx
from loguru import logger
from enum import Enum
import aioredis
from app.core.cache import CacheManager
from app.core.database import DatabaseOptimizer

class WebhookEvent(str, Enum):
    """Webhook event types."""
    DETECTION_COMPLETED = "detection.completed"
    PHISHING_DETECTED = "phishing.detected"
    THREAT_INTELLIGENCE_UPDATE = "threat_intelligence.updated"
    MODEL_UPDATED = "model.updated"
    BULK_JOB_COMPLETED = "bulk_job.completed"
    SECURITY_ALERT = "security.alert"
    SYSTEM_HEALTH = "system.health"

class WebhookStatus(str, Enum):
    """Webhook delivery status."""
    PENDING = "pending"
    DELIVERED = "delivered"
    FAILED = "failed"
    RETRYING = "retrying"
    DISABLED = "disabled"

class WebhookConfig(BaseModel):
    """Webhook configuration model."""
    
    id: str = Field(..., description="Unique webhook identifier")
    url: str = Field(..., description="Webhook endpoint URL")
    events: List[WebhookEvent] = Field(..., description="Events to subscribe to")
    secret: Optional[str] = Field(None, description="Webhook signing secret")
    active: bool = Field(True, description="Whether webhook is active")
    retry_count: int = Field(3, description="Number of retry attempts")
    timeout_seconds: int = Field(30, description="Request timeout")
    headers: Dict[str, str] = Field(default_factory=dict, description="Custom headers")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Event filters")
    created_at: datetime = Field(default_factory=datetime.utcnow)
    
    @validator('url')
    def validate_url(cls, v):
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL must start with http:// or https://')
        return v
    
    @validator('retry_count')
    def validate_retry_count(cls, v):
        if v < 0 or v > 10:
            raise ValueError('Retry count must be between 0 and 10')
        return v

class WebhookPayload(BaseModel):
    """Webhook payload structure."""
    
    event: WebhookEvent
    timestamp: datetime
    data: Dict[str, Any]
    webhook_id: str
    delivery_id: str
    signature: Optional[str] = None

class WebhookDelivery(BaseModel):
    """Webhook delivery record."""
    
    delivery_id: str
    webhook_id: str
    event: WebhookEvent
    payload: Dict[str, Any]
    status: WebhookStatus
    attempts: int = 0
    last_attempt: Optional[datetime] = None
    next_retry: Optional[datetime] = None
    response_status: Optional[int] = None
    response_body: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)

class WebhookManager:
    """Manage webhook registrations and deliveries."""
    
    def __init__(self, db_optimizer: DatabaseOptimizer, 
                 cache_manager: CacheManager):
        self.db_optimizer = db_optimizer
        self.cache_manager = cache_manager
        self.webhooks: Dict[str, WebhookConfig] = {}
        self.delivery_queue = asyncio.Queue()
        self.http_client = httpx.AsyncClient(timeout=30.0)
        
        # Start background delivery worker
        asyncio.create_task(self._delivery_worker())
        
        logger.info("Webhook manager initialized")
    
    async def register_webhook(self, webhook_config: WebhookConfig) -> str:
        """Register a new webhook."""
        
        try:
            # Store in database
            webhook_data = webhook_config.dict()
            await self.db_optimizer.database["webhooks"].insert_one(webhook_data)
            
            # Cache webhook config
            self.webhooks[webhook_config.id] = webhook_config
            await self.cache_manager.set(
                f"webhook:{webhook_config.id}",
                webhook_config.dict(),
                ttl=3600
            )
            
            logger.info(f"Webhook registered: {webhook_config.id} -> {webhook_config.url}")
            return webhook_config.id
            
        except Exception as e:
            logger.error(f"Error registering webhook {webhook_config.id}: {e}")
            raise
    
    async def unregister_webhook(self, webhook_id: str) -> bool:
        """Unregister a webhook."""
        
        try:
            # Remove from database
            result = await self.db_optimizer.database["webhooks"].delete_one(
                {"id": webhook_id}
            )
            
            # Remove from cache
            if webhook_id in self.webhooks:
                del self.webhooks[webhook_id]
            
            await self.cache_manager.delete(f"webhook:{webhook_id}")
            
            logger.info(f"Webhook unregistered: {webhook_id}")
            return result.deleted_count > 0
            
        except Exception as e:
            logger.error(f"Error unregistering webhook {webhook_id}: {e}")
            return False
    
    async def update_webhook(self, webhook_id: str, 
                           updates: Dict[str, Any]) -> bool:
        """Update webhook configuration."""
        
        try:
            # Update in database
            result = await self.db_optimizer.database["webhooks"].update_one(
                {"id": webhook_id},
                {"$set": updates}
            )
            
            # Update cache
            if webhook_id in self.webhooks:
                for key, value in updates.items():
                    setattr(self.webhooks[webhook_id], key, value)
                
                await self.cache_manager.set(
                    f"webhook:{webhook_id}",
                    self.webhooks[webhook_id].dict(),
                    ttl=3600
                )
            
            return result.modified_count > 0
            
        except Exception as e:
            logger.error(f"Error updating webhook {webhook_id}: {e}")
            return False
    
    async def trigger_webhook(self, event: WebhookEvent, 
                            data: Dict[str, Any],
                            filters: Optional[Dict[str, Any]] = None) -> int:
        """Trigger webhooks for specific event."""
        
        triggered_count = 0
        
        try:
            # Get webhooks subscribed to this event
            subscribed_webhooks = await self._get_subscribed_webhooks(event)
            
            for webhook in subscribed_webhooks:
                if not webhook.active:
                    continue
                
                # Apply filters if specified
                if filters and not self._match_filters(webhook.filters, filters):
                    continue
                
                # Create delivery record
                delivery_id = self._generate_delivery_id()
                
                payload = WebhookPayload(
                    event=event,
                    timestamp=datetime.utcnow(),
                    data=data,
                    webhook_id=webhook.id,
                    delivery_id=delivery_id
                )
                
                # Add signature if secret is configured
                if webhook.secret:
                    payload.signature = self._generate_signature(
                        payload.dict(), webhook.secret
                    )
                
                # Queue for delivery
                delivery = WebhookDelivery(
                    delivery_id=delivery_id,
                    webhook_id=webhook.id,
                    event=event,
                    payload=payload.dict(),
                    status=WebhookStatus.PENDING
                )
                
                await self.delivery_queue.put((webhook, delivery))
                triggered_count += 1
            
            logger.info(f"Triggered {triggered_count} webhooks for event: {event}")
            return triggered_count
            
        except Exception as e:
            logger.error(f"Error triggering webhooks for event {event}: {e}")
            return 0
    
    async def get_webhook_deliveries(self, webhook_id: str,
                                   limit: int = 50) -> List[WebhookDelivery]:
        """Get delivery history for a webhook."""
        
        try:
            deliveries = await self.db_optimizer.optimize_query(
                "webhook_deliveries",
                {"webhook_id": webhook_id},
                sort=[("created_at", -1)],
                limit=limit
            )
            
            return [WebhookDelivery(**delivery) for delivery in deliveries]
            
        except Exception as e:
            logger.error(f"Error getting deliveries for webhook {webhook_id}: {e}")
            return []
    
    async def retry_failed_delivery(self, delivery_id: str) -> bool:
        """Manually retry a failed delivery."""
        
        try:
            # Get delivery record
            delivery_data = await self.db_optimizer.database["webhook_deliveries"].find_one(
                {"delivery_id": delivery_id}
            )
            
            if not delivery_data:
                return False
            
            delivery = WebhookDelivery(**delivery_data)
            
            # Get webhook config
            webhook = await self._get_webhook_config(delivery.webhook_id)
            if not webhook:
                return False
            
            # Reset status and queue for retry
            delivery.status = WebhookStatus.PENDING
            await self.delivery_queue.put((webhook, delivery))
            
            return True
            
        except Exception as e:
            logger.error(f"Error retrying delivery {delivery_id}: {e}")
            return False
    
    async def _delivery_worker(self):
        """Background worker for webhook deliveries."""
        
        while True:
            try:
                # Get delivery from queue
                webhook, delivery = await self.delivery_queue.get()
                
                # Perform delivery
                await self._deliver_webhook(webhook, delivery)
                
                # Mark queue task as done
                self.delivery_queue.task_done()
                
            except Exception as e:
                logger.error(f"Delivery worker error: {e}")
                await asyncio.sleep(1)
    
    async def _deliver_webhook(self, webhook: WebhookConfig, 
                             delivery: WebhookDelivery):
        """Deliver webhook payload to endpoint."""
        
        try:
            delivery.attempts += 1
            delivery.last_attempt = datetime.utcnow()
            delivery.status = WebhookStatus.RETRYING if delivery.attempts > 1 else WebhookStatus.PENDING
            
            # Prepare headers
            headers = {
                "Content-Type": "application/json",
                "User-Agent": "PhishingDetection-Webhook/1.0",
                "X-Webhook-Event": delivery.event.value,
                "X-Webhook-Delivery": delivery.delivery_id,
                "X-Webhook-Timestamp": str(int(delivery.created_at.timestamp()))
            }
            
            # Add custom headers
            headers.update(webhook.headers)
            
            # Add signature header if present
            if delivery.payload.get("signature"):
                headers["X-Webhook-Signature"] = f"sha256={delivery.payload['signature']}"
            
            # Make HTTP request
            response = await self.http_client.post(
                webhook.url,
                json=delivery.payload,
                headers=headers,
                timeout=webhook.timeout_seconds
            )
            
            delivery.response_status = response.status_code
            delivery.response_body = response.text[:1000]  # Limit response size
            
            # Check if delivery was successful
            if 200 <= response.status_code < 300:
                delivery.status = WebhookStatus.DELIVERED
                logger.info(f"Webhook delivered successfully: {delivery.delivery_id}")
            else:
                delivery.status = WebhookStatus.FAILED
                delivery.error_message = f"HTTP {response.status_code}: {response.text[:200]}"
                logger.warning(f"Webhook delivery failed: {delivery.delivery_id} - {delivery.error_message}")
            
        except Exception as e:
            delivery.status = WebhookStatus.FAILED
            delivery.error_message = str(e)[:500]
            logger.error(f"Webhook delivery error: {delivery.delivery_id} - {e}")
        
        finally:
            # Save delivery record
            await self._save_delivery_record(delivery)
            
            # Schedule retry if needed
            if (delivery.status == WebhookStatus.FAILED and 
                delivery.attempts < webhook.retry_count):
                
                retry_delay = min(300, 30 * (2 ** delivery.attempts))  # Exponential backoff
                delivery.next_retry = datetime.utcnow() + timedelta(seconds=retry_delay)
                
                # Schedule retry
                asyncio.create_task(self._schedule_retry(webhook, delivery, retry_delay))
    
    async def _schedule_retry(self, webhook: WebhookConfig, 
                            delivery: WebhookDelivery, delay: int):
        """Schedule webhook retry after delay."""
        
        await asyncio.sleep(delay)
        
        # Check if webhook is still active
        current_webhook = await self._get_webhook_config(webhook.id)
        if current_webhook and current_webhook.active:
            await self.delivery_queue.put((current_webhook, delivery))
    
    async def _get_subscribed_webhooks(self, event: WebhookEvent) -> List[WebhookConfig]:
        """Get webhooks subscribed to specific event."""
        
        try:
            # Query from database with caching
            webhooks_data = await self.db_optimizer.optimize_query(
                "webhooks",
                {
                    "active": True,
                    "events": {"$in": [event.value]}
                },
                use_cache=True,
                cache_ttl=300
            )
            
            return [WebhookConfig(**webhook) for webhook in webhooks_data]
            
        except Exception as e:
            logger.error(f"Error getting subscribed webhooks for {event}: {e}")
            return []
    
    async def _get_webhook_config(self, webhook_id: str) -> Optional[WebhookConfig]:
        """Get webhook configuration."""
        
        # Try cache first
        if webhook_id in self.webhooks:
            return self.webhooks[webhook_id]
        
        # Try database
        try:
            webhook_data = await self.db_optimizer.database["webhooks"].find_one(
                {"id": webhook_id}
            )
            
            if webhook_data:
                webhook = WebhookConfig(**webhook_data)
                self.webhooks[webhook_id] = webhook
                return webhook
            
        except Exception as e:
            logger.error(f"Error getting webhook config {webhook_id}: {e}")
        
        return None
    
    async def _save_delivery_record(self, delivery: WebhookDelivery):
        """Save webhook delivery record."""
        
        try:
            await self.db_optimizer.database["webhook_deliveries"].update_one(
                {"delivery_id": delivery.delivery_id},
                {"$set": delivery.dict()},
                upsert=True
            )
            
        except Exception as e:
            logger.error(f"Error saving delivery record {delivery.delivery_id}: {e}")
    
    def _match_filters(self, webhook_filters: Dict[str, Any], 
                      event_filters: Dict[str, Any]) -> bool:
        """Check if event matches webhook filters."""
        
        if not webhook_filters:
            return True
        
        for key, expected_value in webhook_filters.items():
            event_value = event_filters.get(key)
            
            if isinstance(expected_value, list):
                if event_value not in expected_value:
                    return False
            elif event_value != expected_value:
                return False
        
        return True
    
    def _generate_delivery_id(self) -> str:
        """Generate unique delivery ID."""
        
        timestamp = str(int(time.time() * 1000))
        random_part = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        return f"wh_del_{timestamp}_{random_part}"
    
    def _generate_signature(self, payload: Dict[str, Any], secret: str) -> str:
        """Generate HMAC signature for webhook payload."""
        
        payload_json = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        signature = hmac.new(
            secret.encode(),
            payload_json.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature

class WebhookValidator:
    """Validate incoming webhook signatures."""
    
    @staticmethod
    def validate_signature(payload: bytes, signature: str, secret: str) -> bool:
        """Validate webhook signature."""
        
        try:
            # Extract signature from header (format: sha256=<signature>)
            if signature.startswith('sha256='):
                signature = signature[7:]
            
            # Generate expected signature
            expected_signature = hmac.new(
                secret.encode(),
                payload,
                hashlib.sha256
            ).hexdigest()
            
            # Compare signatures
            return hmac.compare_digest(signature, expected_signature)
            
        except Exception as e:
            logger.error(f"Signature validation error: {e}")
            return False

# Webhook event helpers
class WebhookEvents:
    """Helper class for triggering common webhook events."""
    
    def __init__(self, webhook_manager: WebhookManager):
        self.webhook_manager = webhook_manager
    
    async def detection_completed(self, detection_result: Dict[str, Any]):
        """Trigger detection completed webhook."""
        
        await self.webhook_manager.trigger_webhook(
            WebhookEvent.DETECTION_COMPLETED,
            detection_result
        )
    
    async def phishing_detected(self, detection_result: Dict[str, Any]):
        """Trigger phishing detected webhook."""
        
        if detection_result.get("is_phishing") and detection_result.get("confidence", 0) > 0.7:
            await self.webhook_manager.trigger_webhook(
                WebhookEvent.PHISHING_DETECTED,
                detection_result,
                filters={"is_phishing": True, "high_confidence": True}
            )
    
    async def threat_intelligence_update(self, threat_data: Dict[str, Any]):
        """Trigger threat intelligence update webhook."""
        
        await self.webhook_manager.trigger_webhook(
            WebhookEvent.THREAT_INTELLIGENCE_UPDATE,
            threat_data
        )
    
    async def security_alert(self, alert_data: Dict[str, Any]):
        """Trigger security alert webhook."""
        
        await self.webhook_manager.trigger_webhook(
            WebhookEvent.SECURITY_ALERT,
            alert_data,
            filters={"severity": alert_data.get("severity")}
        )
    
    async def bulk_job_completed(self, job_data: Dict[str, Any]):
        """Trigger bulk job completed webhook."""
        
        await self.webhook_manager.trigger_webhook(
            WebhookEvent.BULK_JOB_COMPLETED,
            job_data
        )

# Global webhook manager instance
webhook_manager: Optional[WebhookManager] = None
webhook_events: Optional[WebhookEvents] = None

def initialize_webhook_system(db_optimizer: DatabaseOptimizer, 
                            cache_manager: CacheManager):
    """Initialize global webhook system."""
    
    global webhook_manager, webhook_events
    
    webhook_manager = WebhookManager(db_optimizer, cache_manager)
    webhook_events = WebhookEvents(webhook_manager)
    
    logger.info("Webhook system initialized")