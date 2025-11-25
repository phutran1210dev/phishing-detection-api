"""SIEM/SOAR integration module for enterprise security platforms."""

import asyncio
import json
import aiohttp
from typing import Dict, List, Any, Optional, Union
from datetime import datetime
from enum import Enum
from pydantic import BaseModel, Field
from loguru import logger

class SIEMPlatform(str, Enum):
    """Supported SIEM platforms."""
    SPLUNK = "splunk"
    ELASTIC = "elastic"
    QRadar = "qradar"
    SENTINEL = "sentinel"
    CHRONICLE = "chronicle"

class SOARPlatform(str, Enum):
    """Supported SOAR platforms."""
    PHANTOM = "phantom"
    DEMISTO = "demisto"
    SIEMPLIFY = "siemplify"
    SWIMLANE = "swimlane"
    RESILIENT = "resilient"

class AlertSeverity(str, Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class SecurityEvent(BaseModel):
    """Security event model for SIEM integration."""
    
    event_id: str = Field(..., description="Unique event identifier")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    severity: AlertSeverity = Field(..., description="Event severity")
    
    # Event details
    event_type: str = Field(..., description="Type of security event")
    source_ip: Optional[str] = None
    user_id: Optional[str] = None
    url: Optional[str] = None
    
    # Detection details
    confidence: float = Field(..., ge=0.0, le=1.0)
    threat_indicators: List[str] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    
    # Additional data
    metadata: Dict[str, Any] = Field(default_factory=dict)
    raw_data: Dict[str, Any] = Field(default_factory=dict)

class IncidentResponse(BaseModel):
    """SOAR incident response model."""
    
    incident_id: str = Field(..., description="Unique incident identifier")
    title: str = Field(..., description="Incident title")
    description: str = Field(..., description="Incident description")
    
    severity: AlertSeverity = Field(..., description="Incident severity")
    status: str = Field(default="new", description="Incident status")
    
    # Response details
    assigned_to: Optional[str] = None
    playbook_id: Optional[str] = None
    actions_taken: List[str] = Field(default_factory=list)
    
    # Timing
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Related events
    related_events: List[str] = Field(default_factory=list)
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)

class SIEMIntegration:
    """Base class for SIEM integrations."""
    
    def __init__(self, platform: SIEMPlatform, config: Dict[str, Any]):
        self.platform = platform
        self.config = config
        self.session = None
        
    async def initialize(self):
        """Initialize SIEM connection."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
    
    async def close(self):
        """Close SIEM connection."""
        if self.session:
            await self.session.close()
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send security event to SIEM."""
        raise NotImplementedError
    
    async def query_events(self, query: str, 
                         start_time: datetime,
                         end_time: datetime) -> List[Dict[str, Any]]:
        """Query events from SIEM."""
        raise NotImplementedError

class SplunkIntegration(SIEMIntegration):
    """Splunk SIEM integration."""
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send event to Splunk HEC (HTTP Event Collector)."""
        
        try:
            hec_url = f"{self.config['url']}/services/collector/event"
            headers = {
                "Authorization": f"Splunk {self.config['hec_token']}",
                "Content-Type": "application/json"
            }
            
            # Format event for Splunk
            splunk_event = {
                "time": int(event.timestamp.timestamp()),
                "source": "phishing-detection-api",
                "sourcetype": "phishing:detection",
                "index": self.config.get("index", "security"),
                "event": {
                    "event_id": event.event_id,
                    "severity": event.severity.value,
                    "event_type": event.event_type,
                    "confidence": event.confidence,
                    "source_ip": event.source_ip,
                    "user_id": event.user_id,
                    "url": event.url,
                    "threat_indicators": event.threat_indicators,
                    "mitre_tactics": event.mitre_tactics,
                    "metadata": event.metadata
                }
            }
            
            async with self.session.post(hec_url, headers=headers, 
                                       json=splunk_event) as response:
                if response.status == 200:
                    logger.info(f"Successfully sent event {event.event_id} to Splunk")
                    return True
                else:
                    logger.error(f"Failed to send event to Splunk: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending event to Splunk: {e}")
            return False
    
    async def query_events(self, query: str, 
                         start_time: datetime,
                         end_time: datetime) -> List[Dict[str, Any]]:
        """Query events from Splunk."""
        
        try:
            search_url = f"{self.config['url']}/services/search/jobs/export"
            headers = {
                "Authorization": f"Splunk {self.config['auth_token']}",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            search_query = f"""
                search {query}
                | where _time >= {int(start_time.timestamp())} 
                  AND _time <= {int(end_time.timestamp())}
                | head 1000
            """
            
            data = {
                "search": search_query,
                "output_mode": "json",
                "earliest_time": start_time.isoformat(),
                "latest_time": end_time.isoformat()
            }
            
            async with self.session.post(search_url, headers=headers, 
                                       data=data) as response:
                if response.status == 200:
                    results = []
                    async for line in response.content:
                        if line.strip():
                            results.append(json.loads(line))
                    return results
                else:
                    logger.error(f"Failed to query Splunk: {response.status}")
                    return []
                    
        except Exception as e:
            logger.error(f"Error querying Splunk: {e}")
            return []

class ElasticIntegration(SIEMIntegration):
    """Elastic SIEM integration."""
    
    async def send_event(self, event: SecurityEvent) -> bool:
        """Send event to Elasticsearch."""
        
        try:
            index_url = f"{self.config['url']}/{self.config.get('index', 'security-events')}/_doc"
            headers = {
                "Content-Type": "application/json"
            }
            
            # Add authentication
            if "username" in self.config and "password" in self.config:
                auth = aiohttp.BasicAuth(self.config["username"], 
                                       self.config["password"])
            else:
                auth = None
            
            # Format event for Elasticsearch
            elastic_event = {
                "@timestamp": event.timestamp.isoformat(),
                "event": {
                    "id": event.event_id,
                    "type": [event.event_type],
                    "category": ["threat"],
                    "severity": event.severity.value
                },
                "threat": {
                    "indicator": {
                        "type": "url" if event.url else "unknown",
                        "confidence": event.confidence
                    }
                },
                "source": {
                    "ip": event.source_ip
                },
                "user": {
                    "id": event.user_id
                },
                "url": {
                    "original": event.url
                },
                "phishing": {
                    "indicators": event.threat_indicators,
                    "mitre_tactics": event.mitre_tactics,
                    "metadata": event.metadata
                }
            }
            
            async with self.session.post(index_url, headers=headers, 
                                       json=elastic_event, auth=auth) as response:
                if response.status in [200, 201]:
                    logger.info(f"Successfully sent event {event.event_id} to Elasticsearch")
                    return True
                else:
                    logger.error(f"Failed to send event to Elasticsearch: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error sending event to Elasticsearch: {e}")
            return False

class SOARIntegration:
    """Base class for SOAR integrations."""
    
    def __init__(self, platform: SOARPlatform, config: Dict[str, Any]):
        self.platform = platform
        self.config = config
        self.session = None
    
    async def initialize(self):
        """Initialize SOAR connection."""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30)
        )
    
    async def close(self):
        """Close SOAR connection."""
        if self.session:
            await self.session.close()
    
    async def create_incident(self, incident: IncidentResponse) -> str:
        """Create incident in SOAR platform."""
        raise NotImplementedError
    
    async def update_incident(self, incident_id: str, 
                            updates: Dict[str, Any]) -> bool:
        """Update incident in SOAR platform."""
        raise NotImplementedError
    
    async def execute_playbook(self, playbook_id: str, 
                             incident_id: str,
                             parameters: Dict[str, Any] = None) -> bool:
        """Execute playbook for incident."""
        raise NotImplementedError

class PhantomIntegration(SOARIntegration):
    """Phantom (Splunk SOAR) integration."""
    
    async def create_incident(self, incident: IncidentResponse) -> str:
        """Create incident in Phantom."""
        
        try:
            incident_url = f"{self.config['url']}/rest/container"
            headers = {
                "ph-auth-token": self.config["auth_token"],
                "Content-Type": "application/json"
            }
            
            # Format incident for Phantom
            phantom_incident = {
                "name": incident.title,
                "description": incident.description,
                "severity": incident.severity.value,
                "status": incident.status,
                "label": self.config.get("label", "phishing"),
                "source_data_identifier": incident.incident_id,
                "data": {
                    "assigned_to": incident.assigned_to,
                    "related_events": incident.related_events,
                    "artifacts": incident.artifacts
                }
            }
            
            async with self.session.post(incident_url, headers=headers, 
                                       json=phantom_incident) as response:
                if response.status == 200:
                    result = await response.json()
                    phantom_id = str(result.get("id"))
                    logger.info(f"Created Phantom incident: {phantom_id}")
                    return phantom_id
                else:
                    logger.error(f"Failed to create Phantom incident: {response.status}")
                    return ""
                    
        except Exception as e:
            logger.error(f"Error creating Phantom incident: {e}")
            return ""
    
    async def execute_playbook(self, playbook_id: str, 
                             incident_id: str,
                             parameters: Dict[str, Any] = None) -> bool:
        """Execute playbook in Phantom."""
        
        try:
            playbook_url = f"{self.config['url']}/rest/playbook_run"
            headers = {
                "ph-auth-token": self.config["auth_token"],
                "Content-Type": "application/json"
            }
            
            playbook_data = {
                "playbook_id": int(playbook_id),
                "container_id": int(incident_id),
                "scope": "all",
                "run": True
            }
            
            if parameters:
                playbook_data["parameters"] = parameters
            
            async with self.session.post(playbook_url, headers=headers, 
                                       json=playbook_data) as response:
                if response.status == 200:
                    logger.info(f"Executed playbook {playbook_id} for incident {incident_id}")
                    return True
                else:
                    logger.error(f"Failed to execute Phantom playbook: {response.status}")
                    return False
                    
        except Exception as e:
            logger.error(f"Error executing Phantom playbook: {e}")
            return False

class SecurityOrchestrator:
    """Main security orchestrator for SIEM/SOAR integrations."""
    
    def __init__(self):
        self.siem_integrations: Dict[str, SIEMIntegration] = {}
        self.soar_integrations: Dict[str, SOARIntegration] = {}
        self.event_buffer: List[SecurityEvent] = []
        self.buffer_size = 100
        
    async def initialize(self):
        """Initialize all integrations."""
        for integration in self.siem_integrations.values():
            await integration.initialize()
        
        for integration in self.soar_integrations.values():
            await integration.initialize()
        
        logger.info("Security orchestrator initialized")
    
    async def close(self):
        """Close all integrations."""
        for integration in self.siem_integrations.values():
            await integration.close()
        
        for integration in self.soar_integrations.values():
            await integration.close()
    
    def add_siem_integration(self, name: str, integration: SIEMIntegration):
        """Add SIEM integration."""
        self.siem_integrations[name] = integration
        logger.info(f"Added SIEM integration: {name}")
    
    def add_soar_integration(self, name: str, integration: SOARIntegration):
        """Add SOAR integration."""
        self.soar_integrations[name] = integration
        logger.info(f"Added SOAR integration: {name}")
    
    async def send_security_event(self, event: SecurityEvent):
        """Send security event to all SIEM platforms."""
        
        tasks = []
        for name, integration in self.siem_integrations.items():
            task = asyncio.create_task(
                self._send_to_siem(name, integration, event)
            )
            tasks.append(task)
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in results if r is True)
            logger.info(f"Sent event {event.event_id} to {success_count}/{len(tasks)} SIEM platforms")
    
    async def _send_to_siem(self, name: str, integration: SIEMIntegration, 
                          event: SecurityEvent) -> bool:
        """Send event to specific SIEM integration."""
        
        try:
            return await integration.send_event(event)
        except Exception as e:
            logger.error(f"Error sending to SIEM {name}: {e}")
            return False
    
    async def create_security_incident(self, incident: IncidentResponse) -> Dict[str, str]:
        """Create incident in all SOAR platforms."""
        
        results = {}
        
        for name, integration in self.soar_integrations.items():
            try:
                incident_id = await integration.create_incident(incident)
                if incident_id:
                    results[name] = incident_id
                    logger.info(f"Created incident {incident_id} in SOAR {name}")
                else:
                    logger.warning(f"Failed to create incident in SOAR {name}")
            
            except Exception as e:
                logger.error(f"Error creating incident in SOAR {name}: {e}")
        
        return results
    
    async def execute_response_playbook(self, soar_name: str, 
                                      playbook_id: str,
                                      incident_id: str,
                                      parameters: Dict[str, Any] = None) -> bool:
        """Execute response playbook in specific SOAR platform."""
        
        if soar_name not in self.soar_integrations:
            logger.error(f"SOAR integration {soar_name} not found")
            return False
        
        integration = self.soar_integrations[soar_name]
        
        try:
            return await integration.execute_playbook(
                playbook_id, incident_id, parameters
            )
        except Exception as e:
            logger.error(f"Error executing playbook in {soar_name}: {e}")
            return False
    
    async def process_phishing_detection(self, url: str, 
                                       prediction: Dict[str, Any],
                                       source_ip: Optional[str] = None,
                                       user_id: Optional[str] = None):
        """Process phishing detection and create security events/incidents."""
        
        confidence = prediction.get("confidence", 0.0)
        is_phishing = prediction.get("is_phishing", False)
        
        if not is_phishing:
            return
        
        # Determine severity based on confidence
        if confidence >= 0.9:
            severity = AlertSeverity.CRITICAL
        elif confidence >= 0.7:
            severity = AlertSeverity.HIGH
        elif confidence >= 0.5:
            severity = AlertSeverity.MEDIUM
        else:
            severity = AlertSeverity.LOW
        
        # Create security event
        event = SecurityEvent(
            event_id=f"phishing_{int(datetime.utcnow().timestamp())}",
            severity=severity,
            event_type="phishing_detection",
            source_ip=source_ip,
            user_id=user_id,
            url=url,
            confidence=confidence,
            threat_indicators=prediction.get("indicators", []),
            mitre_tactics=["T1566.002"],  # Phishing: Spearphishing Link
            metadata={
                "detection_engine": "ml_ensemble",
                "features": prediction.get("features", {}),
                "model_version": prediction.get("model_version", "1.0")
            }
        )
        
        # Send to SIEM
        await self.send_security_event(event)
        
        # Create incident for high/critical severity
        if severity in [AlertSeverity.HIGH, AlertSeverity.CRITICAL]:
            incident = IncidentResponse(
                incident_id=f"phishing_incident_{int(datetime.utcnow().timestamp())}",
                title=f"Phishing Detection: {url}",
                description=f"High-confidence phishing URL detected with {confidence:.2%} confidence",
                severity=severity,
                related_events=[event.event_id],
                artifacts=[
                    {"type": "url", "value": url},
                    {"type": "confidence", "value": confidence}
                ]
            )
            
            # Create incident in SOAR
            incident_ids = await self.create_security_incident(incident)
            
            # Execute automated response playbooks
            for soar_name, incident_id in incident_ids.items():
                if severity == AlertSeverity.CRITICAL:
                    # Execute immediate response playbook
                    await self.execute_response_playbook(
                        soar_name, "phishing_immediate_response", incident_id,
                        {"url": url, "confidence": confidence}
                    )

# Global security orchestrator
security_orchestrator: Optional[SecurityOrchestrator] = None

async def initialize_security_orchestrator(config: Dict[str, Any]):
    """Initialize global security orchestrator with configurations."""
    
    global security_orchestrator
    
    security_orchestrator = SecurityOrchestrator()
    
    # Initialize SIEM integrations
    if "siem" in config:
        for name, siem_config in config["siem"].items():
            platform = SIEMPlatform(siem_config["platform"])
            
            if platform == SIEMPlatform.SPLUNK:
                integration = SplunkIntegration(platform, siem_config)
            elif platform == SIEMPlatform.ELASTIC:
                integration = ElasticIntegration(platform, siem_config)
            else:
                logger.warning(f"SIEM platform {platform} not implemented")
                continue
            
            security_orchestrator.add_siem_integration(name, integration)
    
    # Initialize SOAR integrations
    if "soar" in config:
        for name, soar_config in config["soar"].items():
            platform = SOARPlatform(soar_config["platform"])
            
            if platform == SOARPlatform.PHANTOM:
                integration = PhantomIntegration(platform, soar_config)
            else:
                logger.warning(f"SOAR platform {platform} not implemented")
                continue
            
            security_orchestrator.add_soar_integration(name, integration)
    
    await security_orchestrator.initialize()
    logger.info("Security orchestrator initialized with integrations")