"""Real-time threat intelligence and monitoring system."""

import asyncio
import aiohttp
import json
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import websockets
from loguru import logger
from dataclasses import dataclass
from enum import Enum
import hashlib
from collections import defaultdict

class ThreatLevel(Enum):
    """Threat severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatIntelligence:
    """Threat intelligence data structure."""
    source: str
    threat_type: str
    indicator: str
    confidence: float
    threat_level: ThreatLevel
    timestamp: datetime
    metadata: Dict[str, Any]

@dataclass
class Alert:
    """Security alert data structure."""
    id: str
    title: str
    description: str
    threat_level: ThreatLevel
    source_url: str
    confidence: float
    timestamp: datetime
    indicators: List[str]
    mitigation: Optional[str] = None
    
class ThreatIntelligenceFeeds:
    """Manage multiple threat intelligence feeds."""
    
    def __init__(self):
        self.feeds = {}
        self.threat_cache = defaultdict(list)
        self.feed_configs = {
            'phishtank': {
                'url': 'http://data.phishtank.com/data/online-valid.json',
                'update_interval': 3600,  # 1 hour
                'parser': self._parse_phishtank_feed
            },
            'openphish': {
                'url': 'https://openphish.com/feed.txt',
                'update_interval': 1800,  # 30 minutes
                'parser': self._parse_openphish_feed
            },
            'urlvoid': {
                'url': 'https://www.urlvoid.com/api1000/host/{domain}/stats/',
                'update_interval': 7200,  # 2 hours
                'parser': self._parse_urlvoid_feed
            }
        }
        self.session: Optional[aiohttp.ClientSession] = None
        self.running = False
        
    async def start_feeds(self):
        """Start all threat intelligence feeds."""
        
        logger.info("Starting threat intelligence feeds")
        
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=30),
            headers={'User-Agent': 'PhishingDetectionAPI/1.0'}
        )
        
        self.running = True
        
        # Start feed update tasks
        tasks = []
        for feed_name, config in self.feed_configs.items():
            task = asyncio.create_task(self._update_feed_loop(feed_name, config))
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def stop_feeds(self):
        """Stop all threat intelligence feeds."""
        
        self.running = False
        
        if self.session:
            await self.session.close()
        
        logger.info("Threat intelligence feeds stopped")
    
    async def _update_feed_loop(self, feed_name: str, config: Dict[str, Any]):
        """Continuously update a specific threat feed."""
        
        while self.running:
            try:
                await self._update_single_feed(feed_name, config)
                await asyncio.sleep(config['update_interval'])
                
            except Exception as e:
                logger.error(f"Error updating feed {feed_name}: {e}")
                await asyncio.sleep(300)  # Wait 5 minutes on error
    
    async def _update_single_feed(self, feed_name: str, config: Dict[str, Any]):
        """Update a single threat intelligence feed."""
        
        try:
            logger.info(f"Updating threat feed: {feed_name}")
            
            async with self.session.get(config['url']) as response:
                if response.status == 200:
                    content = await response.text()
                    threats = await config['parser'](content)
                    
                    # Update cache
                    self.threat_cache[feed_name] = threats
                    
                    logger.info(f"Updated {feed_name}: {len(threats)} threats loaded")
                else:
                    logger.warning(f"Failed to update {feed_name}: HTTP {response.status}")
                    
        except Exception as e:
            logger.error(f"Exception updating {feed_name}: {e}")
    
    async def _parse_phishtank_feed(self, content: str) -> List[ThreatIntelligence]:
        """Parse PhishTank JSON feed."""
        
        threats = []
        
        try:
            data = json.loads(content)
            
            for entry in data:
                threat = ThreatIntelligence(
                    source='phishtank',
                    threat_type='phishing',
                    indicator=entry['url'],
                    confidence=0.9 if entry['verified'] == 'yes' else 0.6,
                    threat_level=ThreatLevel.HIGH if entry['verified'] == 'yes' else ThreatLevel.MEDIUM,
                    timestamp=datetime.utcnow(),
                    metadata={
                        'phish_id': entry['phish_id'],
                        'target': entry.get('target', ''),
                        'verified': entry['verified'],
                        'submission_time': entry['submission_time']
                    }
                )
                threats.append(threat)
                
        except Exception as e:
            logger.error(f"Error parsing PhishTank feed: {e}")
        
        return threats
    
    async def _parse_openphish_feed(self, content: str) -> List[ThreatIntelligence]:
        """Parse OpenPhish text feed."""
        
        threats = []
        
        try:
            urls = content.strip().split('\\n')
            
            for url in urls[:1000]:  # Limit to 1000 URLs
                if url.strip():
                    threat = ThreatIntelligence(
                        source='openphish',
                        threat_type='phishing',
                        indicator=url.strip(),
                        confidence=0.8,
                        threat_level=ThreatLevel.HIGH,
                        timestamp=datetime.utcnow(),
                        metadata={'feed': 'openphish'}
                    )
                    threats.append(threat)
                    
        except Exception as e:
            logger.error(f"Error parsing OpenPhish feed: {e}")
        
        return threats
    
    async def _parse_urlvoid_feed(self, content: str) -> List[ThreatIntelligence]:
        """Parse URLVoid API response (placeholder)."""
        
        # This would be implemented with actual URLVoid API integration
        threats = []
        
        return threats
    
    async def check_url_threats(self, url: str) -> Dict[str, Any]:
        """Check if a URL appears in threat intelligence feeds."""
        
        threat_matches = []
        
        for feed_name, threats in self.threat_cache.items():
            for threat in threats:
                if threat.indicator == url or url in threat.indicator:
                    threat_matches.append({
                        'source': threat.source,
                        'threat_type': threat.threat_type,
                        'confidence': threat.confidence,
                        'threat_level': threat.threat_level.value,
                        'timestamp': threat.timestamp.isoformat(),
                        'metadata': threat.metadata
                    })
        
        return {
            'url': url,
            'threat_found': len(threat_matches) > 0,
            'threat_count': len(threat_matches),
            'threats': threat_matches,
            'max_threat_level': max(
                [ThreatLevel(t['threat_level']) for t in threat_matches],
                default=ThreatLevel.LOW,
                key=lambda x: ['low', 'medium', 'high', 'critical'].index(x.value)
            ).value if threat_matches else 'none'
        }
    
    def get_feed_status(self) -> Dict[str, Any]:
        """Get status of all threat intelligence feeds."""
        
        return {
            'feeds': {
                feed_name: {
                    'threat_count': len(self.threat_cache.get(feed_name, [])),
                    'last_update': max(
                        [t.timestamp for t in self.threat_cache.get(feed_name, [])],
                        default=None
                    ),
                    'config': config
                }
                for feed_name, config in self.feed_configs.items()
            },
            'total_threats': sum(len(threats) for threats in self.threat_cache.values()),
            'running': self.running
        }

class RealTimeAlertSystem:
    """Real-time alerting system for security events."""
    
    def __init__(self):
        self.alert_rules = []
        self.active_alerts = {}
        self.alert_history = []
        self.subscribers = set()  # WebSocket connections
        self.notification_channels = {}
        
    def add_alert_rule(self, rule_name: str, condition: Dict[str, Any], 
                      actions: List[str]):
        """Add a new alert rule."""
        
        rule = {
            'name': rule_name,
            'condition': condition,
            'actions': actions,
            'created_at': datetime.utcnow(),
            'enabled': True,
            'trigger_count': 0
        }
        
        self.alert_rules.append(rule)
        logger.info(f"Alert rule added: {rule_name}")
    
    async def process_detection_result(self, detection_data: Dict[str, Any]):
        """Process detection result and trigger alerts if needed."""
        
        for rule in self.alert_rules:
            if not rule['enabled']:
                continue
                
            if await self._evaluate_rule_condition(rule['condition'], detection_data):
                await self._trigger_alert(rule, detection_data)
    
    async def _evaluate_rule_condition(self, condition: Dict[str, Any], 
                                     data: Dict[str, Any]) -> bool:
        """Evaluate if alert rule condition is met."""
        
        try:
            # Example conditions
            if 'probability_threshold' in condition:
                if data.get('probability', 0) >= condition['probability_threshold']:
                    return True
            
            if 'threat_level' in condition:
                if data.get('threat_level') == condition['threat_level']:
                    return True
            
            if 'domain_in_blacklist' in condition:
                domain = data.get('domain', '')
                if domain in condition['domain_in_blacklist']:
                    return True
            
            if 'multiple_detections' in condition:
                # Check for multiple detections from same source
                threshold = condition['multiple_detections']['count']
                timeframe = condition['multiple_detections']['timeframe_minutes']
                
                cutoff_time = datetime.utcnow() - timedelta(minutes=timeframe)
                recent_alerts = [
                    alert for alert in self.alert_history
                    if alert['timestamp'] > cutoff_time and 
                       alert['source_ip'] == data.get('source_ip')
                ]
                
                if len(recent_alerts) >= threshold:
                    return True
            
        except Exception as e:
            logger.error(f"Error evaluating alert condition: {e}")
        
        return False
    
    async def _trigger_alert(self, rule: Dict[str, Any], detection_data: Dict[str, Any]):
        """Trigger an alert based on rule and detection data."""
        
        alert_id = hashlib.md5(
            f"{rule['name']}_{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]
        
        alert = Alert(
            id=alert_id,
            title=f"Security Alert: {rule['name']}",
            description=f"Alert triggered by rule '{rule['name']}'",
            threat_level=ThreatLevel(detection_data.get('threat_level', 'medium')),
            source_url=detection_data.get('url', ''),
            confidence=detection_data.get('probability', 0.5),
            timestamp=datetime.utcnow(),
            indicators=[detection_data.get('url', '')],
            mitigation="Review and block if confirmed malicious"
        )
        
        # Store alert
        self.active_alerts[alert_id] = alert
        self.alert_history.append({
            'alert_id': alert_id,
            'rule_name': rule['name'],
            'timestamp': alert.timestamp,
            'threat_level': alert.threat_level.value,
            'source_ip': detection_data.get('source_ip'),
            'url': detection_data.get('url')
        })
        
        # Update rule trigger count
        rule['trigger_count'] += 1
        
        logger.warning(f"Alert triggered: {alert.title} (ID: {alert_id})")
        
        # Execute alert actions
        for action in rule['actions']:
            await self._execute_alert_action(action, alert, detection_data)
    
    async def _execute_alert_action(self, action: str, alert: Alert, 
                                   detection_data: Dict[str, Any]):
        """Execute alert action."""
        
        try:
            if action == 'websocket_notify':
                await self._send_websocket_alert(alert)
            
            elif action == 'email_notify':
                await self._send_email_alert(alert)
            
            elif action == 'slack_notify':
                await self._send_slack_alert(alert)
            
            elif action == 'log_alert':
                logger.critical(f"SECURITY ALERT: {alert.title} - {alert.description}")
            
            elif action == 'block_ip':
                await self._block_ip_address(detection_data.get('source_ip'))
            
        except Exception as e:
            logger.error(f"Error executing alert action {action}: {e}")
    
    async def _send_websocket_alert(self, alert: Alert):
        """Send alert to WebSocket subscribers."""
        
        alert_message = {
            'type': 'security_alert',
            'alert_id': alert.id,
            'title': alert.title,
            'description': alert.description,
            'threat_level': alert.threat_level.value,
            'confidence': alert.confidence,
            'timestamp': alert.timestamp.isoformat(),
            'indicators': alert.indicators
        }
        
        # Send to all subscribers
        disconnected = set()
        for websocket in self.subscribers:
            try:
                await websocket.send(json.dumps(alert_message))
            except:
                disconnected.add(websocket)
        
        # Remove disconnected subscribers
        self.subscribers -= disconnected
    
    async def _send_email_alert(self, alert: Alert):
        """Send email alert (placeholder)."""
        
        # This would integrate with email service (SendGrid, etc.)
        logger.info(f"Email alert sent: {alert.title}")
    
    async def _send_slack_alert(self, alert: Alert):
        """Send Slack alert (placeholder)."""
        
        # This would integrate with Slack webhook
        logger.info(f"Slack alert sent: {alert.title}")
    
    async def _block_ip_address(self, ip_address: str):
        """Block IP address (placeholder)."""
        
        # This would integrate with firewall/WAF
        logger.info(f"IP blocked: {ip_address}")
    
    async def add_websocket_subscriber(self, websocket):
        """Add WebSocket subscriber for real-time alerts."""
        
        self.subscribers.add(websocket)
        logger.info("WebSocket subscriber added")
    
    def get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get all active alerts."""
        
        return [
            {
                'id': alert.id,
                'title': alert.title,
                'description': alert.description,
                'threat_level': alert.threat_level.value,
                'confidence': alert.confidence,
                'timestamp': alert.timestamp.isoformat(),
                'indicators': alert.indicators,
                'mitigation': alert.mitigation
            }
            for alert in self.active_alerts.values()
        ]
    
    def acknowledge_alert(self, alert_id: str, user: str) -> bool:
        """Acknowledge an alert."""
        
        if alert_id in self.active_alerts:
            del self.active_alerts[alert_id]
            logger.info(f"Alert {alert_id} acknowledged by {user}")
            return True
        
        return False
    
    def get_alert_statistics(self) -> Dict[str, Any]:
        """Get alert statistics."""
        
        # Recent alerts (last 24 hours)
        cutoff_time = datetime.utcnow() - timedelta(hours=24)
        recent_alerts = [
            alert for alert in self.alert_history
            if alert['timestamp'] > cutoff_time
        ]
        
        # Group by threat level
        by_threat_level = defaultdict(int)
        for alert in recent_alerts:
            by_threat_level[alert['threat_level']] += 1
        
        # Group by rule
        by_rule = defaultdict(int)
        for alert in recent_alerts:
            by_rule[alert['rule_name']] += 1
        
        return {
            'total_alerts_24h': len(recent_alerts),
            'active_alerts': len(self.active_alerts),
            'by_threat_level': dict(by_threat_level),
            'by_rule': dict(by_rule),
            'total_rules': len(self.alert_rules),
            'enabled_rules': len([r for r in self.alert_rules if r['enabled']])
        }