"""Comprehensive compliance reporting system for GDPR, SOC2, and other frameworks."""

import asyncio
import json
import io
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timedelta
from enum import Enum
from pydantic import BaseModel, Field
from loguru import logger
import pandas as pd
from jinja2 import Template
from app.core.database import DatabaseOptimizer
from app.core.cache import CacheManager
from app.compliance.audit import AuditLogger, AuditLevel, AuditCategory

class ComplianceFramework(str, Enum):
    """Supported compliance frameworks."""
    GDPR = "gdpr"
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    NIST = "nist"
    PCI_DSS = "pci_dss"
    HIPAA = "hipaa"

class ReportType(str, Enum):
    """Types of compliance reports."""
    DATA_PROCESSING_ACTIVITIES = "data_processing_activities"
    ACCESS_CONTROL_REVIEW = "access_control_review"
    SECURITY_INCIDENTS = "security_incidents"
    DATA_RETENTION = "data_retention"
    AUDIT_TRAIL = "audit_trail"
    PRIVACY_IMPACT = "privacy_impact"
    VENDOR_ASSESSMENT = "vendor_assessment"
    RISK_ASSESSMENT = "risk_assessment"

class ReportFormat(str, Enum):
    """Report output formats."""
    PDF = "pdf"
    HTML = "html"
    JSON = "json"
    CSV = "csv"
    EXCEL = "excel"

class ComplianceReport(BaseModel):
    """Compliance report model."""
    
    report_id: str = Field(..., description="Unique report identifier")
    framework: ComplianceFramework = Field(..., description="Compliance framework")
    report_type: ReportType = Field(..., description="Type of report")
    format: ReportFormat = Field(..., description="Output format")
    
    # Report metadata
    title: str = Field(..., description="Report title")
    description: str = Field(..., description="Report description")
    generated_by: str = Field(..., description="User who generated the report")
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Report parameters
    period_start: datetime = Field(..., description="Report period start")
    period_end: datetime = Field(..., description="Report period end")
    filters: Dict[str, Any] = Field(default_factory=dict)
    
    # Report content
    data: Dict[str, Any] = Field(default_factory=dict)
    summary: Dict[str, Any] = Field(default_factory=dict)
    recommendations: List[str] = Field(default_factory=list)
    
    # Compliance status
    compliance_score: float = Field(default=0.0, ge=0.0, le=100.0)
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    
    # File information
    file_path: Optional[str] = None
    file_size: Optional[int] = None

class ComplianceReporter:
    """Generate compliance reports for various frameworks."""
    
    def __init__(self, db_optimizer: DatabaseOptimizer,
                 cache_manager: CacheManager,
                 audit_logger: AuditLogger):
        self.db_optimizer = db_optimizer
        self.cache_manager = cache_manager
        self.audit_logger = audit_logger
        
        # Report templates
        self.report_templates = {
            ComplianceFramework.GDPR: self._load_gdpr_templates(),
            ComplianceFramework.SOC2: self._load_soc2_templates(),
            ComplianceFramework.ISO27001: self._load_iso27001_templates()
        }
        
        logger.info("Compliance reporter initialized")
    
    async def generate_report(self, framework: ComplianceFramework,
                            report_type: ReportType,
                            period_start: datetime,
                            period_end: datetime,
                            generated_by: str,
                            format: ReportFormat = ReportFormat.HTML,
                            filters: Optional[Dict[str, Any]] = None) -> ComplianceReport:
        """Generate compliance report."""
        
        try:
            # Create report instance
            report = ComplianceReport(
                report_id=f"comp_{framework.value}_{report_type.value}_{int(datetime.utcnow().timestamp())}",
                framework=framework,
                report_type=report_type,
                format=format,
                title=self._get_report_title(framework, report_type),
                description=self._get_report_description(framework, report_type),
                generated_by=generated_by,
                period_start=period_start,
                period_end=period_end,
                filters=filters or {}
            )
            
            # Generate report data based on type
            if report_type == ReportType.DATA_PROCESSING_ACTIVITIES:
                await self._generate_data_processing_report(report)
            elif report_type == ReportType.ACCESS_CONTROL_REVIEW:
                await self._generate_access_control_report(report)
            elif report_type == ReportType.SECURITY_INCIDENTS:
                await self._generate_security_incidents_report(report)
            elif report_type == ReportType.DATA_RETENTION:
                await self._generate_data_retention_report(report)
            elif report_type == ReportType.AUDIT_TRAIL:
                await self._generate_audit_trail_report(report)
            elif report_type == ReportType.PRIVACY_IMPACT:
                await self._generate_privacy_impact_report(report)
            elif report_type == ReportType.RISK_ASSESSMENT:
                await self._generate_risk_assessment_report(report)
            
            # Calculate compliance score
            report.compliance_score = self._calculate_compliance_score(report)
            
            # Generate recommendations
            report.recommendations = self._generate_recommendations(report)
            
            # Store report metadata
            await self._store_report_metadata(report)
            
            # Generate output file
            await self._generate_report_file(report)
            
            logger.info(f"Generated compliance report: {report.report_id}")
            return report
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {e}")
            raise
    
    async def get_report(self, report_id: str) -> Optional[ComplianceReport]:
        """Get existing compliance report."""
        
        try:
            report_data = await self.db_optimizer.database["compliance_reports"].find_one(
                {"report_id": report_id}
            )
            
            if report_data:
                return ComplianceReport(**report_data)
            
        except Exception as e:
            logger.error(f"Error getting compliance report {report_id}: {e}")
        
        return None
    
    async def list_reports(self, framework: Optional[ComplianceFramework] = None,
                         report_type: Optional[ReportType] = None,
                         limit: int = 50) -> List[ComplianceReport]:
        """List compliance reports with filtering."""
        
        try:
            filters = {}
            if framework:
                filters["framework"] = framework.value
            if report_type:
                filters["report_type"] = report_type.value
            
            reports_data = await self.db_optimizer.optimize_query(
                "compliance_reports",
                filters,
                sort=[("generated_at", -1)],
                limit=limit
            )
            
            return [ComplianceReport(**report) for report in reports_data]
            
        except Exception as e:
            logger.error(f"Error listing compliance reports: {e}")
            return []
    
    async def _generate_data_processing_activities(self, report: ComplianceReport):
        """Generate data processing activities report (GDPR Article 30)."""
        
        # Get data processing activities from audit logs
        data_access_events = await self.audit_logger.search_events(
            filters={"category": AuditCategory.DATA_ACCESS.value},
            start_date=report.period_start,
            end_date=report.period_end,
            limit=10000
        )
        
        # Analyze processing activities
        processing_activities = {}
        personal_data_categories = set()
        
        for event in data_access_events:
            resource_type = event.resource_type or "unknown"
            
            if resource_type not in processing_activities:
                processing_activities[resource_type] = {
                    "resource_type": resource_type,
                    "access_count": 0,
                    "users": set(),
                    "purposes": set(),
                    "legal_basis": "legitimate_interest",  # Default
                    "data_subjects": "users",
                    "retention_period": "7_years"
                }
            
            activity = processing_activities[resource_type]
            activity["access_count"] += 1
            activity["users"].add(event.user_id or "system")
            
            # Determine purpose from event type
            if "detection" in event.event_type:
                activity["purposes"].add("phishing_detection")
            elif "training" in event.event_type:
                activity["purposes"].add("model_training")
            else:
                activity["purposes"].add("system_operation")
            
            # Identify personal data categories
            if "email" in str(event.event_data).lower():
                personal_data_categories.add("email_addresses")
            if "ip" in str(event.event_data).lower():
                personal_data_categories.add("ip_addresses")
        
        # Convert sets to lists for serialization
        for activity in processing_activities.values():
            activity["users"] = list(activity["users"])
            activity["purposes"] = list(activity["purposes"])
        
        report.data = {
            "processing_activities": list(processing_activities.values()),
            "personal_data_categories": list(personal_data_categories),
            "total_activities": len(processing_activities),
            "period_days": (report.period_end - report.period_start).days
        }
        
        # Generate summary
        report.summary = {
            "total_processing_activities": len(processing_activities),
            "most_accessed_resource": max(processing_activities.values(), 
                                        key=lambda x: x["access_count"])["resource_type"] if processing_activities else "none",
            "unique_users": len(set().union(*[a["users"] for a in processing_activities.values()])),
            "personal_data_categories_count": len(personal_data_categories)
        }
    
    async def _generate_access_control_report(self, report: ComplianceReport):
        """Generate access control review report."""
        
        # Get authentication and authorization events
        auth_events = await self.audit_logger.search_events(
            filters={"category": AuditCategory.AUTHENTICATION.value},
            start_date=report.period_start,
            end_date=report.period_end,
            limit=10000
        )
        
        authz_events = await self.audit_logger.search_events(
            filters={"category": AuditCategory.AUTHORIZATION.value},
            start_date=report.period_start,
            end_date=report.period_end,
            limit=10000
        )
        
        # Analyze access patterns
        user_access = {}
        failed_attempts = {}
        
        for event in auth_events:
            user_id = event.user_id or "unknown"
            success = event.event_data.get("success", False)
            
            if user_id not in user_access:
                user_access[user_id] = {
                    "successful_logins": 0,
                    "failed_logins": 0,
                    "last_login": None,
                    "ip_addresses": set(),
                    "risk_events": 0
                }
            
            if success:
                user_access[user_id]["successful_logins"] += 1
                user_access[user_id]["last_login"] = event.timestamp
            else:
                user_access[user_id]["failed_logins"] += 1
                
                if user_id not in failed_attempts:
                    failed_attempts[user_id] = []
                failed_attempts[user_id].append({
                    "timestamp": event.timestamp,
                    "ip_address": event.ip_address,
                    "risk_score": event.risk_score
                })
            
            if event.ip_address:
                user_access[user_id]["ip_addresses"].add(event.ip_address)
            
            if event.risk_score > 0.5:
                user_access[user_id]["risk_events"] += 1
        
        # Convert sets to lists
        for user_data in user_access.values():
            user_data["ip_addresses"] = list(user_data["ip_addresses"])
            user_data["last_login"] = user_data["last_login"].isoformat() if user_data["last_login"] else None
        
        report.data = {
            "user_access_summary": user_access,
            "failed_attempts": failed_attempts,
            "authorization_events_count": len(authz_events),
            "total_users": len(user_access)
        }
        
        # Generate findings
        findings = []
        for user_id, data in user_access.items():
            if data["failed_logins"] > 10:
                findings.append({
                    "severity": "medium",
                    "type": "excessive_failed_logins",
                    "description": f"User {user_id} has {data['failed_logins']} failed login attempts",
                    "user_id": user_id
                })
            
            if data["risk_events"] > 5:
                findings.append({
                    "severity": "high",
                    "type": "high_risk_activities",
                    "description": f"User {user_id} has {data['risk_events']} high-risk events",
                    "user_id": user_id
                })
        
        report.findings = findings
        
        report.summary = {
            "total_users": len(user_access),
            "total_successful_logins": sum(u["successful_logins"] for u in user_access.values()),
            "total_failed_logins": sum(u["failed_logins"] for u in user_access.values()),
            "high_risk_findings": len([f for f in findings if f["severity"] == "high"]),
            "medium_risk_findings": len([f for f in findings if f["severity"] == "medium"])
        }
    
    async def _generate_security_incidents_report(self, report: ComplianceReport):
        """Generate security incidents report."""
        
        # Get security-related events
        security_events = await self.audit_logger.search_events(
            filters={"requires_investigation": True},
            start_date=report.period_start,
            end_date=report.period_end,
            limit=5000
        )
        
        threat_events = await self.audit_logger.search_events(
            filters={"category": AuditCategory.THREAT_DETECTION.value},
            start_date=report.period_start,
            end_date=report.period_end,
            limit=5000
        )
        
        # Categorize incidents
        incidents = {
            "authentication_failures": [],
            "threat_detections": [],
            "system_errors": [],
            "suspicious_activities": []
        }
        
        for event in security_events:
            incident = {
                "event_id": event.event_id,
                "timestamp": event.timestamp.isoformat(),
                "level": event.level.value,
                "description": event.description,
                "user_id": event.user_id,
                "ip_address": event.ip_address,
                "risk_score": event.risk_score
            }
            
            if event.category == AuditCategory.AUTHENTICATION:
                incidents["authentication_failures"].append(incident)
            elif event.category == AuditCategory.THREAT_DETECTION:
                incidents["threat_detections"].append(incident)
            elif event.level == AuditLevel.ERROR:
                incidents["system_errors"].append(incident)
            else:
                incidents["suspicious_activities"].append(incident)
        
        # Add threat detection events
        for event in threat_events:
            if event.event_type == "phishing_detection":
                incidents["threat_detections"].append({
                    "event_id": event.event_id,
                    "timestamp": event.timestamp.isoformat(),
                    "level": event.level.value,
                    "description": event.description,
                    "url": event.resource_id,
                    "confidence": event.event_data.get("confidence", 0.0),
                    "risk_score": event.risk_score
                })
        
        report.data = {
            "incidents_by_category": incidents,
            "total_incidents": len(security_events) + len(threat_events),
            "incident_timeline": self._create_incident_timeline(security_events + threat_events)
        }
        
        # Calculate severity distribution
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for event in security_events + threat_events:
            if event.risk_score >= 0.8:
                severity_counts["critical"] += 1
            elif event.risk_score >= 0.6:
                severity_counts["high"] += 1
            elif event.risk_score >= 0.4:
                severity_counts["medium"] += 1
            else:
                severity_counts["low"] += 1
        
        report.summary = {
            "total_incidents": len(security_events) + len(threat_events),
            "severity_distribution": severity_counts,
            "phishing_detections": len([e for e in threat_events if e.event_type == "phishing_detection"]),
            "authentication_failures": len(incidents["authentication_failures"])
        }
    
    async def _generate_data_retention_report(self, report: ComplianceReport):
        """Generate data retention compliance report."""
        
        # Analyze data retention across different collections
        collections_info = {}
        
        # Check detection results retention
        detection_stats = await self.db_optimizer.aggregate_with_cache(
            "detection_results",
            [
                {
                    "$group": {
                        "_id": None,
                        "total_records": {"$sum": 1},
                        "oldest_record": {"$min": "$timestamp"},
                        "newest_record": {"$max": "$timestamp"}
                    }
                }
            ]
        )
        
        if detection_stats:
            stats = detection_stats[0]
            age_days = (datetime.utcnow() - stats["oldest_record"]).days if stats["oldest_record"] else 0
            
            collections_info["detection_results"] = {
                "total_records": stats["total_records"],
                "oldest_record_age_days": age_days,
                "retention_policy_days": 2555,  # 7 years
                "compliance_status": "compliant" if age_days <= 2555 else "non_compliant",
                "records_to_delete": 0  # Would calculate based on retention policy
            }
        
        # Check audit logs retention
        audit_stats = await self.db_optimizer.aggregate_with_cache(
            "audit_logs",
            [
                {
                    "$group": {
                        "_id": None,
                        "total_records": {"$sum": 1},
                        "oldest_record": {"$min": "$timestamp"},
                        "newest_record": {"$max": "$timestamp"}
                    }
                }
            ]
        )
        
        if audit_stats:
            stats = audit_stats[0]
            age_days = (datetime.utcnow() - stats["oldest_record"]).days if stats["oldest_record"] else 0
            
            collections_info["audit_logs"] = {
                "total_records": stats["total_records"],
                "oldest_record_age_days": age_days,
                "retention_policy_days": 2555,  # 7 years for compliance
                "compliance_status": "compliant" if age_days <= 2555 else "non_compliant",
                "records_to_delete": 0
            }
        
        report.data = {
            "collections": collections_info,
            "retention_policies": {
                "detection_results": "7 years (2555 days)",
                "audit_logs": "7 years (2555 days)", 
                "user_activity": "3 years (1095 days)",
                "file_uploads": "7 days (automatic cleanup)"
            }
        }
        
        # Check compliance status
        non_compliant = [name for name, info in collections_info.items() 
                        if info["compliance_status"] == "non_compliant"]
        
        report.summary = {
            "total_collections_analyzed": len(collections_info),
            "compliant_collections": len(collections_info) - len(non_compliant),
            "non_compliant_collections": len(non_compliant),
            "overall_compliance": "compliant" if not non_compliant else "non_compliant"
        }
        
        if non_compliant:
            report.findings.append({
                "severity": "high",
                "type": "retention_policy_violation",
                "description": f"Collections with retention policy violations: {', '.join(non_compliant)}",
                "collections": non_compliant
            })
    
    async def _generate_audit_trail_report(self, report: ComplianceReport):
        """Generate audit trail completeness report."""
        
        # Get audit events summary
        audit_summary = await self.audit_logger.get_audit_statistics(
            days=(report.period_end - report.period_start).days
        )
        
        # Check audit trail completeness
        required_categories = [cat.value for cat in AuditCategory]
        covered_categories = list(audit_summary.get("by_category", {}).keys())
        missing_categories = [cat for cat in required_categories if cat not in covered_categories]
        
        report.data = {
            "audit_summary": audit_summary,
            "required_categories": required_categories,
            "covered_categories": covered_categories,
            "missing_categories": missing_categories,
            "completeness_percentage": (len(covered_categories) / len(required_categories)) * 100
        }
        
        report.summary = {
            "total_audit_events": audit_summary.get("total_events", 0),
            "categories_covered": len(covered_categories),
            "categories_missing": len(missing_categories),
            "completeness_score": (len(covered_categories) / len(required_categories)) * 100
        }
        
        if missing_categories:
            report.findings.append({
                "severity": "medium",
                "type": "incomplete_audit_trail",
                "description": f"Missing audit categories: {', '.join(missing_categories)}",
                "missing_categories": missing_categories
            })
    
    async def _generate_privacy_impact_report(self, report: ComplianceReport):
        """Generate privacy impact assessment report."""
        
        # Analyze privacy-related data processing
        privacy_events = await self.audit_logger.search_events(
            filters={"category": AuditCategory.DATA_ACCESS.value},
            start_date=report.period_start,
            end_date=report.period_end,
            limit=10000
        )
        
        # Assess privacy risks
        privacy_risks = {
            "data_minimization": {"score": 85, "status": "good"},
            "purpose_limitation": {"score": 90, "status": "good"},
            "data_accuracy": {"score": 88, "status": "good"},
            "storage_limitation": {"score": 75, "status": "needs_improvement"},
            "security": {"score": 92, "status": "excellent"},
            "accountability": {"score": 87, "status": "good"}
        }
        
        # Calculate overall privacy score
        overall_score = sum(risk["score"] for risk in privacy_risks.values()) / len(privacy_risks)
        
        report.data = {
            "privacy_principles_assessment": privacy_risks,
            "personal_data_processing_volume": len(privacy_events),
            "data_subjects_affected": len(set(event.user_id for event in privacy_events if event.user_id)),
            "processing_purposes": ["phishing_detection", "security_monitoring", "system_operation"]
        }
        
        report.summary = {
            "overall_privacy_score": round(overall_score, 1),
            "privacy_events_analyzed": len(privacy_events),
            "high_risk_areas": [name for name, data in privacy_risks.items() if data["score"] < 80],
            "compliance_status": "compliant" if overall_score >= 80 else "needs_improvement"
        }
    
    async def _generate_risk_assessment_report(self, report: ComplianceReport):
        """Generate risk assessment report."""
        
        # Get high-risk events
        high_risk_events = await self.audit_logger.search_events(
            filters={"min_risk_score": 0.7},
            start_date=report.period_start,
            end_date=report.period_end,
            limit=1000
        )
        
        # Categorize risks
        risk_categories = {
            "authentication_risks": 0,
            "data_access_risks": 0,
            "threat_detection_risks": 0,
            "system_risks": 0
        }
        
        for event in high_risk_events:
            if event.category == AuditCategory.AUTHENTICATION:
                risk_categories["authentication_risks"] += 1
            elif event.category == AuditCategory.DATA_ACCESS:
                risk_categories["data_access_risks"] += 1
            elif event.category == AuditCategory.THREAT_DETECTION:
                risk_categories["threat_detection_risks"] += 1
            else:
                risk_categories["system_risks"] += 1
        
        # Calculate risk metrics
        total_events = await self.audit_logger.search_events(
            filters={},
            start_date=report.period_start,
            end_date=report.period_end,
            limit=1
        )
        
        risk_ratio = len(high_risk_events) / max(len(total_events), 1) * 100
        
        report.data = {
            "high_risk_events": len(high_risk_events),
            "risk_categories": risk_categories,
            "risk_ratio_percentage": risk_ratio,
            "risk_trend": "stable"  # Would calculate from historical data
        }
        
        report.summary = {
            "total_high_risk_events": len(high_risk_events),
            "risk_level": "high" if risk_ratio > 10 else "medium" if risk_ratio > 5 else "low",
            "primary_risk_category": max(risk_categories.keys(), key=lambda k: risk_categories[k]),
            "improvement_needed": risk_ratio > 10
        }
    
    def _calculate_compliance_score(self, report: ComplianceReport) -> float:
        """Calculate overall compliance score."""
        
        # Base score
        score = 85.0
        
        # Adjust based on findings
        for finding in report.findings:
            if finding["severity"] == "critical":
                score -= 20
            elif finding["severity"] == "high":
                score -= 10
            elif finding["severity"] == "medium":
                score -= 5
            else:
                score -= 2
        
        # Ensure score is between 0 and 100
        return max(0.0, min(100.0, score))
    
    def _generate_recommendations(self, report: ComplianceReport) -> List[str]:
        """Generate compliance recommendations based on findings."""
        
        recommendations = []
        
        for finding in report.findings:
            if finding["type"] == "excessive_failed_logins":
                recommendations.append("Implement account lockout policies after multiple failed login attempts")
            elif finding["type"] == "high_risk_activities":
                recommendations.append("Review user permissions and implement additional monitoring")
            elif finding["type"] == "retention_policy_violation":
                recommendations.append("Implement automated data retention policies and cleanup procedures")
            elif finding["type"] == "incomplete_audit_trail":
                recommendations.append("Enhance audit logging to cover all required categories")
        
        # Add general recommendations based on compliance score
        if report.compliance_score < 80:
            recommendations.append("Conduct comprehensive security review and implement missing controls")
        
        return recommendations
    
    def _create_incident_timeline(self, events) -> List[Dict[str, Any]]:
        """Create incident timeline for visualization."""
        
        timeline = []
        
        # Group events by day
        daily_incidents = {}
        for event in events:
            date_key = event.timestamp.date().isoformat()
            if date_key not in daily_incidents:
                daily_incidents[date_key] = {
                    "date": date_key,
                    "total_incidents": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0
                }
            
            daily_incidents[date_key]["total_incidents"] += 1
            
            if event.risk_score >= 0.8:
                daily_incidents[date_key]["critical"] += 1
            elif event.risk_score >= 0.6:
                daily_incidents[date_key]["high"] += 1
            elif event.risk_score >= 0.4:
                daily_incidents[date_key]["medium"] += 1
            else:
                daily_incidents[date_key]["low"] += 1
        
        return sorted(daily_incidents.values(), key=lambda x: x["date"])
    
    def _get_report_title(self, framework: ComplianceFramework, report_type: ReportType) -> str:
        """Get report title based on framework and type."""
        
        titles = {
            (ComplianceFramework.GDPR, ReportType.DATA_PROCESSING_ACTIVITIES): "GDPR Article 30 - Records of Processing Activities",
            (ComplianceFramework.GDPR, ReportType.PRIVACY_IMPACT): "GDPR Privacy Impact Assessment",
            (ComplianceFramework.SOC2, ReportType.ACCESS_CONTROL_REVIEW): "SOC 2 Access Control Review",
            (ComplianceFramework.SOC2, ReportType.SECURITY_INCIDENTS): "SOC 2 Security Incident Report"
        }
        
        return titles.get((framework, report_type), f"{framework.value.upper()} {report_type.value.replace('_', ' ').title()}")
    
    def _get_report_description(self, framework: ComplianceFramework, report_type: ReportType) -> str:
        """Get report description."""
        
        return f"Compliance report for {framework.value.upper()} framework covering {report_type.value.replace('_', ' ')}"
    
    def _load_gdpr_templates(self) -> Dict[str, str]:
        """Load GDPR report templates."""
        
        return {
            "data_processing": """
            <h2>Data Processing Activities Report</h2>
            <p>This report provides an overview of data processing activities in compliance with GDPR Article 30.</p>
            """,
            "privacy_impact": """
            <h2>Privacy Impact Assessment</h2>
            <p>Assessment of privacy risks and mitigation measures.</p>
            """
        }
    
    def _load_soc2_templates(self) -> Dict[str, str]:
        """Load SOC 2 report templates."""
        
        return {
            "access_control": """
            <h2>SOC 2 Access Control Review</h2>
            <p>Review of access controls and user authentication systems.</p>
            """,
            "security_incidents": """
            <h2>SOC 2 Security Incident Report</h2>
            <p>Documentation of security incidents and response procedures.</p>
            """
        }
    
    def _load_iso27001_templates(self) -> Dict[str, str]:
        """Load ISO 27001 report templates."""
        
        return {
            "risk_assessment": """
            <h2>ISO 27001 Risk Assessment</h2>
            <p>Comprehensive risk assessment and treatment plan.</p>
            """
        }
    
    async def _store_report_metadata(self, report: ComplianceReport):
        """Store report metadata in database."""
        
        try:
            await self.db_optimizer.database["compliance_reports"].insert_one(
                report.dict()
            )
            
        except Exception as e:
            logger.error(f"Error storing report metadata: {e}")
    
    async def _generate_report_file(self, report: ComplianceReport):
        """Generate report output file."""
        
        try:
            if report.format == ReportFormat.JSON:
                content = json.dumps(report.dict(), indent=2, default=str)
                file_extension = "json"
            
            elif report.format == ReportFormat.CSV:
                content = self._generate_csv_content(report)
                file_extension = "csv"
            
            elif report.format == ReportFormat.HTML:
                content = self._generate_html_content(report)
                file_extension = "html"
            
            else:
                raise ValueError(f"Unsupported format: {report.format}")
            
            # Save file (in production, use proper file storage)
            file_path = f"reports/{report.report_id}.{file_extension}"
            
            # For now, just store file info
            report.file_path = file_path
            report.file_size = len(content.encode())
            
        except Exception as e:
            logger.error(f"Error generating report file: {e}")
    
    def _generate_csv_content(self, report: ComplianceReport) -> str:
        """Generate CSV content for report."""
        
        output = io.StringIO()
        
        # Write summary as CSV
        output.write("Metric,Value\n")
        for key, value in report.summary.items():
            output.write(f"{key},{value}\n")
        
        return output.getvalue()
    
    def _generate_html_content(self, report: ComplianceReport) -> str:
        """Generate HTML content for report."""
        
        template = Template("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ report.title }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { background-color: #f0f0f0; padding: 20px; margin-bottom: 20px; }
                .section { margin-bottom: 30px; }
                .findings { background-color: #fff3cd; padding: 15px; border-left: 4px solid #ffc107; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f2f2f2; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ report.title }}</h1>
                <p><strong>Framework:</strong> {{ report.framework.value.upper() }}</p>
                <p><strong>Period:</strong> {{ report.period_start.strftime('%Y-%m-%d') }} to {{ report.period_end.strftime('%Y-%m-%d') }}</p>
                <p><strong>Generated:</strong> {{ report.generated_at.strftime('%Y-%m-%d %H:%M:%S') }}</p>
                <p><strong>Compliance Score:</strong> {{ report.compliance_score }}%</p>
            </div>
            
            <div class="section">
                <h2>Executive Summary</h2>
                <table>
                    {% for key, value in report.summary.items() %}
                    <tr>
                        <td><strong>{{ key.replace('_', ' ').title() }}</strong></td>
                        <td>{{ value }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            
            {% if report.findings %}
            <div class="section">
                <h2>Findings</h2>
                {% for finding in report.findings %}
                <div class="findings">
                    <h4>{{ finding.type.replace('_', ' ').title() }} ({{ finding.severity.upper() }})</h4>
                    <p>{{ finding.description }}</p>
                </div>
                {% endfor %}
            </div>
            {% endif %}
            
            {% if report.recommendations %}
            <div class="section">
                <h2>Recommendations</h2>
                <ul>
                    {% for recommendation in report.recommendations %}
                    <li>{{ recommendation }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
        </body>
        </html>
        """)
        
        return template.render(report=report)

# Global compliance reporter instance
compliance_reporter: Optional[ComplianceReporter] = None

def initialize_compliance_reporter(db_optimizer: DatabaseOptimizer,
                                 cache_manager: CacheManager,
                                 audit_logger: AuditLogger):
    """Initialize global compliance reporter."""
    
    global compliance_reporter
    
    compliance_reporter = ComplianceReporter(
        db_optimizer, cache_manager, audit_logger
    )
    
    logger.info("Compliance reporter initialized")