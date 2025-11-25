"""Compliance API endpoints for generating reports and managing retention policies."""

from fastapi import APIRouter, HTTPException, Depends, Query, Body
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from loguru import logger

from app.compliance.reporting import (
    ComplianceReporter, ComplianceReport, ComplianceFramework,
    ReportType, ReportFormat, compliance_reporter
)
from app.compliance.retention import (
    DataRetentionManager, RetentionPolicy, RetentionExecution,
    DataCategory, RetentionAction, RetentionSchedule, 
    data_retention_manager
)
from app.compliance.audit import AuditLogger, audit_logger
from app.core.auth import get_current_user_with_permissions
from app.core.database import get_database_optimizer

router = APIRouter(prefix="/compliance", tags=["compliance"])

class ReportRequest(BaseModel):
    """Request model for generating compliance reports."""
    
    framework: ComplianceFramework
    report_type: ReportType
    period_start: datetime
    period_end: datetime
    format: ReportFormat = ReportFormat.HTML
    filters: Optional[Dict[str, Any]] = None

class PolicyCreateRequest(BaseModel):
    """Request model for creating retention policy."""
    
    name: str = Field(..., description="Policy name")
    description: str = Field(..., description="Policy description")
    data_category: DataCategory
    collection_name: str
    retention_period_days: int = Field(..., gt=0)
    action: RetentionAction
    schedule: RetentionSchedule
    date_field: str = "timestamp"
    additional_filters: Dict[str, Any] = Field(default_factory=dict)
    preserve_conditions: Dict[str, Any] = Field(default_factory=dict)
    compliance_frameworks: List[str] = Field(default_factory=list)

class PolicyUpdateRequest(BaseModel):
    """Request model for updating retention policy."""
    
    name: Optional[str] = None
    description: Optional[str] = None
    retention_period_days: Optional[int] = Field(None, gt=0)
    action: Optional[RetentionAction] = None
    schedule: Optional[RetentionSchedule] = None
    additional_filters: Optional[Dict[str, Any]] = None
    preserve_conditions: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None
    compliance_frameworks: Optional[List[str]] = None

# Compliance Reporting Endpoints

@router.post("/reports/generate", response_model=ComplianceReport)
async def generate_compliance_report(
    request: ReportRequest,
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """Generate compliance report."""
    
    try:
        if not compliance_reporter:
            raise HTTPException(status_code=503, detail="Compliance reporter not initialized")
        
        # Validate date range
        if request.period_end <= request.period_start:
            raise HTTPException(status_code=400, detail="End date must be after start date")
        
        max_period_days = 365  # Maximum 1 year
        if (request.period_end - request.period_start).days > max_period_days:
            raise HTTPException(status_code=400, detail=f"Period cannot exceed {max_period_days} days")
        
        report = await compliance_reporter.generate_report(
            framework=request.framework,
            report_type=request.report_type,
            period_start=request.period_start,
            period_end=request.period_end,
            generated_by=user.get("user_id", "unknown"),
            format=request.format,
            filters=request.filters
        )
        
        return report
        
    except Exception as e:
        logger.error(f"Error generating compliance report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/reports/{report_id}", response_model=ComplianceReport)
async def get_compliance_report(
    report_id: str,
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """Get existing compliance report."""
    
    try:
        if not compliance_reporter:
            raise HTTPException(status_code=503, detail="Compliance reporter not initialized")
        
        report = await compliance_reporter.get_report(report_id)
        if not report:
            raise HTTPException(status_code=404, detail="Report not found")
        
        return report
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting compliance report: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/reports", response_model=List[ComplianceReport])
async def list_compliance_reports(
    framework: Optional[ComplianceFramework] = Query(None),
    report_type: Optional[ReportType] = Query(None),
    limit: int = Query(50, le=100),
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """List compliance reports with filtering."""
    
    try:
        if not compliance_reporter:
            raise HTTPException(status_code=503, detail="Compliance reporter not initialized")
        
        reports = await compliance_reporter.list_reports(
            framework=framework,
            report_type=report_type,
            limit=limit
        )
        
        return reports
        
    except Exception as e:
        logger.error(f"Error listing compliance reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Data Retention Endpoints

@router.post("/retention/policies", response_model=Dict[str, str])
async def create_retention_policy(
    request: PolicyCreateRequest,
    user = Depends(get_current_user_with_permissions(["compliance:write"]))
):
    """Create new retention policy."""
    
    try:
        if not data_retention_manager:
            raise HTTPException(status_code=503, detail="Data retention manager not initialized")
        
        # Create policy
        policy = RetentionPolicy(
            policy_id=f"policy_{request.name.lower().replace(' ', '_')}_{int(datetime.utcnow().timestamp())}",
            name=request.name,
            description=request.description,
            data_category=request.data_category,
            collection_name=request.collection_name,
            retention_period_days=request.retention_period_days,
            action=request.action,
            schedule=request.schedule,
            date_field=request.date_field,
            additional_filters=request.additional_filters,
            preserve_conditions=request.preserve_conditions,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            compliance_frameworks=request.compliance_frameworks
        )
        
        policy_id = await data_retention_manager.create_policy(policy)
        
        return {"policy_id": policy_id, "status": "created"}
        
    except Exception as e:
        logger.error(f"Error creating retention policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.put("/retention/policies/{policy_id}", response_model=Dict[str, str])
async def update_retention_policy(
    policy_id: str,
    request: PolicyUpdateRequest,
    user = Depends(get_current_user_with_permissions(["compliance:write"]))
):
    """Update retention policy."""
    
    try:
        if not data_retention_manager:
            raise HTTPException(status_code=503, detail="Data retention manager not initialized")
        
        # Build update dict
        updates = {}
        for field, value in request.dict(exclude_unset=True).items():
            if value is not None:
                updates[field] = value
        
        if not updates:
            raise HTTPException(status_code=400, detail="No updates provided")
        
        success = await data_retention_manager.update_policy(policy_id, updates)
        if not success:
            raise HTTPException(status_code=404, detail="Policy not found")
        
        return {"policy_id": policy_id, "status": "updated"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating retention policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/retention/policies/{policy_id}", response_model=Dict[str, str])
async def delete_retention_policy(
    policy_id: str,
    user = Depends(get_current_user_with_permissions(["compliance:write"]))
):
    """Delete retention policy."""
    
    try:
        if not data_retention_manager:
            raise HTTPException(status_code=503, detail="Data retention manager not initialized")
        
        success = await data_retention_manager.delete_policy(policy_id)
        if not success:
            raise HTTPException(status_code=404, detail="Policy not found")
        
        return {"policy_id": policy_id, "status": "deleted"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting retention policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/retention/policies/{policy_id}", response_model=RetentionPolicy)
async def get_retention_policy(
    policy_id: str,
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """Get retention policy by ID."""
    
    try:
        if not data_retention_manager:
            raise HTTPException(status_code=503, detail="Data retention manager not initialized")
        
        policy = await data_retention_manager.get_policy(policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        
        return policy
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting retention policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/retention/policies", response_model=List[RetentionPolicy])
async def list_retention_policies(
    data_category: Optional[DataCategory] = Query(None),
    active_only: bool = Query(True),
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """List retention policies with filtering."""
    
    try:
        if not data_retention_manager:
            raise HTTPException(status_code=503, detail="Data retention manager not initialized")
        
        policies = await data_retention_manager.list_policies(
            data_category=data_category,
            active_only=active_only
        )
        
        return policies
        
    except Exception as e:
        logger.error(f"Error listing retention policies: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/retention/policies/{policy_id}/execute", response_model=RetentionExecution)
async def execute_retention_policy(
    policy_id: str,
    dry_run: bool = Query(False, description="Preview changes without executing"),
    user = Depends(get_current_user_with_permissions(["compliance:write"]))
):
    """Execute retention policy manually."""
    
    try:
        if not data_retention_manager:
            raise HTTPException(status_code=503, detail="Data retention manager not initialized")
        
        execution = await data_retention_manager.execute_policy(policy_id, dry_run)
        
        return execution
        
    except Exception as e:
        logger.error(f"Error executing retention policy: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/retention/execute-all", response_model=Dict[str, Any])
async def execute_all_due_policies(
    dry_run: bool = Query(False, description="Preview changes without executing"),
    user = Depends(get_current_user_with_permissions(["compliance:write"]))
):
    """Execute all retention policies that are due."""
    
    try:
        if not data_retention_manager:
            raise HTTPException(status_code=503, detail="Data retention manager not initialized")
        
        await data_retention_manager.execute_all_due_policies(dry_run)
        
        return {"status": "completed", "dry_run": dry_run}
        
    except Exception as e:
        logger.error(f"Error executing due retention policies: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/retention/policies/{policy_id}/preview", response_model=Dict[str, Any])
async def preview_policy_impact(
    policy_id: str,
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """Preview the impact of executing a retention policy."""
    
    try:
        if not data_retention_manager:
            raise HTTPException(status_code=503, detail="Data retention manager not initialized")
        
        policy = await data_retention_manager.get_policy(policy_id)
        if not policy:
            raise HTTPException(status_code=404, detail="Policy not found")
        
        impact = await data_retention_manager.preview_policy_impact(policy)
        
        return impact
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error previewing policy impact: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Statistics and Monitoring Endpoints

@router.get("/retention/statistics", response_model=Dict[str, Any])
async def get_retention_statistics(
    days: int = Query(30, ge=1, le=365),
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """Get retention statistics for the specified period."""
    
    try:
        if not data_retention_manager:
            raise HTTPException(status_code=503, detail="Data retention manager not initialized")
        
        stats = await data_retention_manager.get_retention_statistics(days)
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting retention statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/audit/statistics", response_model=Dict[str, Any])
async def get_audit_statistics(
    days: int = Query(30, ge=1, le=365),
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """Get audit statistics for compliance monitoring."""
    
    try:
        if not audit_logger:
            raise HTTPException(status_code=503, detail="Audit logger not initialized")
        
        stats = await audit_logger.get_audit_statistics(days)
        
        return stats
        
    except Exception as e:
        logger.error(f"Error getting audit statistics: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/frameworks", response_model=List[str])
async def get_supported_frameworks(
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """Get list of supported compliance frameworks."""
    
    return [framework.value for framework in ComplianceFramework]

@router.get("/report-types", response_model=List[str])
async def get_supported_report_types(
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """Get list of supported report types."""
    
    return [report_type.value for report_type in ReportType]

@router.get("/data-categories", response_model=List[str])
async def get_data_categories(
    user = Depends(get_current_user_with_permissions(["compliance:read"]))
):
    """Get list of data categories for retention policies."""
    
    return [category.value for category in DataCategory]