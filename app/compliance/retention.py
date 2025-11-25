"""Data retention policies and automated cleanup system."""

import asyncio
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
from pydantic import BaseModel
from loguru import logger
from app.core.database import DatabaseOptimizer
from app.core.cache import CacheManager
from app.compliance.audit import AuditLogger, AuditCategory

class RetentionAction(str, Enum):
    """Types of retention actions."""
    DELETE = "delete"
    ARCHIVE = "archive"
    ANONYMIZE = "anonymize"
    BACKUP = "backup"

class RetentionSchedule(str, Enum):
    """Retention schedule frequencies."""
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"
    YEARLY = "yearly"

class DataCategory(str, Enum):
    """Categories of data for retention policies."""
    DETECTION_RESULTS = "detection_results"
    AUDIT_LOGS = "audit_logs"
    USER_ACTIVITY = "user_activity"
    THREAT_INTELLIGENCE = "threat_intelligence"
    ML_TRAINING_DATA = "ml_training_data"
    FILE_UPLOADS = "file_uploads"
    CACHE_DATA = "cache_data"
    SESSION_DATA = "session_data"

class RetentionPolicy(BaseModel):
    """Data retention policy configuration."""
    
    policy_id: str
    name: str
    description: str
    
    # Policy configuration
    data_category: DataCategory
    collection_name: str
    retention_period_days: int
    action: RetentionAction
    schedule: RetentionSchedule
    
    # Policy rules
    date_field: str = "timestamp"
    additional_filters: Dict[str, Any] = {}
    preserve_conditions: Dict[str, Any] = {}  # Conditions to preserve data
    
    # Metadata
    created_at: datetime
    updated_at: datetime
    is_active: bool = True
    last_executed: Optional[datetime] = None
    next_execution: Optional[datetime] = None
    
    # Compliance
    legal_basis: str = "data_retention_policy"
    compliance_frameworks: List[str] = []

class RetentionExecution(BaseModel):
    """Retention policy execution record."""
    
    execution_id: str
    policy_id: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    status: str = "running"  # running, completed, failed
    
    # Execution results
    records_processed: int = 0
    records_deleted: int = 0
    records_archived: int = 0
    records_anonymized: int = 0
    records_preserved: int = 0
    
    # Error information
    errors: List[str] = []
    
    # Metadata
    execution_duration_seconds: Optional[float] = None

class DataRetentionManager:
    """Manage data retention policies and automated cleanup."""
    
    def __init__(self, db_optimizer: DatabaseOptimizer,
                 cache_manager: CacheManager,
                 audit_logger: AuditLogger):
        self.db_optimizer = db_optimizer
        self.cache_manager = cache_manager
        self.audit_logger = audit_logger
        
        # Default retention policies
        self.default_policies = self._create_default_policies()
        
        logger.info("Data retention manager initialized")
    
    async def initialize(self):
        """Initialize retention policies and schedules."""
        
        try:
            # Create indexes for efficient cleanup
            await self._create_retention_indexes()
            
            # Load existing policies or create defaults
            await self._load_or_create_policies()
            
            # Schedule retention jobs
            await self._schedule_retention_jobs()
            
            logger.info("Data retention manager initialization completed")
            
        except Exception as e:
            logger.error(f"Error initializing retention manager: {e}")
            raise
    
    async def create_policy(self, policy: RetentionPolicy) -> str:
        """Create new retention policy."""
        
        try:
            # Validate policy
            await self._validate_policy(policy)
            
            # Store policy
            await self.db_optimizer.database["retention_policies"].insert_one(
                policy.dict()
            )
            
            # Schedule policy execution
            await self._schedule_policy(policy)
            
            # Audit log
            await self.audit_logger.log_system_event(
                "retention_policy_created",
                f"Created retention policy: {policy.name}",
                data={
                    "policy_id": policy.policy_id,
                    "data_category": policy.data_category.value,
                    "retention_days": policy.retention_period_days
                }
            )
            
            logger.info(f"Created retention policy: {policy.policy_id}")
            return policy.policy_id
            
        except Exception as e:
            logger.error(f"Error creating retention policy: {e}")
            raise
    
    async def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> bool:
        """Update existing retention policy."""
        
        try:
            # Update policy
            result = await self.db_optimizer.database["retention_policies"].update_one(
                {"policy_id": policy_id},
                {
                    "$set": {
                        **updates,
                        "updated_at": datetime.utcnow()
                    }
                }
            )
            
            if result.modified_count > 0:
                # Reschedule if needed
                updated_policy = await self.get_policy(policy_id)
                if updated_policy:
                    await self._schedule_policy(updated_policy)
                
                # Audit log
                await self.audit_logger.log_system_event(
                    "retention_policy_updated",
                    f"Updated retention policy: {policy_id}",
                    data={"policy_id": policy_id, "updates": updates}
                )
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error updating retention policy {policy_id}: {e}")
            raise
    
    async def delete_policy(self, policy_id: str) -> bool:
        """Delete retention policy."""
        
        try:
            result = await self.db_optimizer.database["retention_policies"].delete_one(
                {"policy_id": policy_id}
            )
            
            if result.deleted_count > 0:
                # Audit log
                await self.audit_logger.log_system_event(
                    "retention_policy_deleted",
                    f"Deleted retention policy: {policy_id}",
                    data={"policy_id": policy_id}
                )
                
                return True
            
            return False
            
        except Exception as e:
            logger.error(f"Error deleting retention policy {policy_id}: {e}")
            raise
    
    async def get_policy(self, policy_id: str) -> Optional[RetentionPolicy]:
        """Get retention policy by ID."""
        
        try:
            policy_data = await self.db_optimizer.database["retention_policies"].find_one(
                {"policy_id": policy_id}
            )
            
            if policy_data:
                return RetentionPolicy(**policy_data)
            
        except Exception as e:
            logger.error(f"Error getting retention policy {policy_id}: {e}")
        
        return None
    
    async def list_policies(self, data_category: Optional[DataCategory] = None,
                          active_only: bool = True) -> List[RetentionPolicy]:
        """List retention policies with filtering."""
        
        try:
            filters = {}
            if data_category:
                filters["data_category"] = data_category.value
            if active_only:
                filters["is_active"] = True
            
            policies_data = await self.db_optimizer.database["retention_policies"].find(
                filters
            ).to_list(length=None)
            
            return [RetentionPolicy(**policy) for policy in policies_data]
            
        except Exception as e:
            logger.error(f"Error listing retention policies: {e}")
            return []
    
    async def execute_policy(self, policy_id: str, dry_run: bool = False) -> RetentionExecution:
        """Execute retention policy manually."""
        
        try:
            # Get policy
            policy = await self.get_policy(policy_id)
            if not policy:
                raise ValueError(f"Policy not found: {policy_id}")
            
            if not policy.is_active:
                raise ValueError(f"Policy is inactive: {policy_id}")
            
            # Create execution record
            execution = RetentionExecution(
                execution_id=f"exec_{policy_id}_{int(datetime.utcnow().timestamp())}",
                policy_id=policy_id,
                started_at=datetime.utcnow()
            )
            
            # Store execution record
            await self.db_optimizer.database["retention_executions"].insert_one(
                execution.dict()
            )
            
            try:
                # Execute retention action
                await self._execute_retention_action(policy, execution, dry_run)
                
                # Mark as completed
                execution.completed_at = datetime.utcnow()
                execution.status = "completed"
                execution.execution_duration_seconds = (
                    execution.completed_at - execution.started_at
                ).total_seconds()
                
                # Update policy last execution
                if not dry_run:
                    await self.update_policy(policy_id, {
                        "last_executed": execution.completed_at,
                        "next_execution": self._calculate_next_execution(policy)
                    })
                
            except Exception as e:
                execution.status = "failed"
                execution.errors.append(str(e))
                execution.completed_at = datetime.utcnow()
                raise
            
            finally:
                # Update execution record
                await self.db_optimizer.database["retention_executions"].update_one(
                    {"execution_id": execution.execution_id},
                    {"$set": execution.dict()}
                )
            
            # Audit log
            await self.audit_logger.log_system_event(
                "retention_policy_executed",
                f"Executed retention policy: {policy.name}",
                data={
                    "policy_id": policy_id,
                    "execution_id": execution.execution_id,
                    "dry_run": dry_run,
                    "records_processed": execution.records_processed,
                    "records_deleted": execution.records_deleted,
                    "status": execution.status
                }
            )
            
            logger.info(f"Retention policy execution completed: {execution.execution_id}")
            return execution
            
        except Exception as e:
            logger.error(f"Error executing retention policy {policy_id}: {e}")
            raise
    
    async def execute_all_due_policies(self, dry_run: bool = False):
        """Execute all policies that are due for execution."""
        
        try:
            # Get due policies
            due_policies = await self._get_due_policies()
            
            logger.info(f"Found {len(due_policies)} due retention policies")
            
            # Execute each policy
            results = []
            for policy in due_policies:
                try:
                    execution = await self.execute_policy(policy.policy_id, dry_run)
                    results.append(execution)
                    
                except Exception as e:
                    logger.error(f"Error executing policy {policy.policy_id}: {e}")
                    results.append(None)
            
            successful = len([r for r in results if r and r.status == "completed"])
            logger.info(f"Executed {successful}/{len(due_policies)} retention policies successfully")
            
        except Exception as e:
            logger.error(f"Error executing due retention policies: {e}")
            raise
    
    async def get_retention_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Get retention statistics for the specified period."""
        
        try:
            start_date = datetime.utcnow() - timedelta(days=days)
            
            # Get execution statistics
            executions = await self.db_optimizer.database["retention_executions"].find({
                "started_at": {"$gte": start_date}
            }).to_list(length=None)
            
            total_executions = len(executions)
            successful_executions = len([e for e in executions if e.get("status") == "completed"])
            failed_executions = len([e for e in executions if e.get("status") == "failed"])
            
            total_records_processed = sum(e.get("records_processed", 0) for e in executions)
            total_records_deleted = sum(e.get("records_deleted", 0) for e in executions)
            total_records_archived = sum(e.get("records_archived", 0) for e in executions)
            
            # Get policy statistics
            total_policies = await self.db_optimizer.database["retention_policies"].count_documents({})
            active_policies = await self.db_optimizer.database["retention_policies"].count_documents(
                {"is_active": True}
            )
            
            return {
                "period_days": days,
                "total_policies": total_policies,
                "active_policies": active_policies,
                "total_executions": total_executions,
                "successful_executions": successful_executions,
                "failed_executions": failed_executions,
                "success_rate": (successful_executions / max(total_executions, 1)) * 100,
                "total_records_processed": total_records_processed,
                "total_records_deleted": total_records_deleted,
                "total_records_archived": total_records_archived
            }
            
        except Exception as e:
            logger.error(f"Error getting retention statistics: {e}")
            return {}
    
    async def preview_policy_impact(self, policy: RetentionPolicy) -> Dict[str, Any]:
        """Preview the impact of executing a retention policy."""
        
        try:
            # Calculate cutoff date
            cutoff_date = datetime.utcnow() - timedelta(days=policy.retention_period_days)
            
            # Build query
            query = {
                policy.date_field: {"$lt": cutoff_date},
                **policy.additional_filters
            }
            
            # Count affected records
            total_count = await self.db_optimizer.database[policy.collection_name].count_documents(query)
            
            # Count preserved records
            preserved_count = 0
            if policy.preserve_conditions:
                preserve_query = {**query, **policy.preserve_conditions}
                preserved_count = await self.db_optimizer.database[policy.collection_name].count_documents(
                    preserve_query
                )
            
            affected_count = total_count - preserved_count
            
            # Estimate storage impact
            sample_docs = await self.db_optimizer.database[policy.collection_name].find(
                query
            ).limit(10).to_list(length=10)
            
            avg_doc_size = sum(len(str(doc).encode()) for doc in sample_docs) / max(len(sample_docs), 1)
            estimated_storage_freed_mb = (affected_count * avg_doc_size) / (1024 * 1024)
            
            return {
                "policy_id": policy.policy_id,
                "collection_name": policy.collection_name,
                "cutoff_date": cutoff_date.isoformat(),
                "total_records_found": total_count,
                "records_to_preserve": preserved_count,
                "records_to_affect": affected_count,
                "action": policy.action.value,
                "estimated_storage_freed_mb": round(estimated_storage_freed_mb, 2)
            }
            
        except Exception as e:
            logger.error(f"Error previewing policy impact: {e}")
            raise
    
    def _create_default_policies(self) -> List[RetentionPolicy]:
        """Create default retention policies."""
        
        current_time = datetime.utcnow()
        
        return [
            # Detection results - 7 years for compliance
            RetentionPolicy(
                policy_id="policy_detection_results",
                name="Detection Results Retention",
                description="Retain phishing detection results for 7 years",
                data_category=DataCategory.DETECTION_RESULTS,
                collection_name="detection_results",
                retention_period_days=2555,  # 7 years
                action=RetentionAction.ARCHIVE,
                schedule=RetentionSchedule.MONTHLY,
                date_field="timestamp",
                created_at=current_time,
                updated_at=current_time,
                compliance_frameworks=["GDPR", "SOC2"]
            ),
            
            # Audit logs - 7 years for compliance
            RetentionPolicy(
                policy_id="policy_audit_logs",
                name="Audit Logs Retention",
                description="Retain audit logs for 7 years for compliance",
                data_category=DataCategory.AUDIT_LOGS,
                collection_name="audit_logs",
                retention_period_days=2555,  # 7 years
                action=RetentionAction.ARCHIVE,
                schedule=RetentionSchedule.MONTHLY,
                date_field="timestamp",
                preserve_conditions={"requires_investigation": True},  # Keep investigation events
                created_at=current_time,
                updated_at=current_time,
                compliance_frameworks=["GDPR", "SOC2", "ISO27001"]
            ),
            
            # User activity - 3 years
            RetentionPolicy(
                policy_id="policy_user_activity",
                name="User Activity Retention",
                description="Retain user activity logs for 3 years",
                data_category=DataCategory.USER_ACTIVITY,
                collection_name="user_sessions",
                retention_period_days=1095,  # 3 years
                action=RetentionAction.DELETE,
                schedule=RetentionSchedule.WEEKLY,
                date_field="created_at",
                created_at=current_time,
                updated_at=current_time,
                compliance_frameworks=["GDPR"]
            ),
            
            # File uploads - 7 days
            RetentionPolicy(
                policy_id="policy_file_uploads",
                name="File Uploads Cleanup",
                description="Remove uploaded files after 7 days",
                data_category=DataCategory.FILE_UPLOADS,
                collection_name="file_uploads",
                retention_period_days=7,
                action=RetentionAction.DELETE,
                schedule=RetentionSchedule.DAILY,
                date_field="uploaded_at",
                preserve_conditions={"status": "processing"},  # Keep processing files
                created_at=current_time,
                updated_at=current_time,
                compliance_frameworks=["GDPR"]
            ),
            
            # Cache data - 30 days
            RetentionPolicy(
                policy_id="policy_cache_data",
                name="Cache Data Cleanup",
                description="Remove old cache entries after 30 days",
                data_category=DataCategory.CACHE_DATA,
                collection_name="cache_entries",
                retention_period_days=30,
                action=RetentionAction.DELETE,
                schedule=RetentionSchedule.DAILY,
                date_field="created_at",
                created_at=current_time,
                updated_at=current_time
            ),
            
            # Session data - 1 day
            RetentionPolicy(
                policy_id="policy_session_data",
                name="Session Data Cleanup",
                description="Remove expired session data after 1 day",
                data_category=DataCategory.SESSION_DATA,
                collection_name="user_sessions",
                retention_period_days=1,
                action=RetentionAction.DELETE,
                schedule=RetentionSchedule.DAILY,
                date_field="last_accessed",
                additional_filters={"expired": True},
                created_at=current_time,
                updated_at=current_time
            )
        ]
    
    async def _create_retention_indexes(self):
        """Create database indexes for efficient retention queries."""
        
        try:
            collections_indexes = {
                "detection_results": [("timestamp", 1)],
                "audit_logs": [("timestamp", 1), ("requires_investigation", 1)],
                "user_sessions": [("created_at", 1), ("last_accessed", 1), ("expired", 1)],
                "file_uploads": [("uploaded_at", 1), ("status", 1)],
                "cache_entries": [("created_at", 1)],
                "retention_policies": [("policy_id", 1), ("is_active", 1), ("next_execution", 1)],
                "retention_executions": [("policy_id", 1), ("started_at", 1), ("status", 1)]
            }
            
            for collection_name, indexes in collections_indexes.items():
                collection = self.db_optimizer.database[collection_name]
                
                for index_spec in indexes:
                    try:
                        await collection.create_index([index_spec])
                    except Exception as e:
                        # Index might already exist
                        logger.debug(f"Index creation skipped for {collection_name}: {e}")
            
            logger.info("Retention indexes created successfully")
            
        except Exception as e:
            logger.error(f"Error creating retention indexes: {e}")
    
    async def _load_or_create_policies(self):
        """Load existing policies or create default ones."""
        
        try:
            # Check if policies exist
            existing_count = await self.db_optimizer.database["retention_policies"].count_documents({})
            
            if existing_count == 0:
                logger.info("No existing retention policies found, creating defaults")
                
                # Create default policies
                for policy in self.default_policies:
                    await self.db_optimizer.database["retention_policies"].insert_one(
                        policy.dict()
                    )
                
                logger.info(f"Created {len(self.default_policies)} default retention policies")
            else:
                logger.info(f"Loaded {existing_count} existing retention policies")
            
        except Exception as e:
            logger.error(f"Error loading/creating retention policies: {e}")
    
    async def _schedule_retention_jobs(self):
        """Schedule retention policy executions."""
        
        try:
            policies = await self.list_policies(active_only=True)
            
            for policy in policies:
                await self._schedule_policy(policy)
            
            logger.info(f"Scheduled {len(policies)} retention policies")
            
        except Exception as e:
            logger.error(f"Error scheduling retention jobs: {e}")
    
    async def _schedule_policy(self, policy: RetentionPolicy):
        """Schedule individual policy execution."""
        
        try:
            # Calculate next execution if not set
            if not policy.next_execution:
                next_execution = self._calculate_next_execution(policy)
                await self.update_policy(policy.policy_id, {"next_execution": next_execution})
            
        except Exception as e:
            logger.error(f"Error scheduling policy {policy.policy_id}: {e}")
    
    def _calculate_next_execution(self, policy: RetentionPolicy) -> datetime:
        """Calculate next execution time for policy."""
        
        now = datetime.utcnow()
        
        if policy.schedule == RetentionSchedule.DAILY:
            return now + timedelta(days=1)
        elif policy.schedule == RetentionSchedule.WEEKLY:
            return now + timedelta(weeks=1)
        elif policy.schedule == RetentionSchedule.MONTHLY:
            return now + timedelta(days=30)
        elif policy.schedule == RetentionSchedule.QUARTERLY:
            return now + timedelta(days=90)
        elif policy.schedule == RetentionSchedule.YEARLY:
            return now + timedelta(days=365)
        else:
            return now + timedelta(days=1)  # Default to daily
    
    async def _get_due_policies(self) -> List[RetentionPolicy]:
        """Get policies that are due for execution."""
        
        try:
            now = datetime.utcnow()
            
            policies_data = await self.db_optimizer.database["retention_policies"].find({
                "is_active": True,
                "$or": [
                    {"next_execution": {"$lte": now}},
                    {"next_execution": None}
                ]
            }).to_list(length=None)
            
            return [RetentionPolicy(**policy) for policy in policies_data]
            
        except Exception as e:
            logger.error(f"Error getting due policies: {e}")
            return []
    
    async def _execute_retention_action(self, policy: RetentionPolicy,
                                      execution: RetentionExecution,
                                      dry_run: bool = False):
        """Execute retention action for policy."""
        
        try:
            # Calculate cutoff date
            cutoff_date = datetime.utcnow() - timedelta(days=policy.retention_period_days)
            
            # Build base query
            query = {
                policy.date_field: {"$lt": cutoff_date},
                **policy.additional_filters
            }
            
            # Get records to process
            collection = self.db_optimizer.database[policy.collection_name]
            
            # First, count all matching records
            total_count = await collection.count_documents(query)
            execution.records_processed = total_count
            
            if total_count == 0:
                logger.info(f"No records to process for policy {policy.policy_id}")
                return
            
            # Handle preserved records
            if policy.preserve_conditions:
                preserve_query = {**query, **policy.preserve_conditions}
                preserved_records = await collection.find(preserve_query).to_list(length=None)
                execution.records_preserved = len(preserved_records)
                
                # Exclude preserved records from processing
                if preserved_records:
                    preserved_ids = [record["_id"] for record in preserved_records]
                    query["_id"] = {"$nin": preserved_ids}
            
            # Execute action
            if not dry_run:
                if policy.action == RetentionAction.DELETE:
                    result = await collection.delete_many(query)
                    execution.records_deleted = result.deleted_count
                    
                elif policy.action == RetentionAction.ARCHIVE:
                    # Move to archive collection
                    records_to_archive = await collection.find(query).to_list(length=None)
                    
                    if records_to_archive:
                        archive_collection = self.db_optimizer.database[f"{policy.collection_name}_archive"]
                        await archive_collection.insert_many(records_to_archive)
                        
                        # Delete from original collection
                        result = await collection.delete_many(query)
                        execution.records_archived = result.deleted_count
                
                elif policy.action == RetentionAction.ANONYMIZE:
                    # Anonymize sensitive fields
                    anonymize_update = self._create_anonymization_update(policy)
                    result = await collection.update_many(query, anonymize_update)
                    execution.records_anonymized = result.modified_count
            
            else:
                # Dry run - just count records
                if policy.action == RetentionAction.DELETE:
                    execution.records_deleted = await collection.count_documents(query)
                elif policy.action == RetentionAction.ARCHIVE:
                    execution.records_archived = await collection.count_documents(query)
                elif policy.action == RetentionAction.ANONYMIZE:
                    execution.records_anonymized = await collection.count_documents(query)
            
            logger.info(f"Retention action completed for policy {policy.policy_id}: "
                       f"processed={execution.records_processed}, "
                       f"deleted={execution.records_deleted}, "
                       f"archived={execution.records_archived}, "
                       f"anonymized={execution.records_anonymized}, "
                       f"preserved={execution.records_preserved}")
            
        except Exception as e:
            execution.errors.append(f"Execution error: {str(e)}")
            logger.error(f"Error executing retention action: {e}")
            raise
    
    def _create_anonymization_update(self, policy: RetentionPolicy) -> Dict[str, Any]:
        """Create anonymization update based on data category."""
        
        # Default anonymization patterns
        anonymization_patterns = {
            DataCategory.USER_ACTIVITY: {
                "$unset": {
                    "user_id": "",
                    "ip_address": "",
                    "user_agent": ""
                },
                "$set": {
                    "anonymized": True,
                    "anonymized_at": datetime.utcnow()
                }
            },
            DataCategory.DETECTION_RESULTS: {
                "$unset": {
                    "url": "",
                    "ip_address": ""
                },
                "$set": {
                    "anonymized": True,
                    "anonymized_at": datetime.utcnow()
                }
            }
        }
        
        return anonymization_patterns.get(policy.data_category, {
            "$set": {
                "anonymized": True,
                "anonymized_at": datetime.utcnow()
            }
        })
    
    async def _validate_policy(self, policy: RetentionPolicy):
        """Validate retention policy configuration."""
        
        # Check if collection exists
        collections = await self.db_optimizer.database.list_collection_names()
        if policy.collection_name not in collections:
            raise ValueError(f"Collection does not exist: {policy.collection_name}")
        
        # Check retention period
        if policy.retention_period_days < 1:
            raise ValueError("Retention period must be at least 1 day")
        
        # Check date field exists in collection
        sample_doc = await self.db_optimizer.database[policy.collection_name].find_one()
        if sample_doc and policy.date_field not in sample_doc:
            raise ValueError(f"Date field '{policy.date_field}' not found in collection")

# Global data retention manager instance
data_retention_manager: Optional[DataRetentionManager] = None

def initialize_data_retention_manager(db_optimizer: DatabaseOptimizer,
                                    cache_manager: CacheManager,
                                    audit_logger: AuditLogger):
    """Initialize global data retention manager."""
    
    global data_retention_manager
    
    data_retention_manager = DataRetentionManager(
        db_optimizer, cache_manager, audit_logger
    )
    
    logger.info("Data retention manager initialized")