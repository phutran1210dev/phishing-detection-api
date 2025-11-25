"""File upload and processing system with security validation."""

import os
import uuid
import asyncio
import mimetypes
from typing import Dict, List, Any, Optional, BinaryIO, Union
from datetime import datetime, timedelta
from pathlib import Path
from enum import Enum
import aiofiles
import hashlib
import magic
from pydantic import BaseModel, Field, validator
from fastapi import UploadFile, HTTPException
from loguru import logger
import json
import csv
import pandas as pd
from app.core.cache import CacheManager
from app.core.database import DatabaseOptimizer
from app.security.validation import SecurityValidator
from app.core.bulk_processing import BulkProcessor, JobPriority
import zipfile
import tempfile

class FileType(str, Enum):
    """Supported file types."""
    CSV = "csv"
    JSON = "json"
    TXT = "txt"
    ZIP = "zip"
    EXCEL = "excel"
    XML = "xml"

class ProcessingStatus(str, Enum):
    """File processing status."""
    UPLOADED = "uploaded"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    EXPIRED = "expired"

class FileMetadata(BaseModel):
    """File metadata model."""
    
    file_id: str = Field(..., description="Unique file identifier")
    original_name: str = Field(..., description="Original filename")
    file_type: FileType = Field(..., description="Detected file type")
    file_size: int = Field(..., description="File size in bytes")
    mime_type: str = Field(..., description="MIME type")
    
    # Security
    hash_md5: str = Field(..., description="MD5 hash of file")
    hash_sha256: str = Field(..., description="SHA256 hash of file")
    is_safe: bool = Field(True, description="Security validation result")
    scan_results: Dict[str, Any] = Field(default_factory=dict)
    
    # Processing
    status: ProcessingStatus = Field(default=ProcessingStatus.UPLOADED)
    processing_job_id: Optional[str] = None
    extracted_count: int = Field(0, description="Number of items extracted")
    
    # Metadata
    uploaded_by: Optional[str] = None
    uploaded_at: datetime = Field(default_factory=datetime.utcnow)
    expires_at: datetime = Field(default_factory=lambda: datetime.utcnow() + timedelta(days=7))
    
    # Storage
    storage_path: str = Field(..., description="File storage path")
    processed_data_path: Optional[str] = None
    
    @validator('file_size')
    def validate_file_size(cls, v):
        max_size = 100 * 1024 * 1024  # 100MB
        if v > max_size:
            raise ValueError(f'File size exceeds maximum limit of {max_size} bytes')
        return v

class FileUploadConfig(BaseModel):
    """File upload configuration."""
    
    max_file_size: int = Field(default=100 * 1024 * 1024)  # 100MB
    allowed_types: List[FileType] = Field(default_factory=lambda: list(FileType))
    storage_path: str = Field(default="uploads")
    enable_virus_scan: bool = Field(default=True)
    auto_process: bool = Field(default=True)
    retention_days: int = Field(default=7)

class FileProcessor:
    """Process uploaded files and extract data."""
    
    def __init__(self, db_optimizer: DatabaseOptimizer,
                 cache_manager: CacheManager,
                 bulk_processor: BulkProcessor,
                 config: FileUploadConfig):
        self.db_optimizer = db_optimizer
        self.cache_manager = cache_manager
        self.bulk_processor = bulk_processor
        self.config = config
        self.security_validator = SecurityValidator()
        
        # Create storage directory
        self.storage_path = Path(config.storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Register file processing job types
        self.bulk_processor.register_processor("file_urls_detection", self._process_urls_file)
        self.bulk_processor.register_processor("file_data_import", self._process_data_import)
        
        logger.info("File processor initialized")
    
    async def upload_file(self, file: UploadFile, 
                         user_id: Optional[str] = None,
                         auto_process: bool = None) -> FileMetadata:
        """Handle file upload with security validation."""
        
        try:
            # Validate file
            await self._validate_upload(file)
            
            # Generate file ID and paths
            file_id = f"file_{uuid.uuid4().hex}"
            safe_filename = self._sanitize_filename(file.filename)
            file_path = self.storage_path / f"{file_id}_{safe_filename}"
            
            # Read file content for validation
            content = await file.read()
            await file.seek(0)  # Reset file pointer
            
            # Security validation
            security_results = await self._security_scan(content, file.filename)
            if not security_results["is_safe"]:
                raise HTTPException(
                    status_code=400,
                    detail=f"File failed security scan: {security_results['threats']}"
                )
            
            # Detect file type
            detected_type = self._detect_file_type(content, file.filename)
            
            # Calculate hashes
            md5_hash = hashlib.md5(content).hexdigest()
            sha256_hash = hashlib.sha256(content).hexdigest()
            
            # Save file to storage
            async with aiofiles.open(file_path, 'wb') as f:
                await f.write(content)
            
            # Create file metadata
            metadata = FileMetadata(
                file_id=file_id,
                original_name=file.filename,
                file_type=detected_type,
                file_size=len(content),
                mime_type=file.content_type or "application/octet-stream",
                hash_md5=md5_hash,
                hash_sha256=sha256_hash,
                is_safe=security_results["is_safe"],
                scan_results=security_results,
                uploaded_by=user_id,
                storage_path=str(file_path)
            )
            
            # Store metadata in database
            await self._save_file_metadata(metadata)
            
            # Auto-process if enabled
            if auto_process or (auto_process is None and self.config.auto_process):
                await self.process_file(file_id, user_id)
            
            logger.info(f"File uploaded successfully: {file_id} ({file.filename})")
            return metadata
            
        except Exception as e:
            logger.error(f"File upload error: {e}")
            raise HTTPException(status_code=500, detail=str(e))
    
    async def process_file(self, file_id: str, user_id: Optional[str] = None,
                          processing_type: str = "auto") -> str:
        """Process uploaded file and extract data."""
        
        try:
            # Get file metadata
            metadata = await self.get_file_metadata(file_id)
            if not metadata:
                raise ValueError("File not found")
            
            if metadata.status != ProcessingStatus.UPLOADED:
                raise ValueError(f"File already processed or in progress: {metadata.status}")
            
            # Update status
            metadata.status = ProcessingStatus.PROCESSING
            await self._save_file_metadata(metadata)
            
            # Determine processing type based on file content
            if processing_type == "auto":
                processing_type = await self._determine_processing_type(metadata)
            
            # Extract data from file
            extracted_data = await self._extract_file_data(metadata)
            
            # Submit bulk processing job
            job_id = await self.bulk_processor.submit_job(
                job_type=processing_type,
                items=extracted_data,
                priority=JobPriority.NORMAL,
                user_id=user_id,
                file_id=file_id
            )
            
            # Update metadata
            metadata.processing_job_id = job_id
            metadata.extracted_count = len(extracted_data)
            await self._save_file_metadata(metadata)
            
            logger.info(f"File processing started: {file_id} -> job {job_id}")
            return job_id
            
        except Exception as e:
            # Mark as failed
            if 'metadata' in locals():
                metadata.status = ProcessingStatus.FAILED
                await self._save_file_metadata(metadata)
            
            logger.error(f"File processing error: {e}")
            raise
    
    async def get_file_metadata(self, file_id: str) -> Optional[FileMetadata]:
        """Get file metadata."""
        
        try:
            # Try cache first
            cached_data = await self.cache_manager.get(f"file_metadata:{file_id}")
            if cached_data:
                return FileMetadata(**cached_data)
            
            # Try database
            file_data = await self.db_optimizer.database["file_uploads"].find_one(
                {"file_id": file_id}
            )
            
            if file_data:
                metadata = FileMetadata(**file_data)
                
                # Cache for future requests
                await self.cache_manager.set(
                    f"file_metadata:{file_id}",
                    metadata.dict(),
                    ttl=3600
                )
                
                return metadata
            
        except Exception as e:
            logger.error(f"Error getting file metadata {file_id}: {e}")
        
        return None
    
    async def delete_file(self, file_id: str) -> bool:
        """Delete uploaded file and metadata."""
        
        try:
            metadata = await self.get_file_metadata(file_id)
            if not metadata:
                return False
            
            # Delete file from storage
            file_path = Path(metadata.storage_path)
            if file_path.exists():
                file_path.unlink()
            
            # Delete processed data if exists
            if metadata.processed_data_path:
                processed_path = Path(metadata.processed_data_path)
                if processed_path.exists():
                    processed_path.unlink()
            
            # Remove from database
            await self.db_optimizer.database["file_uploads"].delete_one(
                {"file_id": file_id}
            )
            
            # Remove from cache
            await self.cache_manager.delete(f"file_metadata:{file_id}")
            
            logger.info(f"File deleted: {file_id}")
            return True
            
        except Exception as e:
            logger.error(f"Error deleting file {file_id}: {e}")
            return False
    
    async def list_files(self, user_id: Optional[str] = None,
                        status: Optional[ProcessingStatus] = None,
                        limit: int = 50) -> List[FileMetadata]:
        """List uploaded files with filtering."""
        
        try:
            query_filters = {}
            
            if user_id:
                query_filters["uploaded_by"] = user_id
            
            if status:
                query_filters["status"] = status.value
            
            files_data = await self.db_optimizer.optimize_query(
                "file_uploads",
                query_filters,
                sort=[("uploaded_at", -1)],
                limit=limit,
                use_cache=True,
                cache_ttl=300
            )
            
            return [FileMetadata(**file_data) for file_data in files_data]
            
        except Exception as e:
            logger.error(f"Error listing files: {e}")
            return []
    
    async def cleanup_expired_files(self) -> int:
        """Clean up expired files."""
        
        try:
            expired_files = await self.db_optimizer.optimize_query(
                "file_uploads",
                {"expires_at": {"$lt": datetime.utcnow()}},
                limit=1000
            )
            
            deleted_count = 0
            for file_data in expired_files:
                metadata = FileMetadata(**file_data)
                if await self.delete_file(metadata.file_id):
                    deleted_count += 1
            
            logger.info(f"Cleaned up {deleted_count} expired files")
            return deleted_count
            
        except Exception as e:
            logger.error(f"Error cleaning up expired files: {e}")
            return 0
    
    async def _validate_upload(self, file: UploadFile):
        """Validate uploaded file."""
        
        # Check file size
        if hasattr(file, 'size') and file.size > self.config.max_file_size:
            raise HTTPException(
                status_code=413,
                detail=f"File too large. Maximum size: {self.config.max_file_size} bytes"
            )
        
        # Check filename
        if not file.filename:
            raise HTTPException(status_code=400, detail="Filename is required")
        
        # Check for dangerous extensions
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com']
        if any(file.filename.lower().endswith(ext) for ext in dangerous_extensions):
            raise HTTPException(status_code=400, detail="File type not allowed")
    
    def _sanitize_filename(self, filename: str) -> str:
        """Sanitize filename for safe storage."""
        
        # Remove path components
        filename = os.path.basename(filename)
        
        # Replace dangerous characters
        safe_chars = "".join(c for c in filename if c.isalnum() or c in '.-_')
        
        # Ensure reasonable length
        if len(safe_chars) > 100:
            name, ext = os.path.splitext(safe_chars)
            safe_chars = name[:90] + ext
        
        return safe_chars or "unknown_file"
    
    def _detect_file_type(self, content: bytes, filename: str) -> FileType:
        """Detect file type from content and filename."""
        
        # Try to detect from content using python-magic
        try:
            mime = magic.from_buffer(content, mime=True)
            
            if mime == 'text/csv':
                return FileType.CSV
            elif mime == 'application/json':
                return FileType.JSON
            elif mime == 'text/plain':
                return FileType.TXT
            elif mime == 'application/zip':
                return FileType.ZIP
            elif mime in ['application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet']:
                return FileType.EXCEL
            elif mime in ['application/xml', 'text/xml']:
                return FileType.XML
                
        except Exception as e:
            logger.warning(f"Magic detection failed: {e}")
        
        # Fall back to extension detection
        ext = os.path.splitext(filename)[1].lower()
        
        if ext == '.csv':
            return FileType.CSV
        elif ext == '.json':
            return FileType.JSON
        elif ext in ['.txt', '.log']:
            return FileType.TXT
        elif ext == '.zip':
            return FileType.ZIP
        elif ext in ['.xls', '.xlsx']:
            return FileType.EXCEL
        elif ext == '.xml':
            return FileType.XML
        
        # Default to text
        return FileType.TXT
    
    async def _security_scan(self, content: bytes, filename: str) -> Dict[str, Any]:
        """Perform security scan on file content."""
        
        threats = []
        
        # Check file size
        if len(content) > self.config.max_file_size:
            threats.append("File too large")
        
        # Check for suspicious patterns in content
        suspicious_patterns = [
            b'<script',
            b'javascript:',
            b'vbscript:',
            b'<?php',
            b'<%',
            b'#!/bin/',
            b'powershell',
            b'cmd.exe'
        ]
        
        content_lower = content.lower()
        for pattern in suspicious_patterns:
            if pattern in content_lower:
                threats.append(f"Suspicious pattern detected: {pattern.decode('utf-8', errors='ignore')}")
        
        # Check filename for suspicious extensions
        dangerous_extensions = ['.exe', '.bat', '.cmd', '.scr', '.pif', '.com', '.ps1']
        if any(filename.lower().endswith(ext) for ext in dangerous_extensions):
            threats.append("Dangerous file extension")
        
        return {
            "is_safe": len(threats) == 0,
            "threats": threats,
            "scan_timestamp": datetime.utcnow().isoformat(),
            "file_size": len(content)
        }
    
    async def _determine_processing_type(self, metadata: FileMetadata) -> str:
        """Determine processing type based on file content."""
        
        if metadata.file_type in [FileType.CSV, FileType.TXT, FileType.JSON]:
            # Check if file contains URLs
            sample_content = await self._read_file_sample(metadata.storage_path)
            
            # Simple heuristic: if sample contains http/https, it's likely URLs
            if 'http' in sample_content.lower():
                return "file_urls_detection"
        
        return "file_data_import"
    
    async def _read_file_sample(self, file_path: str, sample_size: int = 1024) -> str:
        """Read a sample of file content."""
        
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return await f.read(sample_size)
        except Exception as e:
            logger.warning(f"Error reading file sample: {e}")
            return ""
    
    async def _extract_file_data(self, metadata: FileMetadata) -> List[str]:
        """Extract data from uploaded file."""
        
        file_path = Path(metadata.storage_path)
        
        try:
            if metadata.file_type == FileType.CSV:
                return await self._extract_csv_data(file_path)
            elif metadata.file_type == FileType.JSON:
                return await self._extract_json_data(file_path)
            elif metadata.file_type == FileType.TXT:
                return await self._extract_text_data(file_path)
            elif metadata.file_type == FileType.ZIP:
                return await self._extract_zip_data(file_path)
            elif metadata.file_type == FileType.EXCEL:
                return await self._extract_excel_data(file_path)
            elif metadata.file_type == FileType.XML:
                return await self._extract_xml_data(file_path)
            else:
                raise ValueError(f"Unsupported file type: {metadata.file_type}")
                
        except Exception as e:
            logger.error(f"Error extracting data from {metadata.file_id}: {e}")
            raise
    
    async def _extract_csv_data(self, file_path: Path) -> List[str]:
        """Extract data from CSV file."""
        
        data = []
        
        async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = await f.read()
        
        # Use pandas for robust CSV parsing
        try:
            df = pd.read_csv(io.StringIO(content))
            
            # Look for URL columns
            url_columns = []
            for col in df.columns:
                if 'url' in col.lower() or 'link' in col.lower() or 'website' in col.lower():
                    url_columns.append(col)
            
            if url_columns:
                # Extract URLs from identified columns
                for col in url_columns:
                    urls = df[col].dropna().astype(str).tolist()
                    data.extend(urls)
            else:
                # If no URL columns found, assume first column contains data
                if not df.empty:
                    data = df.iloc[:, 0].dropna().astype(str).tolist()
            
        except Exception as e:
            # Fall back to simple CSV parsing
            logger.warning(f"Pandas CSV parsing failed, using fallback: {e}")
            
            import csv
            import io
            
            reader = csv.reader(io.StringIO(content))
            for row in reader:
                if row:  # Skip empty rows
                    data.append(row[0])  # Take first column
        
        return [item for item in data if item.strip()]
    
    async def _extract_json_data(self, file_path: Path) -> List[str]:
        """Extract data from JSON file."""
        
        async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
            content = await f.read()
        
        try:
            json_data = json.loads(content)
            
            data = []
            
            if isinstance(json_data, list):
                # Array of items
                for item in json_data:
                    if isinstance(item, str):
                        data.append(item)
                    elif isinstance(item, dict):
                        # Look for URL-like fields
                        for key, value in item.items():
                            if 'url' in key.lower() and isinstance(value, str):
                                data.append(value)
                                break
                        else:
                            # If no URL field found, take first string value
                            for value in item.values():
                                if isinstance(value, str):
                                    data.append(value)
                                    break
            
            elif isinstance(json_data, dict):
                # Object with arrays or values
                for key, value in json_data.items():
                    if isinstance(value, list):
                        data.extend([str(v) for v in value if v])
                    elif isinstance(value, str):
                        data.append(value)
            
            return [item for item in data if item.strip()]
            
        except Exception as e:
            logger.error(f"JSON parsing error: {e}")
            raise ValueError("Invalid JSON format")
    
    async def _extract_text_data(self, file_path: Path) -> List[str]:
        """Extract data from text file."""
        
        async with aiofiles.open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = await f.read()
        
        # Split by lines and filter empty lines
        lines = [line.strip() for line in content.split('\n') if line.strip()]
        
        return lines
    
    async def _extract_zip_data(self, file_path: Path) -> List[str]:
        """Extract data from ZIP file."""
        
        data = []
        
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Extract ZIP file
                with zipfile.ZipFile(file_path, 'r') as zip_file:
                    zip_file.extractall(temp_dir)
                
                # Process extracted files
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        extracted_path = Path(root) / file
                        
                        # Determine file type and extract
                        file_type = self._detect_file_type(
                            extracted_path.read_bytes(),
                            file
                        )
                        
                        if file_type == FileType.CSV:
                            file_data = await self._extract_csv_data(extracted_path)
                        elif file_type == FileType.JSON:
                            file_data = await self._extract_json_data(extracted_path)
                        elif file_type == FileType.TXT:
                            file_data = await self._extract_text_data(extracted_path)
                        else:
                            continue
                        
                        data.extend(file_data)
            
            except Exception as e:
                logger.error(f"ZIP extraction error: {e}")
                raise ValueError("Failed to extract ZIP file")
        
        return data
    
    async def _extract_excel_data(self, file_path: Path) -> List[str]:
        """Extract data from Excel file."""
        
        try:
            # Read Excel file with pandas
            df = pd.read_excel(file_path)
            
            data = []
            
            # Look for URL columns first
            url_columns = []
            for col in df.columns:
                if 'url' in str(col).lower() or 'link' in str(col).lower():
                    url_columns.append(col)
            
            if url_columns:
                for col in url_columns:
                    urls = df[col].dropna().astype(str).tolist()
                    data.extend(urls)
            else:
                # Take first column if no URL columns found
                if not df.empty:
                    data = df.iloc[:, 0].dropna().astype(str).tolist()
            
            return [item for item in data if str(item).strip()]
            
        except Exception as e:
            logger.error(f"Excel parsing error: {e}")
            raise ValueError("Failed to parse Excel file")
    
    async def _extract_xml_data(self, file_path: Path) -> List[str]:
        """Extract data from XML file."""
        
        try:
            import xml.etree.ElementTree as ET
            
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                content = await f.read()
            
            root = ET.fromstring(content)
            data = []
            
            # Extract text content from all elements
            for elem in root.iter():
                if elem.text and elem.text.strip():
                    text = elem.text.strip()
                    # Check if it looks like a URL or data we want
                    if ('http' in text.lower() or 
                        len(text) > 10 and '.' in text):
                        data.append(text)
            
            return data
            
        except Exception as e:
            logger.error(f"XML parsing error: {e}")
            raise ValueError("Failed to parse XML file")
    
    async def _process_urls_file(self, url: str, **kwargs) -> Dict[str, Any]:
        """Process URL from file upload for phishing detection."""
        
        # This would integrate with the main phishing detection system
        # For now, return a placeholder
        
        return {
            "url": url,
            "is_phishing": False,  # Would be actual detection result
            "confidence": 0.5,
            "processed_at": datetime.utcnow().isoformat()
        }
    
    async def _process_data_import(self, data_item: str, **kwargs) -> Dict[str, Any]:
        """Process data import from file."""
        
        return {
            "data": data_item,
            "imported": True,
            "processed_at": datetime.utcnow().isoformat()
        }
    
    async def _save_file_metadata(self, metadata: FileMetadata):
        """Save file metadata to database and cache."""
        
        try:
            # Save to database
            await self.db_optimizer.database["file_uploads"].update_one(
                {"file_id": metadata.file_id},
                {"$set": metadata.dict()},
                upsert=True
            )
            
            # Update cache
            await self.cache_manager.set(
                f"file_metadata:{metadata.file_id}",
                metadata.dict(),
                ttl=3600
            )
            
        except Exception as e:
            logger.error(f"Error saving file metadata: {e}")

# Import required modules for file processing
import io

# Global file processor instance
file_processor: Optional[FileProcessor] = None

def initialize_file_processor(db_optimizer: DatabaseOptimizer,
                            cache_manager: CacheManager,
                            bulk_processor: BulkProcessor,
                            config: FileUploadConfig = None):
    """Initialize global file processor."""
    
    global file_processor
    
    if config is None:
        config = FileUploadConfig()
    
    file_processor = FileProcessor(
        db_optimizer, cache_manager, bulk_processor, config
    )
    
    logger.info("File processor system initialized")