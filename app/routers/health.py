"""Health check API endpoints."""

from fastapi import APIRouter
import time
from datetime import datetime
from loguru import logger

from app.models import HealthResponse
from app.database import get_database
from app.ml.inference.predictor import PhishingPredictor

router = APIRouter()

# Application start time for uptime calculation
START_TIME = time.time()

@router.get("/health", response_model=HealthResponse)
async def health_check():
    """Comprehensive health check."""
    try:
        # Check database
        try:
            db = get_database()
            await db.command("ping")
            database_status = "healthy"
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            database_status = "unhealthy"
        
        # Check models
        try:
            predictor = PhishingPredictor()
            model_info = await predictor.get_model_info()
            models_status = "healthy" if model_info else "no_models"
        except Exception as e:
            logger.error(f"Models health check failed: {e}")
            models_status = "unhealthy"
        
        # Calculate uptime
        uptime = time.time() - START_TIME
        
        # Determine overall status
        overall_status = "healthy"
        if database_status != "healthy" or models_status == "unhealthy":
            overall_status = "degraded"
        elif models_status == "no_models":
            overall_status = "partial"
        
        return HealthResponse(
            status=overall_status,
            database=database_status,
            models=models_status,
            uptime_seconds=uptime,
            version="1.0.0"
        )
        
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return HealthResponse(
            status="unhealthy",
            database="unknown",
            models="unknown",
            uptime_seconds=time.time() - START_TIME,
            version="1.0.0"
        )

@router.get("/ping")
async def ping():
    """Simple ping endpoint."""
    return {"message": "pong", "timestamp": datetime.utcnow().isoformat()}

@router.get("/status")
async def status():
    """Basic status endpoint."""
    return {
        "status": "running",
        "service": "phishing-detection-api",
        "version": "1.0.0",
        "uptime_seconds": time.time() - START_TIME
    }