"""Main FastAPI application module."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
from loguru import logger

from app.config import settings
from app.database import connect_to_mongo, close_mongo_connection
from app.routers import detection, models, health

# Configure logging
logger.add(
    "logs/app.log",
    rotation="1 day",
    retention="30 days",
    level=settings.log_level,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}"
)

app = FastAPI(
    title="Phishing Detection API",
    description="Machine learning-powered API for real-time phishing detection",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(detection.router, prefix=f"{settings.api_prefix}/detect", tags=["detection"])
app.include_router(models.router, prefix=f"{settings.api_prefix}/models", tags=["models"])
app.include_router(health.router, prefix=f"{settings.api_prefix}", tags=["health"])

@app.on_event("startup")
async def startup_event():
    """Initialize application on startup."""
    logger.info("Starting Phishing Detection API")
    await connect_to_mongo()
    logger.info("Application startup complete")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on application shutdown."""
    logger.info("Shutting down Phishing Detection API")
    await close_mongo_connection()
    logger.info("Application shutdown complete")

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.error(f"Unhandled exception: {exc}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"}
    )

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "message": "Phishing Detection API",
        "version": "1.0.0",
        "docs": "/docs"
    }

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )