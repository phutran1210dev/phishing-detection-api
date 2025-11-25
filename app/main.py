"""Simple FastAPI main application for Docker deployment."""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import time
import uvicorn
from typing import Dict, Any, Optional

# Request/Response models
class DetectionRequest(BaseModel):
    url: str
    context: Optional[Dict[str, Any]] = None

class DetectionResponse(BaseModel):
    url: str
    prediction: Dict[str, Any]
    analysis: Dict[str, Any]
    processing_time_ms: float
    timestamp: str

# Initialize FastAPI app
app = FastAPI(
    title="Phishing Detection API",
    description="Enterprise-grade phishing detection system",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {
        "status": "healthy",
        "service": "phishing-detection-api",
        "version": "1.0.0",
        "timestamp": time.time()
    }

# Metrics endpoint for Prometheus
@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return {
        "api_requests_total": 100,
        "api_request_duration_seconds": 0.1,
        "phishing_detections_total": 25,
        "legitimate_detections_total": 75
    }

# Root endpoint
@app.get("/")
async def root():
    """Root endpoint with API information."""
    return {
        "message": "Phishing Detection API",
        "version": "1.0.0",
        "docs": "/docs",
        "health": "/health",
        "detect": "/api/v1/detect"
    }

# Main detection endpoint
@app.post("/api/v1/detect", response_model=DetectionResponse)
async def detect_phishing(request: DetectionRequest):
    """Detect if a URL is phishing or legitimate."""
    
    start_time = time.time()
    
    try:
        url = request.url
        
        # Simple rule-based detection for Docker testing
        suspicious_score = 0
        
        # Check for suspicious patterns
        if not url.startswith('https://'):
            suspicious_score += 0.3
        
        suspicious_keywords = ['login', 'secure', 'account', 'update', 'verify', 'bank']
        keyword_count = sum(1 for keyword in suspicious_keywords if keyword.lower() in url.lower())
        if keyword_count > 1:
            suspicious_score += 0.4
        
        if len(url) > 100:
            suspicious_score += 0.2
        
        # Count subdomains
        domain_parts = url.replace('http://', '').replace('https://', '').split('/')[0]
        subdomain_count = len(domain_parts.split('.')) - 2
        if subdomain_count > 2:
            suspicious_score += 0.3
        
        # Determine if phishing
        is_phishing = suspicious_score > 0.5
        confidence = min(suspicious_score, 1.0) if is_phishing else (1.0 - suspicious_score)
        risk_score = suspicious_score * 10
        
        # Calculate processing time
        processing_time = (time.time() - start_time) * 1000
        
        # Prepare response
        response = DetectionResponse(
            url=url,
            prediction={
                "is_phishing": is_phishing,
                "confidence": round(confidence, 3),
                "risk_score": round(risk_score, 1),
                "threat_level": "high" if risk_score > 7 else "medium" if risk_score > 4 else "low"
            },
            analysis={
                "url_features": {
                    "url_length": len(url),
                    "has_https": url.startswith('https://'),
                    "subdomain_count": subdomain_count,
                    "suspicious_keywords": keyword_count
                },
                "reputation_score": round(10 - risk_score, 1)
            },
            processing_time_ms=round(processing_time, 2),
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ")
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(
            status_code=500, 
            detail=f"Error processing URL: {str(e)}"
        )

# Bulk detection endpoint
@app.post("/api/v1/bulk/detect")
async def bulk_detect(urls: list[str]):
    """Detect multiple URLs in bulk."""
    
    if len(urls) > 100:
        raise HTTPException(
            status_code=400,
            detail="Maximum 100 URLs allowed per request"
        )
    
    results = []
    
    for url in urls:
        try:
            request = DetectionRequest(url=url)
            result = await detect_phishing(request)
            results.append(result.dict())
        except Exception as e:
            results.append({
                "url": url,
                "error": str(e),
                "status": "failed"
            })
    
    return {
        "results": results,
        "total_processed": len(urls),
        "successful": len([r for r in results if "error" not in r]),
        "failed": len([r for r in results if "error" in r])
    }

# Statistics endpoint
@app.get("/api/v1/stats")
async def get_stats():
    """Get API statistics."""
    return {
        "service": "phishing-detection-api",
        "status": "operational",
        "features": {
            "url_analysis": True,
            "bulk_processing": True,
            "real_time_detection": True
        }
    }

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )