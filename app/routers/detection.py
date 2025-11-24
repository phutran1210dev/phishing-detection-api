"""Detection API endpoints."""

from fastapi import APIRouter, HTTPException, Depends
from typing import List
import time
from loguru import logger

from app.models import (
    URLDetectionRequest,
    BatchURLDetectionRequest,
    DetectionResponse,
    BatchDetectionResponse,
    PhishingResult
)
from app.ml.inference.predictor import PhishingPredictor
from app.utils.rate_limiter import rate_limit

router = APIRouter()

# Initialize predictor (will be loaded once)
predictor = PhishingPredictor()

@router.post("/url", response_model=DetectionResponse)
async def detect_phishing_url(
    request: URLDetectionRequest,
    _: None = Depends(rate_limit)
):
    """Detect phishing for a single URL."""
    start_time = time.time()
    
    try:
        url_str = str(request.url)
        logger.info(f"Analyzing URL: {url_str}")
        
        # Perform prediction
        result = await predictor.predict_single(url_str, request.include_features)
        
        processing_time = (time.time() - start_time) * 1000
        
        # Determine result classification
        if result["probability"] >= 0.8:
            classification = PhishingResult.PHISHING
        elif result["probability"] >= 0.3:
            classification = PhishingResult.SUSPICIOUS
        else:
            classification = PhishingResult.LEGITIMATE
        
        response = DetectionResponse(
            url=url_str,
            is_phishing=result["is_phishing"],
            probability=result["probability"],
            result=classification,
            confidence=result["confidence"],
            processing_time_ms=processing_time,
            features=result.get("features")
        )
        
        logger.info(f"URL analysis complete: {url_str} -> {classification} (p={result['probability']:.3f})")
        return response
        
    except Exception as e:
        logger.error(f"Error analyzing URL {url_str}: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@router.post("/batch", response_model=BatchDetectionResponse)
async def detect_phishing_batch(
    request: BatchURLDetectionRequest,
    _: None = Depends(rate_limit)
):
    """Detect phishing for multiple URLs."""
    start_time = time.time()
    
    try:
        urls = [str(url) for url in request.urls]
        logger.info(f"Analyzing {len(urls)} URLs in batch")
        
        # Perform batch prediction
        results = await predictor.predict_batch(urls, request.include_features)
        
        processing_time = (time.time() - start_time) * 1000
        
        # Convert results to response format
        detection_results = []
        for i, result in enumerate(results):
            # Determine result classification
            if result["probability"] >= 0.8:
                classification = PhishingResult.PHISHING
            elif result["probability"] >= 0.3:
                classification = PhishingResult.SUSPICIOUS
            else:
                classification = PhishingResult.LEGITIMATE
            
            detection_result = DetectionResponse(
                url=urls[i],
                is_phishing=result["is_phishing"],
                probability=result["probability"],
                result=classification,
                confidence=result["confidence"],
                processing_time_ms=result["processing_time_ms"],
                features=result.get("features")
            )
            detection_results.append(detection_result)
        
        response = BatchDetectionResponse(
            results=detection_results,
            total_processed=len(urls),
            processing_time_ms=processing_time
        )
        
        logger.info(f"Batch analysis complete: {len(urls)} URLs processed in {processing_time:.2f}ms")
        return response
        
    except Exception as e:
        logger.error(f"Error in batch analysis: {e}")
        raise HTTPException(status_code=500, detail=f"Batch analysis failed: {str(e)}")

@router.get("/stats")
async def get_detection_stats():
    """Get detection statistics."""
    try:
        stats = await predictor.get_statistics()
        return stats
    except Exception as e:
        logger.error(f"Error getting detection stats: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get statistics: {str(e)}")