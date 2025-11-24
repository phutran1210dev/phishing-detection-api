"""Model management API endpoints."""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from loguru import logger

from app.models import ModelStatus, ModelInfo, TrainingRequest
from app.ml.training.trainer import ModelTrainer
from app.ml.inference.predictor import PhishingPredictor

router = APIRouter()

# Initialize components
trainer = ModelTrainer()
predictor = PhishingPredictor()

@router.get("/status", response_model=ModelStatus)
async def get_model_status():
    """Get current model status and information."""
    try:
        models_info = await predictor.get_model_info()
        
        model_list = []
        for model_name, info in models_info.items():
            model_info = ModelInfo(
                name=model_name,
                version=info["version"],
                accuracy=info["accuracy"],
                precision=info["precision"],
                recall=info["recall"],
                f1_score=info["f1_score"],
                last_trained=info["last_trained"],
                total_samples=info["total_samples"]
            )
            model_list.append(model_info)
        
        status = ModelStatus(
            status="ready" if models_info else "no_models",
            models=model_list,
            last_update=max(info["last_trained"] for info in models_info.values()) if models_info else None
        )
        
        return status
        
    except Exception as e:
        logger.error(f"Error getting model status: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get model status: {str(e)}")

@router.post("/retrain")
async def retrain_models(
    request: TrainingRequest,
    background_tasks: BackgroundTasks
):
    """Trigger model retraining."""
    try:
        logger.info(f"Starting model retraining: {request.model_name or 'all models'}")
        
        # Add training task to background
        background_tasks.add_task(
            trainer.train_models,
            model_name=request.model_name,
            use_new_data=request.use_new_data
        )
        
        return {
            "message": "Model retraining started",
            "model": request.model_name or "all",
            "status": "training_initiated"
        }
        
    except Exception as e:
        logger.error(f"Error starting model retraining: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start retraining: {str(e)}")

@router.get("/metrics")
async def get_model_metrics():
    """Get detailed model performance metrics."""
    try:
        metrics = await predictor.get_detailed_metrics()
        return metrics
        
    except Exception as e:
        logger.error(f"Error getting model metrics: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get metrics: {str(e)}")

@router.get("/info")
async def get_model_info():
    """Get comprehensive model information."""
    try:
        info = await predictor.get_comprehensive_info()
        return info
        
    except Exception as e:
        logger.error(f"Error getting model info: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to get model info: {str(e)}")

@router.post("/reload")
async def reload_models():
    """Reload models from disk."""
    try:
        await predictor.reload_models()
        
        return {
            "message": "Models reloaded successfully",
            "status": "success"
        }
        
    except Exception as e:
        logger.error(f"Error reloading models: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reload models: {str(e)}")