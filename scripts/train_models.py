#!/usr/bin/env python3
"""
Training script for phishing detection models.
This script trains all ML models and saves them to the models directory.
"""

import asyncio
import os
import sys
from pathlib import Path

# Add app to path
sys.path.append(str(Path(__file__).parent))

from app.ml.training.trainer import ModelTrainer
from loguru import logger

async def main():
    """Train all phishing detection models."""
    
    logger.info("Starting model training process")
    
    try:
        trainer = ModelTrainer()
        
        # Train all models
        await trainer.train_models()
        
        logger.info("Model training completed successfully")
        
    except Exception as e:
        logger.error(f"Model training failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())