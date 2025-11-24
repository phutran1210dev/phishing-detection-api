"""Database connection and management."""

import motor.motor_asyncio
from pymongo.errors import ConnectionFailure
from loguru import logger
from app.config import settings

class Database:
    client: motor.motor_asyncio.AsyncIOMotorClient = None
    database: motor.motor_asyncio.AsyncIOMotorDatabase = None

db = Database()

async def connect_to_mongo():
    """Create database connection."""
    try:
        db.client = motor.motor_asyncio.AsyncIOMotorClient(
            settings.database_url,
            serverSelectionTimeoutMS=5000
        )
        
        # Test connection
        await db.client.admin.command('ping')
        db.database = db.client[settings.database_name]
        
        logger.info("Connected to MongoDB successfully")
        
        # Create indexes
        await create_indexes()
        
    except ConnectionFailure as e:
        logger.error(f"Failed to connect to MongoDB: {e}")
        raise e

async def close_mongo_connection():
    """Close database connection."""
    if db.client:
        db.client.close()
        logger.info("Disconnected from MongoDB")

async def create_indexes():
    """Create necessary database indexes."""
    try:
        # Create indexes for collections
        await db.database.detections.create_index([("url", 1), ("timestamp", -1)])
        await db.database.training_data.create_index([("url", 1)])
        await db.database.model_metadata.create_index([("model_name", 1), ("version", 1)])
        
        logger.info("Database indexes created successfully")
        
    except Exception as e:
        logger.error(f"Failed to create database indexes: {e}")

def get_database() -> motor.motor_asyncio.AsyncIOMotorDatabase:
    """Get database instance."""
    return db.database