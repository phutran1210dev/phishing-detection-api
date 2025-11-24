"""Test configuration and fixtures."""

import pytest
import asyncio
from fastapi.testclient import TestClient
from httpx import AsyncClient
import numpy as np

from app.main import app
from app.database import connect_to_mongo, close_mongo_connection

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(scope="session")
async def setup_database():
    """Setup test database."""
    await connect_to_mongo()
    yield
    await close_mongo_connection()

@pytest.fixture
def client():
    """Create test client."""
    return TestClient(app)

@pytest.fixture
async def async_client():
    """Create async test client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac

@pytest.fixture
def sample_urls():
    """Sample URLs for testing."""
    return [
        "https://www.google.com",
        "https://www.github.com",
        "https://phishing-example.com",
        "http://suspicious-site.tk"
    ]

@pytest.fixture 
def sample_features():
    """Sample feature vectors for testing."""
    return np.random.rand(10, 20)

@pytest.fixture
def sample_labels():
    """Sample labels for testing."""
    return np.random.randint(0, 2, 10)