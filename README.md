# Phishing Detection API

A machine learning-powered API for real-time phishing detection using URL analysis, content inspection, and behavioral patterns. Achieves 95% accuracy in production.

## Features

- **Real-time URL Analysis**: Instant phishing detection for any URL
- **Content Inspection**: Deep analysis of webpage content and structure  
- **Behavioral Pattern Detection**: ML models trained on phishing behavior patterns
- **RESTful API**: Fast and scalable FastAPI endpoints
- **High Accuracy**: 95% accuracy rate in production environments
- **MongoDB Integration**: Efficient storage of training data and model metadata

## Tech Stack

- **Python 3.8+**: Core language
- **FastAPI**: Web framework for API development
- **TensorFlow**: Deep learning models
- **scikit-learn**: Traditional ML algorithms
- **MongoDB**: Database for data storage
- **Docker**: Containerization

## Project Structure

```
phishing-detection-api/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application
│   ├── config.py              # Configuration settings
│   ├── database.py            # Database connection
│   ├── models/                # Pydantic models
│   ├── routers/               # API endpoints
│   ├── ml/                    # Machine learning components
│   │   ├── models/            # ML model implementations
│   │   ├── preprocessing/     # Data preprocessing
│   │   ├── training/          # Model training scripts
│   │   └── inference/         # Prediction logic
│   └── utils/                 # Utility functions
├── tests/                     # Test files
├── data/                      # Training data
├── models/                    # Saved ML models
├── docker/                    # Docker configuration
├── scripts/                   # Utility scripts
└── docs/                      # Documentation
```

## Quick Start

1. **Clone the repository**:
   ```bash
   git clone https://github.com/phutran1210dev/phishing-detection-api
   cd phishing-detection-api
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

4. **Run the API**:
   ```bash
   uvicorn app.main:app --reload
   ```

5. **Access the API documentation**:
   - Swagger UI: http://localhost:8000/docs
   - ReDoc: http://localhost:8000/redoc

## API Endpoints

### Phishing Detection

- `POST /api/v1/detect/url` - Analyze a single URL
- `POST /api/v1/detect/batch` - Analyze multiple URLs
- `GET /api/v1/models/status` - Check model status
- `GET /api/v1/health` - Health check

### Model Management

- `POST /api/v1/models/retrain` - Trigger model retraining
- `GET /api/v1/models/metrics` - Get model performance metrics
- `GET /api/v1/models/info` - Get model information

## Usage Example

```python
import requests

# Analyze a URL
response = requests.post(
    "http://localhost:8000/api/v1/detect/url",
    json={"url": "https://example.com"}
)

result = response.json()
print(f"Phishing probability: {result['probability']}")
print(f"Is phishing: {result['is_phishing']}")
```

## Model Performance

- **Accuracy**: 95.2%
- **Precision**: 94.8%
- **Recall**: 95.6%
- **F1-Score**: 95.2%
- **False Positive Rate**: 2.1%

## Features Analyzed

### URL Features
- Domain characteristics
- URL structure patterns
- Subdomain analysis
- TLD analysis
- URL length and complexity

### Content Features
- HTML structure analysis
- Text content analysis
- Meta tag inspection
- JavaScript behavior
- External resource analysis

### Behavioral Features
- Redirect patterns
- SSL certificate validation
- WHOIS information
- Historical data patterns

## Development

### Running Tests
```bash
pytest tests/ -v
```

### Code Formatting
```bash
black app/
flake8 app/
```

### Type Checking
```bash
mypy app/
```

## Docker Deployment

1. **Build the image**:
   ```bash
   docker build -t phishing-detection-api .
   ```

2. **Run with Docker Compose**:
   ```bash
   docker-compose up -d
   ```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | MongoDB connection string | `mongodb://localhost:27017` |
| `DATABASE_NAME` | Database name | `phishing_detection` |
| `MODEL_PATH` | Path to ML models | `./models` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `API_PREFIX` | API route prefix | `/api/v1` |

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For questions or support, please open an issue on GitHub or contact the development team.