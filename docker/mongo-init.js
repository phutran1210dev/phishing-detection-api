// MongoDB initialization script
db = db.getSiblingDB('phishing_detection');

// Create collections with validation
db.createCollection('detections', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['url', 'result', 'timestamp'],
      properties: {
        url: {
          bsonType: 'string',
          description: 'URL that was analyzed'
        },
        result: {
          bsonType: 'object',
          description: 'Detection result'
        },
        timestamp: {
          bsonType: 'date',
          description: 'When the detection was performed'
        }
      }
    }
  }
});

db.createCollection('training_data', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['features', 'label', 'timestamp'],
      properties: {
        features: {
          description: 'Feature vector or object'
        },
        label: {
          bsonType: 'int',
          minimum: 0,
          maximum: 1,
          description: 'Binary label (0=legitimate, 1=phishing)'
        },
        timestamp: {
          bsonType: 'date',
          description: 'When the data was collected'
        }
      }
    }
  }
});

db.createCollection('model_metadata', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['model_name', 'version', 'timestamp'],
      properties: {
        model_name: {
          bsonType: 'string',
          description: 'Name of the ML model'
        },
        version: {
          bsonType: 'string',
          description: 'Model version'
        },
        metrics: {
          bsonType: 'object',
          description: 'Model performance metrics'
        },
        timestamp: {
          bsonType: 'date',
          description: 'When the model was trained/updated'
        }
      }
    }
  }
});

// Create indexes for better performance
db.detections.createIndex({ 'url': 1, 'timestamp': -1 });
db.detections.createIndex({ 'result.is_phishing': 1, 'timestamp': -1 });
db.detections.createIndex({ 'timestamp': -1 });

db.training_data.createIndex({ 'label': 1, 'timestamp': -1 });
db.training_data.createIndex({ 'timestamp': -1 });

db.model_metadata.createIndex({ 'model_name': 1, 'version': 1 });
db.model_metadata.createIndex({ 'timestamp': -1 });

print('Database initialized successfully with collections and indexes');