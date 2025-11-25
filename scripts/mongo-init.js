// MongoDB initialization script
print('Starting MongoDB initialization...');

// Create database and user
db = db.getSiblingDB('phishing_detection');

// Create application user with read/write access
db.createUser({
  user: 'phishing_user',
  pwd: 'phishing_password',
  roles: [
    {
      role: 'readWrite',
      db: 'phishing_detection'
    }
  ]
});

// Create collections with indexes
print('Creating collections and indexes...');

// Detection results collection
db.createCollection('detection_results');
db.detection_results.createIndex({ "timestamp": 1 });
db.detection_results.createIndex({ "url": 1 });
db.detection_results.createIndex({ "is_phishing": 1 });
db.detection_results.createIndex({ "user_id": 1 });

// Audit logs collection
db.createCollection('audit_logs');
db.audit_logs.createIndex({ "timestamp": 1 });
db.audit_logs.createIndex({ "user_id": 1 });
db.audit_logs.createIndex({ "event_type": 1 });
db.audit_logs.createIndex({ "level": 1 });

// User sessions collection
db.createCollection('user_sessions');
db.user_sessions.createIndex({ "session_id": 1 }, { unique: true });
db.user_sessions.createIndex({ "user_id": 1 });
db.user_sessions.createIndex({ "expires_at": 1 }, { expireAfterSeconds: 0 });

// File uploads collection
db.createCollection('file_uploads');
db.file_uploads.createIndex({ "upload_id": 1 }, { unique: true });
db.file_uploads.createIndex({ "user_id": 1 });
db.file_uploads.createIndex({ "created_at": 1 });

// Compliance reports collection
db.createCollection('compliance_reports');
db.compliance_reports.createIndex({ "report_id": 1 }, { unique: true });
db.compliance_reports.createIndex({ "framework": 1 });
db.compliance_reports.createIndex({ "generated_at": 1 });

// Retention policies collection
db.createCollection('retention_policies');
db.retention_policies.createIndex({ "policy_id": 1 }, { unique: true });
db.retention_policies.createIndex({ "data_category": 1 });
db.retention_policies.createIndex({ "is_active": 1 });

// Insert some sample data for testing
print('Inserting sample data...');

// Sample detection results
db.detection_results.insertMany([
  {
    url: "https://example.com",
    prediction: {
      is_phishing: false,
      confidence: 0.15,
      risk_score: 1.5
    },
    timestamp: new Date(),
    processing_time_ms: 123,
    model_version: "1.0.0"
  },
  {
    url: "http://phishing-test.example",
    prediction: {
      is_phishing: true,
      confidence: 0.89,
      risk_score: 8.9
    },
    timestamp: new Date(),
    processing_time_ms: 145,
    model_version: "1.0.0"
  }
]);

print('MongoDB initialization completed successfully!');