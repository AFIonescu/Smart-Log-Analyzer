# Smart Log Analyzer

Elasticsearch-based log analysis system with NLP-powered insights and automated alerting using Express.js

## Project Description - Milestone 1

This project ingests application logs from multiple sources into Elasticsearch and uses NLP-powered analysis to detect anomalies, errors, and security threats in real-time. The system automatically categorizes logs by severity, extracts entities (IPs, user IDs, error codes), and triggers intelligent alerts with suggested remediation actions based on configurable rules.

### System Architecture

```
┌─────────────────┐
│  Applications   │
│   (Services)    │
└────────┬────────┘
         │ POST /logs
         │ (timestamp, level, source, message)
         ▼
┌─────────────────────────────────────────────────────────┐
│              Express.js API Server (:5000)              │
│                                                         │
│  ┌──────────────────────────────────────────────────┐  │
│  │            NLP Analysis Engine                   │  │
│  │  - Sentiment Analysis (positive/neutral/negative)│  │
│  │  - Keyword Extraction                            │  │
│  │  - Entity Extraction (IPs, users, error codes)   │  │
│  │  - Severity Scoring (0-10)                       │  │
│  │  - Auto-categorization                           │  │
│  └──────────────┬───────────────────────────────────┘  │
│                 │                                       │
│  ┌──────────────▼───────────────────────────────────┐  │
│  │         Alert Rule Evaluator                     │  │
│  │  - Every 60 seconds (periodic)                   │  │
│  │  - After each log ingestion (event-driven)       │  │
│  │  - Checks conditions: count, error_rate, source  │  │
│  │  - Generates alerts + suggested actions          │  │
│  └──────────────┬───────────────────────────────────┘  │
│                 │                                       │
└─────────────────┼───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│         Elasticsearch Cluster (:10200)                  │
│                                                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐    │
│  │    logs     │  │   alerts    │  │ alert_rules │    │
│  │  (enriched) │  │  (history)  │  │ (conditions)│    │
│  └─────────────┘  └─────────────┘  └─────────────┘    │
│                                                         │
│  ┌─────────────┐                                       │
│  │  anomalies  │                                       │
│  │  (patterns) │                                       │
│  └─────────────┘                                       │
└─────────────────────────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│              Kibana Dashboard (:10601)                  │
│  - Visualize logs and trends                           │
│  - Dev Tools (index management)                        │
│  - Discover (log exploration)                          │
└─────────────────────────────────────────────────────────┘
```

**Data Flow:**
1. Applications send logs via REST API
2. NLP engine enriches logs (sentiment, entities, keywords, severity)
3. Enriched logs stored in Elasticsearch `logs` index
4. Alert evaluator checks rules against incoming logs
5. Alerts created in `alerts` index when conditions met
6. Kibana provides visualization and exploration interface

## List of Use Cases - Milestone 2

**Use Case 1 — Check Elasticsearch Cluster Health**
- Actor: Developer / Monitoring System
- Goal: Verify Elasticsearch cluster is reachable and healthy
- Trigger: GET /health
- Main Flow: Server requests cluster health from Elasticsearch and returns status

**Use Case 2 — Ingest Log Entry with NLP Analysis**
- Actor: Application / Service
- Goal: Store log entry with automatic NLP enrichment
- Trigger: POST /logs with JSON body containing timestamp, level, source, message
- Main Flow: Request body is parsed, NLP analysis performed (sentiment, keywords, entity extraction), severity score calculated, enriched log indexed in Elasticsearch

**Use Case 3 — Search Logs with Filters**
- Actor: Developer / Operations Team
- Goal: Find specific logs matching criteria
- Trigger: GET /logs/search with query parameters (level, source, from, to, q)
- Main Flow: Server builds Elasticsearch query, executes search, returns matching logs

**Use Case 4 — Analyze Error Patterns**
- Actor: Operations Team
- Goal: Identify error trends and top sources
- Trigger: GET /analytics/errors
- Main Flow: Server aggregates error logs, calculates time-series data, identifies top error sources, returns analytics

**Use Case 5 — Create Alert Rule**
- Actor: DevOps Engineer
- Goal: Configure automated alert conditions
- Trigger: POST /alerts/rules with rule definition
- Main Flow: Validate rule, store in alert_rules index, enable automatic evaluation

**Use Case 6 — Automatic Alert Evaluation**
- Actor: System (Automated)
- Goal: Detect when alert conditions are met
- Trigger: Every 60 seconds + after each log ingestion
- Main Flow: Fetch enabled rules, check conditions against recent logs, create alerts when thresholds exceeded

**Use Case 7 — Retrieve Alerts**
- Actor: Operations Team
- Goal: View active and historical alerts
- Trigger: GET /alerts with optional filters (status, severity)
- Main Flow: Query alerts index, return filtered results

**Use Case 8 — Update Alert Status**
- Actor: Operations Team
- Goal: Acknowledge or resolve alerts
- Trigger: PUT /alerts/{id} with status change
- Main Flow: Update alert status, record timestamp and user, return confirmation

**Use Case 9 — Delete Log Entry**
- Actor: Administrator
- Goal: Remove specific log from system
- Trigger: DELETE /logs/{id}
- Main Flow: Delete document from logs index, return confirmation or 404 if not found

**Use Case 10 — Get System Health Metrics**
- Actor: Monitoring System
- Goal: Retrieve overall system health indicators
- Trigger: GET /metrics/health
- Main Flow: Calculate total logs, error rate, active alerts, top error sources, return health assessment

**Use Case 11 — Run Backend Server**
- Actor: Developer / System
- Goal: Start API server and initialize alert evaluation
- Trigger: Running the Node.js application
- Main Flow: Express server starts on port 5000, alert evaluation begins (every 60 seconds), console logs server URL

## Swagger API Implementation - Milestone 3

API documentation using Swagger UI and auto-generated OpenAPI 3.0 specification implemented in app.js using swagger-jsdoc and swagger-ui-express libraries.

**Swagger Setup**
- openapi: "3.0.0"
- info.title: "Smart Log Analyzer API"
- info.version: "1.0.0"
- servers: [{ url: "http://localhost:5000" }]
- apis: ["./app.js"]

**OpenAPI Schemas**
- LogEntry: timestamp, level, source, message, metadata
- IndexedLog: extends LogEntry with \_id, category, severity_score, entities, nlp_analysis
- Alert: alert_id, timestamp, severity, title, description, affected_service, status, suggested_actions
- AlertRule: rule_id, name, conditions, severity, channels, enabled
- HealthMetrics: time_range, overall_health, metrics (total_logs, error_count, error_rate, top_error_sources)

**Swagger-Documented Routes**
- GET /health - Elasticsearch cluster health
- POST /logs - Ingest log entry with NLP analysis
- GET /logs/search - Search logs with filters
- DELETE /logs/{id} - Delete log entry
- GET /analytics/errors - Error pattern analysis
- GET /metrics/health - System health metrics
- GET /alerts - Retrieve alert history
- POST /alerts/rules - Create alert rule
- GET /alerts/rules - Get all alert rules
- PUT /alerts/{id} - Update alert status

**Using Swagger UI**
- Interactive documentation: http://localhost:5000/docs
- OpenAPI JSON specification: http://localhost:5000/openapi.json

## Elasticsearch Mapping Overview - Milestone 4

The system uses 4 Elasticsearch indices with optimized mappings.

**Index 1: logs**
Stores all ingested log entries with NLP enrichment.

```json
{
  "mappings": {
    "properties": {
      "timestamp": { "type": "date" },
      "level": { "type": "keyword" },
      "source": { "type": "keyword" },
      "message": { "type": "text", "fields": { "keyword": { "type": "keyword" } } },
      "metadata": { "type": "object" },
      "category": { "type": "keyword" },
      "severity_score": { "type": "float" },
      "entities": {
        "properties": {
          "ips": { "type": "ip" },
          "user_ids": { "type": "keyword" },
          "error_codes": { "type": "keyword" },
          "urls": { "type": "keyword" }
        }
      },
      "nlp_analysis": {
        "properties": {
          "sentiment": { "type": "keyword" },
          "keywords": { "type": "keyword" },
          "language": { "type": "keyword" }
        }
      },
      "indexed_at": { "type": "date" }
    }
  }
}
```

**Index 2: alerts**
Stores generated alerts with notification history.

```json
{
  "mappings": {
    "properties": {
      "alert_id": { "type": "keyword" },
      "timestamp": { "type": "date" },
      "severity": { "type": "keyword" },
      "title": { "type": "text" },
      "description": { "type": "text" },
      "affected_service": { "type": "keyword" },
      "status": { "type": "keyword" },
      "suggested_actions": { "type": "text" },
      "related_logs": { "type": "keyword" },
      "notification_history": {
        "type": "nested",
        "properties": {
          "channel": { "type": "keyword" },
          "sent_at": { "type": "date" },
          "success": { "type": "boolean" }
        }
      },
      "rule_id": { "type": "keyword" }
    }
  }
}
```

**Index 3: alert_rules**
Stores configured alert rules.

```json
{
  "mappings": {
    "properties": {
      "rule_id": { "type": "keyword" },
      "name": { "type": "text" },
      "conditions": {
        "properties": {
          "source": { "type": "keyword" },
          "level": { "type": "keyword" },
          "error_rate_threshold": { "type": "float" },
          "time_window_minutes": { "type": "integer" },
          "count_threshold": { "type": "integer" }
        }
      },
      "severity": { "type": "keyword" },
      "enabled": { "type": "boolean" },
      "created_at": { "type": "date" },
      "last_triggered": { "type": "date" },
      "trigger_count": { "type": "integer" }
    }
  }
}
```

**Index 4: anomalies**
Stores detected anomaly patterns.

```json
{
  "mappings": {
    "properties": {
      "anomaly_id": { "type": "keyword" },
      "detected_at": { "type": "date" },
      "anomaly_type": { "type": "keyword" },
      "source": { "type": "keyword" },
      "anomaly_score": { "type": "float" },
      "description": { "type": "text" },
      "related_logs": { "type": "keyword" }
    }
  }
}
```

**Kibana Dev Tools – Create Indices**
```
DELETE logs
DELETE alerts
DELETE alert_rules
DELETE anomalies

PUT logs
PUT alerts
PUT alert_rules
PUT anomalies

GET logs/_mapping
GET alerts/_mapping
GET alert_rules/_mapping
GET anomalies/_mapping
```

## Implementation - Milestone 5

**What**: Node.js + Express API that ingests logs into Elasticsearch, performs NLP-powered analysis, and provides automated alerting.

**Server Configuration**
- PORT: 5000
- ES_CLUSTER: http://localhost:10200
- Indices: logs, alerts, alert_rules, anomalies

**NLP Analysis Features**
- Sentiment analysis (positive/neutral/negative)
- Keyword extraction
- Entity extraction (IPs, user IDs, error codes, URLs)
- Automatic categorization (error/security/performance/warning/general)
- Severity scoring (0-10 scale based on level + sentiment + keywords)

**Alert System**
- Rules evaluated every 60 seconds automatically
- Evaluation triggered after each log ingestion
- Configurable conditions: source, level, error_rate_threshold, count_threshold, time_window_minutes
- Automatic alert creation when conditions met
- Auto-generated suggested actions
- Alert lifecycle: open → acknowledged → resolved

**Quick Start**
```bash
npm install
docker-compose up -d elasticsearch kibana
curl http://localhost:10200/_cluster/health
PUT logs, alerts, alert_rules, anomalies (via Kibana Dev Tools)
npm start
```

**API & Swagger**
- Docs: http://localhost:5000/docs
- OpenAPI spec: http://localhost:5000/openapi.json
- All routes documented with @openapi JSDoc comments

## Postman Testing - Milestone 6

Comprehensive API testing using Postman with automated test suite.

**Collection Setup**
- Collection Name: Smart Log Analyzer API Tests
- Base URL: http://localhost:5000
- Variables: base_url, log_id, alert_id, rule_id
- 19 requests organized in 6 folders
- 49 automated test assertions

**Test Suite Structure**

**1. System Health Tests (2 tests)**
- Test 1.1: Check Elasticsearch Health
- Test 1.2: Get API Root Information

**2. Log Ingestion Tests (3 tests)**
- Test 2.1: Create New Log Entry (validates NLP analysis, category, severity score)
- Test 2.2: Create Log with Missing Fields (validates 400 error)
- Test 2.3: Delete Log Entry

**3. Log Search Tests (4 tests)**
- Test 3.1: Search All Logs
- Test 3.2: Search by Level
- Test 3.3: Search by Source
- Test 3.4: Full-Text Search

**4. Analytics Tests (2 tests)**
- Test 4.1: Get Error Analytics (validates total_errors, top_sources, time_series)
- Test 4.2: Get Health Metrics (validates overall_health, metrics)

**5. Alert Management Tests (6 tests)**
- Test 5.1: Create Alert Rule
- Test 5.2: Get All Alert Rules
- Test 5.3: Get Alerts
- Test 5.4: Get Alerts by Status
- Test 5.5: Acknowledge Alert
- Test 5.6: Resolve Alert

**6. Error Handling Tests (2 tests)**
- Test 6.1: Invalid Alert Status Update (validates 400 error)
- Test 6.2: Non-existent Log Deletion (validates 404 error)

**Running Tests**
Import Smart-Log-Analyzer.postman_collection.json into Postman, then click "Run" to execute all tests.

**Test Results**
All 49 tests passing with average response time of 13ms.

## Technology Stack

- Elasticsearch 8.11 - Distributed search and analytics engine
- Kibana 8.11 - Data visualization and exploration
- Node.js 18 - JavaScript runtime
- Express.js - Web application framework
- natural, compromise, sentiment - NLP libraries for text analysis
- swagger-jsdoc, swagger-ui-express - API documentation
- axios - HTTP client for Elasticsearch
- Docker & Docker Compose - Containerization

## Installation

```bash
git clone <repository>
cd Smart-Log-Analyzer
npm install
```

Create `.env` file:
```
PORT=5000
ES_CLUSTER=http://localhost:10200
```

Start Elasticsearch and Kibana:
```bash
docker-compose up -d elasticsearch kibana
```

Wait for Elasticsearch to be ready, then create indices via Kibana Dev Tools (http://localhost:10601):
```
PUT logs
PUT alerts
PUT alert_rules
PUT anomalies
```

Start the server:
```bash
npm start
```

## Testing

**Swagger UI**: http://localhost:5000/docs

**Postman**: Import Smart-Log-Analyzer.postman_collection.json

**Production Simulator**:
```powershell
.\simulate-production.ps1
```

## API Endpoints

- GET / - API information
- GET /health - Elasticsearch cluster health
- GET /docs - Swagger UI
- POST /logs - Ingest log with NLP analysis
- GET /logs/search - Search logs
- DELETE /logs/{id} - Delete log
- GET /analytics/errors - Error pattern analysis
- GET /metrics/health - System health metrics
- GET /alerts - Retrieve alerts
- POST /alerts/rules - Create alert rule
- GET /alerts/rules - List alert rules
- PUT /alerts/{id} - Update alert status
