require('dotenv').config();
const express = require('express');
const axios = require('axios');
const swaggerJSDoc = require('swagger-jsdoc');
const swaggerUi = require('swagger-ui-express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const Sentiment = require('sentiment');
const natural = require('natural');
const compromise = require('compromise');

const app = express();
const PORT = process.env.PORT || 5000;
const ES_CLUSTER = process.env.ES_CLUSTER || 'http://localhost:9200';
const INDEX_LOGS = process.env.INDEX_LOGS || 'logs';
const INDEX_ALERTS = process.env.INDEX_ALERTS || 'alerts';
const INDEX_ALERT_RULES = process.env.INDEX_ALERT_RULES || 'alert_rules';
const INDEX_ANOMALIES = process.env.INDEX_ANOMALIES || 'anomalies';

// Initialize NLP tools
const sentiment = new Sentiment();
const tokenizer = new natural.WordTokenizer();

// Middleware
app.use(express.json());
app.use(cors());
app.use(helmet({
  contentSecurityPolicy: false
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 900000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: 'Too many requests from this IP, please try again later.'
});
app.use('/api/', limiter);

// Elasticsearch client
const esClient = axios.create({
  baseURL: ES_CLUSTER,
  timeout: 8000,
  headers: {
    'Content-Type': 'application/json'
  }
});

// Add basic auth if credentials provided
if (process.env.ES_USERNAME && process.env.ES_PASSWORD) {
  esClient.defaults.auth = {
    username: process.env.ES_USERNAME,
    password: process.env.ES_PASSWORD
  };
}

// Swagger configuration
const swaggerOptions = {
  definition: {
    openapi: '3.0.0',
    info: {
      title: 'Smart Log Analyzer API',
      version: '1.0.0',
      description: 'Intelligent log analysis and alerting system with NLP-powered anomaly detection',
      contact: {
        name: 'API Support'
      }
    },
    servers: [
      {
        url: `http://localhost:${PORT}`,
        description: 'Development server'
      }
    ],
    components: {
      schemas: {
        LogEntry: {
          type: 'object',
          required: ['timestamp', 'level', 'source', 'message'],
          properties: {
            timestamp: {
              type: 'string',
              format: 'date-time',
              description: 'ISO 8601 timestamp',
              example: '2025-12-31T10:35:22Z'
            },
            level: {
              type: 'string',
              enum: ['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'],
              description: 'Log level',
              example: 'ERROR'
            },
            source: {
              type: 'string',
              description: 'Source application or service name',
              example: 'payment-service'
            },
            message: {
              type: 'string',
              description: 'Log message text',
              example: 'Payment processing failed for user 12345'
            },
            metadata: {
              type: 'object',
              description: 'Additional structured data',
              additionalProperties: true
            }
          }
        },
        IndexedLog: {
          allOf: [
            { $ref: '#/components/schemas/LogEntry' },
            {
              type: 'object',
              properties: {
                _id: {
                  type: 'string',
                  description: 'Elasticsearch document ID'
                },
                category: {
                  type: 'string',
                  description: 'Auto-detected category'
                },
                severity_score: {
                  type: 'number',
                  format: 'float',
                  description: 'Computed severity score (0-10)'
                },
                entities: {
                  type: 'object',
                  properties: {
                    ips: {
                      type: 'array',
                      items: { type: 'string' }
                    },
                    user_ids: {
                      type: 'array',
                      items: { type: 'string' }
                    },
                    error_codes: {
                      type: 'array',
                      items: { type: 'string' }
                    }
                  }
                }
              }
            }
          ]
        },
        Alert: {
          type: 'object',
          properties: {
            alert_id: { type: 'string' },
            timestamp: { type: 'string', format: 'date-time' },
            severity: {
              type: 'string',
              enum: ['critical', 'high', 'medium', 'low']
            },
            title: { type: 'string' },
            description: { type: 'string' },
            affected_service: { type: 'string' },
            status: {
              type: 'string',
              enum: ['open', 'acknowledged', 'resolved']
            }
          }
        },
        ErrorResponse: {
          type: 'object',
          properties: {
            error: { type: 'string' },
            details: { type: 'string' },
            timestamp: { type: 'string', format: 'date-time' }
          }
        }
      }
    }
  },
  apis: ['./app.js']
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);

// Swagger routes
app.use('/docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));
app.get('/openapi.json', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(swaggerSpec);
});

// ===============================
// NLP Analysis Functions
// ===============================

function analyzeLogMessage(message, level) {
  const analysis = {
    sentiment: 'neutral',
    keywords: [],
    entities: {
      ips: [],
      user_ids: [],
      error_codes: [],
      urls: []
    },
    category: 'general',
    severity_score: 5.0
  };

  // Sentiment analysis
  const sentimentResult = sentiment.analyze(message);
  if (sentimentResult.score > 0) {
    analysis.sentiment = 'positive';
  } else if (sentimentResult.score < -2) {
    analysis.sentiment = 'negative';
  }

  // Extract keywords
  const tokens = tokenizer.tokenize(message.toLowerCase());
  const stopWords = ['the', 'a', 'an', 'and', 'or', 'but', 'for', 'to', 'from', 'with', 'in', 'on', 'at'];
  analysis.keywords = tokens.filter(token =>
    token.length > 3 && !stopWords.includes(token)
  ).slice(0, 10);

  // Entity extraction using compromise
  const doc = compromise(message);

  // Extract IP addresses
  const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;
  const ips = message.match(ipRegex);
  if (ips) analysis.entities.ips = ips;

  // Extract user IDs (pattern: user followed by number)
  const userIdRegex = /user[_\s]?(\d+)/gi;
  const userIds = [];
  let match;
  while ((match = userIdRegex.exec(message)) !== null) {
    userIds.push(match[1]);
  }
  if (userIds.length > 0) analysis.entities.user_ids = userIds;

  // Extract error codes (pattern: uppercase letters/numbers)
  const errorCodeRegex = /\b[A-Z_]{3,}(?:_\d+)?\b/g;
  const errorCodes = message.match(errorCodeRegex);
  if (errorCodes) {
    analysis.entities.error_codes = errorCodes.filter(code =>
      !['DEBUG', 'INFO', 'WARN', 'ERROR', 'CRITICAL'].includes(code)
    );
  }

  // Categorize based on keywords
  const lowerMessage = message.toLowerCase();
  if (lowerMessage.includes('fail') || lowerMessage.includes('error') || lowerMessage.includes('exception')) {
    analysis.category = 'error';
  } else if (lowerMessage.includes('security') || lowerMessage.includes('unauthorized') || lowerMessage.includes('forbidden')) {
    analysis.category = 'security';
  } else if (lowerMessage.includes('slow') || lowerMessage.includes('timeout') || lowerMessage.includes('latency')) {
    analysis.category = 'performance';
  } else if (lowerMessage.includes('warn')) {
    analysis.category = 'warning';
  }

  // Calculate severity score based on level and content
  let severityScore = 5.0;
  switch (level) {
    case 'CRITICAL':
      severityScore = 9.5;
      break;
    case 'ERROR':
      severityScore = 7.5;
      break;
    case 'WARN':
      severityScore = 5.0;
      break;
    case 'INFO':
      severityScore = 2.0;
      break;
    case 'DEBUG':
      severityScore = 1.0;
      break;
  }

  // Adjust score based on sentiment and keywords
  if (analysis.sentiment === 'negative') severityScore += 1.0;
  if (lowerMessage.includes('critical') || lowerMessage.includes('fatal')) severityScore += 1.5;
  if (lowerMessage.includes('timeout') || lowerMessage.includes('connection')) severityScore += 0.5;

  analysis.severity_score = Math.min(10, severityScore);

  return analysis;
}

// ===============================
// Alert Rule Evaluation
// ===============================

/**
 * Evaluate alert rules against recent error patterns
 * This function checks if any alert rules are triggered based on current log data
 */
async function evaluateAlertRules() {
  try {
    // Get all enabled alert rules
    const rulesResponse = await esClient.post(`/${INDEX_ALERT_RULES}/_search`, {
      query: { term: { enabled: true } },
      size: 100
    });

    const rules = rulesResponse.data.hits.hits;

    for (const ruleHit of rules) {
      const rule = ruleHit._source;
      const ruleId = ruleHit._id;

      // Check if rule conditions are met
      const triggered = await checkRuleConditions(rule);

      if (triggered) {
        await createAlert(rule, ruleId, triggered.relatedLogs);

        // Update rule trigger count
        await esClient.post(`/${INDEX_ALERT_RULES}/_update/${ruleId}`, {
          doc: {
            last_triggered: new Date().toISOString(),
            trigger_count: (rule.trigger_count || 0) + 1
          }
        });
      }
    }
  } catch (error) {
    console.error('Error evaluating alert rules:', error.message);
  }
}

/**
 * Check if a specific rule's conditions are met
 */
async function checkRuleConditions(rule) {
  const { conditions } = rule;
  const timeWindowMs = (conditions.time_window_minutes || 5) * 60 * 1000;
  const fromTime = new Date(Date.now() - timeWindowMs).toISOString();

  try {
    // Build query based on rule conditions
    const must = [
      { range: { timestamp: { gte: fromTime } } }
    ];

    if (conditions.source) {
      must.push({ term: { source: conditions.source } });
    }

    if (conditions.level) {
      must.push({ term: { level: conditions.level } });
    }

    if (conditions.message_pattern) {
      must.push({ match: { message: conditions.message_pattern } });
    }

    // Search for matching logs
    const logsResponse = await esClient.post(`/${INDEX_LOGS}/_search`, {
      query: { bool: { must } },
      size: 100
    });

    const matchingLogs = logsResponse.data.hits.hits;
    const totalLogs = logsResponse.data.hits.total.value;

    // Check error rate threshold if specified
    if (conditions.error_rate_threshold !== undefined) {
      // Get total logs in time window
      const allLogsResponse = await esClient.post(`/${INDEX_LOGS}/_search`, {
        query: {
          range: { timestamp: { gte: fromTime } }
        },
        size: 0
      });

      const totalLogsInWindow = allLogsResponse.data.hits.total.value;

      if (totalLogsInWindow === 0) return false;

      const errorRate = (totalLogs / totalLogsInWindow) * 100;

      if (errorRate >= conditions.error_rate_threshold) {
        return {
          triggered: true,
          errorRate,
          totalErrors: totalLogs,
          totalLogs: totalLogsInWindow,
          relatedLogs: matchingLogs.map(hit => hit._id)
        };
      }
    } else {
      // Simple count threshold (default: trigger if any matching logs found)
      const threshold = conditions.count_threshold || 1;

      if (totalLogs >= threshold) {
        return {
          triggered: true,
          count: totalLogs,
          relatedLogs: matchingLogs.map(hit => hit._id)
        };
      }
    }

    return false;
  } catch (error) {
    console.error('Error checking rule conditions:', error.message);
    return false;
  }
}

/**
 * Create an alert based on triggered rule
 */
async function createAlert(rule, ruleId, relatedLogs = []) {
  try {
    const alertId = `alert_${Date.now()}`;

    const alert = {
      alert_id: alertId,
      timestamp: new Date().toISOString(),
      severity: rule.severity,
      title: `Alert: ${rule.name}`,
      description: rule.description || `Alert triggered by rule: ${rule.name}`,
      affected_service: rule.conditions.source || 'unknown',
      impact: `Rule ${rule.name} conditions have been met`,
      related_logs: relatedLogs.slice(0, 10), // Limit to 10 related logs
      suggested_actions: generateSuggestedActions(rule),
      status: 'open',
      notification_history: [],
      rule_id: ruleId
    };

    await esClient.post(`/${INDEX_ALERTS}/_doc`, alert);

    // Send notification
    sendAlertNotification(alert, rule);

    console.log(`Alert created: ${alertId} for rule: ${rule.name}`);

    return alertId;
  } catch (error) {
    console.error('Error creating alert:', error.message);
    return null;
  }
}

/**
 * Send alert notification (console + could add email/Slack)
 */
function sendAlertNotification(alert, rule) {
  // Console notification
  console.log('\n' + '='.repeat(80));
  console.log('🚨 ALERT TRIGGERED!');
  console.log('='.repeat(80));
  console.log(`Title: ${alert.title}`);
  console.log(`Severity: ${alert.severity.toUpperCase()}`);
  console.log(`Service: ${alert.affected_service}`);
  console.log(`Time: ${new Date(alert.timestamp).toLocaleString()}`);
  console.log(`\nDescription: ${alert.description}`);
  console.log(`\nSuggested Actions:`);
  alert.suggested_actions.forEach((action, i) => {
    console.log(`  ${i + 1}. ${action}`);
  });
  console.log(`\nRelated Logs: ${alert.related_logs.length} log(s)`);
  console.log(`Alert ID: ${alert.alert_id}`);
  console.log('='.repeat(80) + '\n');

  // TODO: Add email notification if configured
  // TODO: Add Slack webhook notification if configured
}

/**
 * Generate suggested actions based on rule conditions
 */
function generateSuggestedActions(rule) {
  const actions = [];
  const { conditions } = rule;

  if (conditions.source) {
    actions.push(`Check ${conditions.source} service health and logs`);
    actions.push(`Review recent deployments to ${conditions.source}`);
  }

  if (conditions.level === 'ERROR' || conditions.level === 'CRITICAL') {
    actions.push('Investigate error logs and stack traces');
    actions.push('Check service dependencies and external API status');
  }

  if (conditions.message_pattern) {
    actions.push(`Search for pattern: "${conditions.message_pattern}" in logs`);
  }

  if (conditions.error_rate_threshold) {
    actions.push('Monitor error rate trends over time');
    actions.push('Check if issue is affecting all users or specific segments');
  }

  if (actions.length === 0) {
    actions.push('Review alert details and related logs');
    actions.push('Investigate root cause and implement fix');
  }

  return actions;
}

// ===============================
// API Routes
// ===============================

/**
 * @openapi
 * /health:
 *   get:
 *     summary: Check Elasticsearch cluster health
 *     tags: [System]
 *     responses:
 *       200:
 *         description: Cluster health status
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 cluster_name:
 *                   type: string
 *                 status:
 *                   type: string
 *                   enum: [green, yellow, red]
 *                 number_of_nodes:
 *                   type: integer
 *                 active_shards:
 *                   type: integer
 *       500:
 *         description: Server error
 */
app.get('/health', async (req, res) => {
  try {
    const response = await esClient.get('/_cluster/health');
    res.json({
      cluster_name: response.data.cluster_name,
      status: response.data.status,
      number_of_nodes: response.data.number_of_nodes,
      active_shards: response.data.active_shards,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    console.error('Health check failed:', error.message);
    res.status(500).json({
      error: 'Health check failed',
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @openapi
 * /logs:
 *   post:
 *     summary: Ingest a new log entry
 *     tags: [Logs]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LogEntry'
 *     responses:
 *       201:
 *         description: Log entry indexed successfully
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/IndexedLog'
 *       400:
 *         description: Invalid request body
 *       500:
 *         description: Indexing failed
 */
app.post('/logs', async (req, res) => {
  try {
    const { timestamp, level, source, message, metadata } = req.body;

    // Validation
    if (!timestamp || !level || !source || !message) {
      return res.status(400).json({
        error: 'Missing required fields',
        details: 'timestamp, level, source, and message are required',
        timestamp: new Date().toISOString()
      });
    }

    // Perform NLP analysis
    const analysis = analyzeLogMessage(message, level);

    // Build enriched log document
    const logDocument = {
      timestamp,
      level,
      source,
      message,
      metadata: metadata || {},
      category: analysis.category,
      severity_score: analysis.severity_score,
      entities: analysis.entities,
      nlp_analysis: {
        sentiment: analysis.sentiment,
        keywords: analysis.keywords,
        language: 'en'
      },
      indexed_at: new Date().toISOString()
    };

    // Index in Elasticsearch
    const response = await esClient.post(`/${INDEX_LOGS}/_doc`, logDocument);

    // Trigger alert rule evaluation asynchronously (don't wait for it)
    evaluateAlertRules().catch(err => {
      console.error('Background alert evaluation failed:', err.message);
    });

    // Return indexed document with ID
    res.status(201).json({
      _id: response.data._id,
      ...logDocument
    });
  } catch (error) {
    console.error('Log indexing failed:', error.message);
    res.status(500).json({
      error: 'Failed to index log entry',
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @openapi
 * /logs/search:
 *   get:
 *     summary: Search logs with filters
 *     tags: [Logs]
 *     parameters:
 *       - in: query
 *         name: level
 *         schema:
 *           type: string
 *         description: Filter by log level
 *       - in: query
 *         name: source
 *         schema:
 *           type: string
 *         description: Filter by source application
 *       - in: query
 *         name: from
 *         schema:
 *           type: string
 *           format: date-time
 *         description: Start of time range
 *       - in: query
 *         name: to
 *         schema:
 *           type: string
 *           format: date-time
 *         description: End of time range
 *       - in: query
 *         name: q
 *         schema:
 *           type: string
 *         description: Full-text search query
 *       - in: query
 *         name: limit
 *         schema:
 *           type: integer
 *           default: 100
 *         description: Maximum results to return
 *     responses:
 *       200:
 *         description: Search results
 */
app.get('/logs/search', async (req, res) => {
  try {
    const { level, source, from, to, q, limit = 100 } = req.query;

    // Build Elasticsearch query
    const must = [];
    const filter = [];

    if (level) {
      filter.push({ term: { level: level } });
    }

    if (source) {
      filter.push({ term: { source: source } });
    }

    if (from || to) {
      const range = { timestamp: {} };
      if (from) range.timestamp.gte = from;
      if (to) range.timestamp.lte = to;
      filter.push({ range });
    }

    if (q) {
      must.push({ match: { message: q } });
    }

    const query = {
      bool: {}
    };

    if (must.length > 0) query.bool.must = must;
    if (filter.length > 0) query.bool.filter = filter;

    const searchBody = {
      query: Object.keys(query.bool).length > 0 ? query : { match_all: {} },
      sort: [{ timestamp: 'desc' }],
      size: parseInt(limit)
    };

    const startTime = Date.now();
    const response = await esClient.post(`/${INDEX_LOGS}/_search`, searchBody);
    const queryTime = Date.now() - startTime;

    res.json({
      total_hits: response.data.hits.total.value,
      query_time_ms: queryTime,
      logs: response.data.hits.hits.map(hit => ({
        _id: hit._id,
        ...hit._source
      }))
    });
  } catch (error) {
    console.error('Log search failed:', error.message);
    res.status(500).json({
      error: 'Search failed',
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @openapi
 * /analytics/errors:
 *   get:
 *     summary: Analyze error patterns and trends
 *     tags: [Analytics]
 *     parameters:
 *       - in: query
 *         name: source
 *         schema:
 *           type: string
 *       - in: query
 *         name: from
 *         schema:
 *           type: string
 *           format: date-time
 *       - in: query
 *         name: to
 *         schema:
 *           type: string
 *           format: date-time
 *     responses:
 *       200:
 *         description: Error analysis results
 */
app.get('/analytics/errors', async (req, res) => {
  try {
    const { source, from, to } = req.query;

    const filter = [
      { terms: { level: ['ERROR', 'CRITICAL'] } }
    ];

    if (source) {
      filter.push({ term: { source } });
    }

    if (from || to) {
      const range = { timestamp: {} };
      if (from) range.timestamp.gte = from;
      if (to) range.timestamp.lte = to;
      filter.push({ range });
    }

    const searchBody = {
      size: 0,
      query: {
        bool: { filter }
      },
      aggs: {
        error_count: {
          value_count: { field: 'level' }
        },
        top_error_sources: {
          terms: {
            field: 'source',
            size: 10
          }
        },
        errors_over_time: {
          date_histogram: {
            field: 'timestamp',
            fixed_interval: '5m'
          }
        },
        top_error_categories: {
          terms: {
            field: 'category',
            size: 5
          }
        }
      }
    };

    const response = await esClient.post(`/${INDEX_LOGS}/_search`, searchBody);
    const aggs = response.data.aggregations;

    res.json({
      time_range: { from: from || 'now-1h', to: to || 'now' },
      total_errors: aggs.error_count.value,
      top_sources: aggs.top_error_sources.buckets.map(b => ({
        source: b.key,
        count: b.doc_count
      })),
      time_series: aggs.errors_over_time.buckets.map(b => ({
        timestamp: b.key_as_string,
        count: b.doc_count
      })),
      top_categories: aggs.top_error_categories.buckets.map(b => ({
        category: b.key,
        count: b.doc_count
      }))
    });
  } catch (error) {
    console.error('Error analysis failed:', error.message);
    res.status(500).json({
      error: 'Analysis failed',
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @openapi
 * /metrics/health:
 *   get:
 *     summary: Get system health metrics
 *     tags: [Metrics]
 *     parameters:
 *       - in: query
 *         name: from
 *         schema:
 *           type: string
 *           format: date-time
 *       - in: query
 *         name: to
 *         schema:
 *           type: string
 *           format: date-time
 *     responses:
 *       200:
 *         description: Health metrics
 */
app.get('/metrics/health', async (req, res) => {
  try {
    const { from = 'now-1h', to = 'now' } = req.query;

    const searchBody = {
      size: 0,
      query: {
        bool: {
          filter: [
            { range: { timestamp: { gte: from, lte: to } } }
          ]
        }
      },
      aggs: {
        total_logs: {
          value_count: { field: 'timestamp' }
        },
        by_level: {
          terms: { field: 'level' }
        },
        error_count: {
          filter: { terms: { level: ['ERROR', 'CRITICAL'] } }
        },
        avg_severity: {
          avg: { field: 'severity_score' }
        }
      }
    };

    const response = await esClient.post(`/${INDEX_LOGS}/_search`, searchBody);
    const aggs = response.data.aggregations;

    const totalLogs = aggs.total_logs.value;
    const errorCount = aggs.error_count.doc_count;
    const errorRate = totalLogs > 0 ? (errorCount / totalLogs * 100).toFixed(2) : 0;

    let overallHealth = 'healthy';
    if (errorRate > 10) {
      overallHealth = 'critical';
    } else if (errorRate > 5) {
      overallHealth = 'warning';
    }

    res.json({
      time_range: { from, to },
      overall_health: overallHealth,
      metrics: {
        total_logs: totalLogs,
        error_count: errorCount,
        error_rate: parseFloat(errorRate),
        avg_severity_score: aggs.avg_severity.value || 0,
        logs_by_level: aggs.by_level.buckets.reduce((acc, b) => {
          acc[b.key] = b.doc_count;
          return acc;
        }, {})
      }
    });
  } catch (error) {
    console.error('Metrics retrieval failed:', error.message);
    res.status(500).json({
      error: 'Failed to retrieve metrics',
      details: error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @openapi
 * /alerts:
 *   get:
 *     summary: Retrieve alert history
 *     tags: [Alerts]
 *     parameters:
 *       - in: query
 *         name: status
 *         schema:
 *           type: string
 *           enum: [open, acknowledged, resolved]
 *         description: Filter by alert status
 *       - in: query
 *         name: severity
 *         schema:
 *           type: string
 *           enum: [critical, high, medium, low]
 *         description: Filter by severity level
 *       - in: query
 *         name: from
 *         schema:
 *           type: string
 *           format: date-time
 *         description: Start of time range
 *       - in: query
 *         name: to
 *         schema:
 *           type: string
 *           format: date-time
 *         description: End of time range
 *     responses:
 *       200:
 *         description: List of alerts
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 total:
 *                   type: integer
 *                 alerts:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/Alert'
 *       500:
 *         description: Server error
 */
app.get('/alerts', async (req, res) => {
  try {
    const { status, severity, from, to } = req.query;

    // Build query
    const must = [];

    if (status) {
      must.push({ term: { status } });
    }

    if (severity) {
      must.push({ term: { severity } });
    }

    if (from || to) {
      const range = { timestamp: {} };
      if (from) range.timestamp.gte = from;
      if (to) range.timestamp.lte = to;
      must.push({ range });
    }

    const query = must.length > 0 ? { bool: { must } } : { match_all: {} };

    const response = await esClient.post(`/${INDEX_ALERTS}/_search`, {
      query,
      sort: [{ timestamp: 'desc' }],
      size: 100
    });

    res.json({
      total: response.data.hits.total.value,
      alerts: response.data.hits.hits.map(hit => ({
        _id: hit._id,
        ...hit._source
      }))
    });
  } catch (error) {
    console.error('Get alerts error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to retrieve alerts',
      details: error.response?.data?.error || error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @openapi
 * /alerts/rules:
 *   post:
 *     summary: Create a new alert rule
 *     tags: [Alerts]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/AlertRule'
 *     responses:
 *       201:
 *         description: Alert rule created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 _id:
 *                   type: string
 *                 rule_id:
 *                   type: string
 *                 message:
 *                   type: string
 *       400:
 *         description: Invalid request body
 *       500:
 *         description: Failed to create alert rule
 */
app.post('/alerts/rules', async (req, res) => {
  try {
    const { name, description, conditions, severity, channels, enabled = true } = req.body;

    // Validate required fields
    if (!name || !conditions || !severity) {
      return res.status(400).json({
        error: 'Missing required fields: name, conditions, severity',
        timestamp: new Date().toISOString()
      });
    }

    const rule_id = `rule_${Date.now()}`;
    const alertRule = {
      rule_id,
      name,
      description: description || '',
      conditions,
      severity,
      channels: channels || ['email'],
      enabled,
      created_at: new Date().toISOString(),
      created_by: 'api',
      last_triggered: null,
      trigger_count: 0
    };

    const response = await esClient.post(`/${INDEX_ALERT_RULES}/_doc`, alertRule);

    res.status(201).json({
      _id: response.data._id,
      rule_id,
      message: 'Alert rule created successfully',
      ...alertRule
    });
  } catch (error) {
    console.error('Create alert rule error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to create alert rule',
      details: error.response?.data?.error || error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @openapi
 * /alerts/rules:
 *   get:
 *     summary: Get all alert rules
 *     tags: [Alerts]
 *     parameters:
 *       - in: query
 *         name: enabled
 *         schema:
 *           type: boolean
 *         description: Filter by enabled status
 *     responses:
 *       200:
 *         description: List of alert rules
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 total:
 *                   type: integer
 *                 rules:
 *                   type: array
 *                   items:
 *                     $ref: '#/components/schemas/AlertRule'
 */
app.get('/alerts/rules', async (req, res) => {
  try {
    const { enabled } = req.query;

    let query = { match_all: {} };

    if (enabled !== undefined) {
      query = { term: { enabled: enabled === 'true' } };
    }

    const response = await esClient.post(`/${INDEX_ALERT_RULES}/_search`, {
      query,
      sort: [{ created_at: 'desc' }],
      size: 100
    });

    res.json({
      total: response.data.hits.total.value,
      rules: response.data.hits.hits.map(hit => ({
        _id: hit._id,
        ...hit._source
      }))
    });
  } catch (error) {
    console.error('Get alert rules error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to retrieve alert rules',
      details: error.response?.data?.error || error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @openapi
 * /alerts/{id}:
 *   put:
 *     summary: Update alert status
 *     tags: [Alerts]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Alert ID
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               status:
 *                 type: string
 *                 enum: [acknowledged, resolved]
 *               notes:
 *                 type: string
 *               acknowledged_by:
 *                 type: string
 *               resolved_by:
 *                 type: string
 *     responses:
 *       200:
 *         description: Alert updated successfully
 *       400:
 *         description: Invalid request
 *       404:
 *         description: Alert not found
 *       500:
 *         description: Server error
 */
app.put('/alerts/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { status, notes, acknowledged_by, resolved_by } = req.body;

    if (!status || !['acknowledged', 'resolved'].includes(status)) {
      return res.status(400).json({
        error: 'Invalid status. Must be "acknowledged" or "resolved"',
        timestamp: new Date().toISOString()
      });
    }

    // First, get the existing alert
    const getResponse = await esClient.get(`/${INDEX_ALERTS}/_doc/${id}`).catch(() => null);

    if (!getResponse || !getResponse.data.found) {
      return res.status(404).json({
        error: 'Alert not found',
        timestamp: new Date().toISOString()
      });
    }

    const updateDoc = {
      status
    };

    if (status === 'acknowledged') {
      updateDoc.acknowledged_at = new Date().toISOString();
      if (acknowledged_by) updateDoc.acknowledged_by = acknowledged_by;
    } else if (status === 'resolved') {
      updateDoc.resolved_at = new Date().toISOString();
      if (resolved_by) updateDoc.resolved_by = resolved_by;
      if (notes) updateDoc.resolution_notes = notes;
    }

    const response = await esClient.post(`/${INDEX_ALERTS}/_update/${id}`, {
      doc: updateDoc
    });

    res.json({
      _id: id,
      message: `Alert ${status} successfully`,
      result: response.data.result,
      ...updateDoc
    });
  } catch (error) {
    console.error('Update alert error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to update alert',
      details: error.response?.data?.error || error.message,
      timestamp: new Date().toISOString()
    });
  }
});

/**
 * @openapi
 * /logs/{id}:
 *   delete:
 *     summary: Delete a log entry by ID
 *     tags: [Logs]
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *         description: Log document ID
 *     responses:
 *       200:
 *         description: Log deleted successfully
 *       404:
 *         description: Log not found
 *       500:
 *         description: Server error
 */
app.delete('/logs/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const response = await esClient.delete(`/${INDEX_LOGS}/_doc/${id}`);

    if (response.data.result === 'not_found') {
      return res.status(404).json({
        error: 'Log not found',
        timestamp: new Date().toISOString()
      });
    }

    res.json({
      message: 'Log deleted successfully',
      _id: id,
      result: response.data.result
    });
  } catch (error) {
    if (error.response?.status === 404) {
      return res.status(404).json({
        error: 'Log not found',
        timestamp: new Date().toISOString()
      });
    }

    console.error('Delete log error:', error.response?.data || error.message);
    res.status(500).json({
      error: 'Failed to delete log',
      details: error.response?.data?.error || error.message,
      timestamp: new Date().toISOString()
    });
  }
});

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Smart Log Analyzer API',
    version: '1.0.0',
    docs: '/docs',
    openapi: '/openapi.json'
  });
});

// Global error handlers
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

process.on('uncaughtException', (error) => {
  console.error('Uncaught Exception:', error);
});

// Start server
app.listen(PORT, () => {
  console.log(`Smart Log Analyzer API is running on http://localhost:${PORT}`);
  console.log(`Swagger UI available at http://localhost:${PORT}/docs`);
  console.log(`OpenAPI spec available at http://localhost:${PORT}/openapi.json`);
  console.log(`Elasticsearch cluster: ${ES_CLUSTER}`);

  // Start periodic alert rule evaluation (every 1 minute)
  setInterval(() => {
    evaluateAlertRules().catch(err => {
      console.error('Periodic alert evaluation failed:', err.message);
    });
  }, 60000); // 60 seconds

  console.log('Alert rule evaluation running every 60 seconds');
});
