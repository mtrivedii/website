const express = require('express');
const sql = require('mssql');
const crypto = require('crypto');
const {
  extractUserInfo,
  requireRole,
  addSecureHeaders,
  logSecurityEvent,
  validateInput,
  checkRateLimit
} = require('./auth-utilities');

const router = express.Router();

// SQL connection pooling
let sqlPool = null;
const poolConnectTimeout = 30000;

async function getSqlPool() {
  if (!sqlPool) {
    try {
      sqlPool = await sql.connect({
        connectionString: process.env.SqlConnectionString,
        options: {
          encrypt: true,
          trustServerCertificate: false,
          connectTimeout: poolConnectTimeout,
          requestTimeout: 15000,
          maxRetriesOnTransientErrors: 3,
          pool: {
            max: 10,
            min: 0,
            idleTimeoutMillis: 30000
          }
        }
      });

      sqlPool.on('error', err => {
        console.error('SQL pool error:', err);
        sqlPool = null;
      });

    } catch (err) {
      sqlPool = null;
      throw err;
    }
  }
  return sqlPool;
}

router.get('/users', async (req, res) => {
  const requestId = crypto.randomUUID();
  const startTime = Date.now();
  const clientIp =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.headers['x-real-ip'] ||
    req.ip ||
    'unknown';

  const rateLimit = checkRateLimit(`users:${clientIp}`, 20, 60000);
  if (rateLimit.limited) {
    logSecurityEvent('RateLimitExceeded', { endpoint: '/api/users', clientIp, requestId });
    return res.status(429).set({
      ...addSecureHeaders(),
      'Retry-After': Math.ceil(rateLimit.reset - Math.floor(Date.now() / 1000)),
      'Content-Type': 'application/json'
    }).json({ message: 'Too many requests', requestId });
  }

  console.log(`[${requestId}] /api/users called`);

  if (req.method !== 'GET') {
    logSecurityEvent('InvalidMethod', { endpoint: '/api/users', method: req.method, clientIp, requestId });
    return res.status(405).set({
      ...addSecureHeaders(),
      Allow: 'GET',
      'Content-Type': 'application/json'
    }).json({ message: 'Method not allowed', requestId });
  }

  const userInfo = extractUserInfo(req);
  console.log(`[${requestId}] Authenticated user info:`, userInfo);

  if (!userInfo.isAuthenticated) {
    logSecurityEvent('UnauthorizedAccess', { endpoint: '/api/users', clientIp, requestId });
    return res.status(401).set({
      ...addSecureHeaders(),
      'Content-Type': 'application/json'
    }).json({ message: 'Authentication required', requestId });
  }

  // Enforce role-based access
  const hasRole = await requireRole(userInfo, 'admin');
  if (!hasRole) {
    logSecurityEvent('InsufficientPrivileges', {
      endpoint: '/api/users',
      userId: userInfo.userId,
      username: userInfo.username,
      clientIp,
      requestId
    });
    return res.status(403).set({
      ...addSecureHeaders(),
      'Content-Type': 'application/json'
    }).json({ message: 'Admin permission required', requestId });
  }

  const userId = req.query.id;
  if (userId !== null && userId !== undefined) {
    if (!validateInput(userId, { type: 'integer', maxLength: 10 })) {
      logSecurityEvent('InvalidInput', {
        endpoint: '/api/users',
        parameter: 'id',
        value: String(userId).substring(0, 20),
        clientIp,
        requestId
      });
      return res.status(400).set({
        ...addSecureHeaders(),
        'Content-Type': 'application/json'
      }).json({ message: 'Invalid user ID format', requestId });
    }
  }

  try {
    const pool = await getSqlPool();
    const sqlRequest = pool.request();
    sqlRequest.timeout = 5000;

    let query = 'SELECT id, email, password, AzureID, Role FROM dbo.users';
    if (userId) {
      query += ' WHERE id = @userId';
      sqlRequest.input('userId', sql.Int, parseInt(userId, 10));
    }

    query += ' ORDER BY id ASC OFFSET 0 ROWS FETCH NEXT 100 ROWS ONLY';

    const result = await Promise.race([
      sqlRequest.query(query),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Query timeout')), 5000)
      )
    ]);

    console.log(`[${requestId}] Retrieved ${result.recordset.length} users`);

    const sanitizedUsers = result.recordset.map(user => ({
      id: user.id,
      email: user.email || '',
      password: user.password || '',
      AzureID: user.AzureID || '',
      Role: user.Role || ''
    }));

    const responseTime = Date.now() - startTime;

    return res.status(200).set({
      ...addSecureHeaders({
        'Cache-Control': 'max-age=60',
        'X-Response-Time': `${responseTime}ms`
      }),
      'Content-Type': 'application/json'
    }).json(sanitizedUsers);

  } catch (err) {
    logSecurityEvent('DatabaseError', {
      endpoint: '/api/users',
      errorType: err.name,
      errorMessage: err.message,
      requestId,
      clientIp
    });
    console.error(`[${requestId}] Error fetching users:`, err);
    return res.status(500).set({
      ...addSecureHeaders(),
      'Content-Type': 'application/json'
    }).json({ message: 'Internal Server Error', requestId });
  }
});

module.exports = router;
