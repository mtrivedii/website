// users.js - Secured API endpoint for user directory
const express = require('express');
const sql = require('mssql');
const {
  extractUserInfo,
  requireRole,
  addSecureHeaders,
  logSecurityEvent,
  validateInput,
  checkRateLimit,
  sanitizeOutput
} = require('./auth-utilities');

const router = express.Router();

// SQL connection pooling with enhanced security
let sqlPool = null;
const poolConnectTimeout = 30000; // 30 seconds timeout
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
        console.error('SQL connection pool error:', err);
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

  // Get client IP for rate limiting and logging
  const clientIp =
    req.headers['x-forwarded-for']?.split(',')[0] ||
    req.headers['x-real-ip'] ||
    req.ip ||
    'unknown';

  // Rate limiting
  const rateLimit = checkRateLimit(`users:${clientIp}`, 20, 60000); // 20 requests per minute
  if (rateLimit.limited) {
    logSecurityEvent('RateLimitExceeded', {
      endpoint: '/api/users',
      clientIp,
      requestId,
      severity: 'warning'
    });
    return res
      .status(429)
      .set({
        ...addSecureHeaders(),
        'Retry-After': Math.ceil(rateLimit.reset - Math.floor(Date.now() / 1000)),
        'Content-Type': 'application/json'
      })
      .json({
        message: 'Too many requests',
        requestId
      });
  }

  // Method check (Express router restricts to GET, but double-check)
  if (req.method !== 'GET') {
    logSecurityEvent('InvalidMethod', {
      endpoint: '/api/users',
      method: req.method,
      clientIp,
      requestId,
      severity: 'warning'
    });
    return res
      .status(405)
      .set({
        ...addSecureHeaders(),
        Allow: 'GET',
        'Content-Type': 'application/json'
      })
      .json({
        message: 'Method not allowed',
        requestId
      });
  }

  // Extract user info
  const userInfo = extractUserInfo(req);

  // Enforce authentication
  if (!userInfo.isAuthenticated) {
    const securityEventId = logSecurityEvent('UnauthorizedAccess', {
      endpoint: '/api/users',
      clientIp,
      userAgent: req.headers['user-agent']?.substring(0, 200) || 'unknown',
      requestId,
      severity: 'warning'
    });
    return res
      .status(401)
      .set({
        ...addSecureHeaders(),
        'Content-Type': 'application/json'
      })
      .json({
        message: 'Authentication required',
        requestId,
        securityEventId
      });
  }

  // Enforce role-based access (admin only)
  if (!requireRole(userInfo, 'admin')) {
    const securityEventId = logSecurityEvent('InsufficientPrivileges', {
      endpoint: '/api/users',
      userId: userInfo.userId,
      username: userInfo.username,
      clientIp,
      requestId,
      severity: 'warning'
    });
    return res
      .status(403)
      .set({
        ...addSecureHeaders(),
        'Content-Type': 'application/json'
      })
      .json({
        message: 'Admin permission required',
        requestId,
        securityEventId
      });
  }

  // Strict input validation for query parameters
  const userId = req.query.id;
  if (userId !== null && userId !== undefined) {
    if (!validateInput(userId, { type: 'integer', maxLength: 10 })) {
      const securityEventId = logSecurityEvent('InvalidInput', {
        endpoint: '/api/users',
        parameter: 'id',
        value: String(userId).substring(0, 20),
        clientIp,
        requestId,
        severity: 'warning'
      });
      return res
        .status(400)
        .set({
          ...addSecureHeaders(),
          'Content-Type': 'application/json'
        })
        .json({
          message: 'Invalid user ID format',
          requestId,
          securityEventId
        });
    }
  }

  try {
    // Get SQL connection pool
    const pool = await getSqlPool();

    // Create request with parameterized query
    const sqlRequest = pool.request();
    sqlRequest.timeout = 5000; // 5 second timeout

    // SECURITY IMPROVEMENT: Only select necessary, non-sensitive fields
    let query = `
      SELECT 
        id, 
        email, 
        Role as role, 
        status, 
        mfa_enabled as twoFactorEnabled,
        last_login as lastLogin,
        password_last_changed as passwordLastChanged
      FROM dbo.users
    `;

    // Apply filtering with strict parameterization
    if (userId) {
      query += ' WHERE id = @userId';
      sqlRequest.input('userId', sql.Int, parseInt(userId, 10));
    }

    // Principle of least privilege - limit results and sort
    query += ' ORDER BY id ASC OFFSET 0 ROWS FETCH NEXT 100 ROWS ONLY';

    // Execute the query with timeout handling
    let result;
    try {
      result = await Promise.race([
        sqlRequest.query(query),
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error('Query timeout')), 5000)
        )
      ]);
    } catch (queryError) {
      throw new Error(`Query execution error: ${queryError.message}`);
    }

    // Sanitize user data before returning
    const sanitizedUsers = result.recordset.map(user => ({
      id: user.id,
      email: user.email || '',
      role: user.role || '',
      status: user.status || 'Inactive',
      twoFactorEnabled: !!user.twoFactorEnabled,
      lastLogin: user.lastLogin,
      passwordLastChanged: user.passwordLastChanged
    }));

    // Add response time header for performance monitoring
    const responseTime = Date.now() - startTime;

    // Log successful access for audit
    logSecurityEvent('UserDirectoryAccess', {
      endpoint: '/api/users',
      userId: userInfo.userId,
      username: userInfo.username,
      resultCount: sanitizedUsers.length,
      requestId,
      clientIp,
      responseTime,
      severity: 'info'
    });

    return res
      .status(200)
      .set({
        ...addSecureHeaders({
          'Cache-Control': 'max-age=60',
          'X-Response-Time': `${responseTime}ms`
        }),
        'Content-Type': 'application/json'
      })
      .json(sanitizedUsers);

  } catch (err) {
    const securityEventId = logSecurityEvent('DatabaseError', {
      endpoint: '/api/users',
      errorType: err.name,
      errorMessage: err.message,
      requestId,
      clientIp,
      severity: 'error'
    });
    console.error(`[${requestId}] Error fetching users:`, err);
    return res
      .status(500)
      .set({
        ...addSecureHeaders(),
        'Content-Type': 'application/json'
      })
      .json({
        message: 'Internal Server Error',
        requestId,
        securityEventId
      });
  }
});

module.exports = router;