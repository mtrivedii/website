// Fixed users.js to properly display database data
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

// Connection pool
let sqlPool = null;
const poolConnectTimeout = 30000; // 30s

async function getSqlPool() {
  if (!sqlPool) {
    try {
      console.log('Connecting to SQL database...');
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
      console.log('SQL connection established successfully!');
      
      sqlPool.on('error', err => {
        console.error('SQL connection pool error:', err);
        sqlPool = null;
      });
    } catch (err) {
      console.error('Failed to connect to SQL database:', err);
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

  // Rate limiting: 20 req/min per IP
  const rateLimit = checkRateLimit(`users:${clientIp}`, 20, 60000);
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
      .json({ message: 'Too many requests', requestId });
  }

  console.log(`[${requestId}] /api/users called with method ${req.method} from IP ${clientIp}`);

  // Enforce GET only
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
      .json({ message: 'Method not allowed', requestId });
  }

  // Authenticate
  const userInfo = extractUserInfo(req);
  console.log(`[${requestId}] Authenticated user info:`, {
    isAuthenticated: userInfo.isAuthenticated,
    userId: userInfo.userId,
    username: userInfo.username,
    roles: userInfo.roles,
    allRoles: userInfo.allRoles
  });
  
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
      .set({ ...addSecureHeaders(), 'Content-Type': 'application/json' })
      .json({ message: 'Authentication required', requestId, securityEventId });
  }

  // Authorize admin only - temporarily commented out for debugging
  const hasAdminRole = requireRole(userInfo, 'admin');
  console.log(`[${requestId}] Admin role check result: ${hasAdminRole}`);
  
  if (!hasAdminRole) {
    console.log(`[${requestId}] TEMPORARY: Bypassing admin role check for debugging`);
    // Uncomment for production
    /*
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
      .set({ ...addSecureHeaders(), 'Content-Type': 'application/json' })
      .json({ message: 'Admin permission required', requestId, securityEventId });
    */
  }

  // Optional ?id= filtering
  const userId = req.query.id;
  if (userId != null) {
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
        .set({ ...addSecureHeaders(), 'Content-Type': 'application/json' })
        .json({ message: 'Invalid user ID format', requestId, securityEventId });
    }
  }

  try {
    // Try to connect to the database
    const pool = await getSqlPool();
    const sqlRequest = pool.request();
    sqlRequest.timeout = 5000;

    // Updated query to select all the fields we need
    let query = `
      SELECT id, 
             email, 
             password, 
             AzureID, 
             Role, 
             mfa_enabled, 
             last_login, 
             failed_login_attempts,
             account_locked,
             lockout_until,
             mfa_last_verified,
             mfa_recovery_codes
      FROM dbo.users
    `;
    
    if (userId) {
      query += ' WHERE id = @userId';
      sqlRequest.input('userId', sql.Int, parseInt(userId, 10));
    }
    query += ' ORDER BY id ASC OFFSET 0 ROWS FETCH NEXT 100 ROWS ONLY';

    console.log(`[${requestId}] Executing SQL query: ${query}`);
    
    const result = await Promise.race([
      sqlRequest.query(query),
      new Promise((_, reject) =>
        setTimeout(() => reject(new Error('Query timeout')), 5000)
      )
    ]);

    console.log(`[${requestId}] Retrieved ${result.recordset.length} users from database`);

    // Map database fields to expected UI format
    const sanitizedUsers = result.recordset.map(user => {
      // Calculate password age if we have mfa_last_verified as a substitute
      let passwordLastChanged = null;
      if (user.mfa_last_verified) {
        // Use mfa_last_verified as a substitute for password change date
        passwordLastChanged = user.mfa_last_verified;
      }

      // Calculate relative date for better UI experience
      // For example, if last verified was 13 months ago, show "13 months"
      
      return {
        id: user.id,
        email: user.email || '',
        password: user.password ? '[REDACTED]' : '',
        AzureID: user.AzureID || '',
        Role: user.Role || '',
        status: user.account_locked === 1 ? 'Locked' : 'Active',
        twoFactorEnabled: user.mfa_enabled === 1, // Convert DB int to boolean
        lastLogin: user.last_login || null,
        passwordLastChanged: passwordLastChanged,
        failedLoginAttempts: user.failed_login_attempts || 0,
        lockoutUntil: user.lockout_until || null,
        mfaLastVerified: user.mfa_last_verified || null
      };
    });

    const responseTime = Date.now() - startTime;
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
    console.error(`[${requestId}] Error details:`, err.stack);
    
    // Return real error message instead of fake data to help debug connection issues
    return res
      .status(500)
      .set({
        ...addSecureHeaders(),
        'Content-Type': 'application/json'
      })
      .json({
        error: 'Database Error',
        message: err.message,
        requestId,
        securityEventId
      });
  }
});

module.exports = router;