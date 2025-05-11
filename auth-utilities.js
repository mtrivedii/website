const crypto = require('crypto');
const sql = require('mssql');
const validator = require('validator');

// In-memory rate limiting
const rateLimits = {
  requestCounts: new Map(),
  lastCleanup: Date.now()
};

// Azure App Service Easy Auth parser
function extractUserInfo(req) {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.ip || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';

  const principalEncoded = req.headers['x-ms-client-principal'];
  if (!principalEncoded) return { isAuthenticated: false };

  let principalJson;
  try {
    const decoded = Buffer.from(principalEncoded, 'base64').toString('utf8');
    principalJson = JSON.parse(decoded);
  } catch (err) {
    console.warn('[auth] Failed to decode principal:', err.message);
    return { isAuthenticated: false };
  }

  const claims = principalJson.claims || [];
  const claimVal = type =>
    (claims.find(c => c.typ === type) || {}).val;

  const roles = claims
    .filter(c => c.typ.toLowerCase().includes('role'))
    .map(c => c.val.toLowerCase());

  const userId = claimVal('http://schemas.microsoft.com/identity/claims/objectidentifier')
    || claimVal('oid') || claimVal('sub');

  const username = claimVal('preferred_username') || claimVal('email') || 'User';

  if (!userId) return { isAuthenticated: false };

  return {
    isAuthenticated: true,
    userId,
    username,
    roles,
    clientIp,
    userAgent,
    authTimestamp: Date.now()
  };
}

// ✅ SQL-backed role checker (new)
async function requireRole(userInfo, requiredRole) {
  if (!userInfo?.isAuthenticated || !userInfo.userId) return false;

  try {
    const pool = await getSqlPool();
    const request = pool.request();
    request.input('userId', sql.VarChar(100), userInfo.userId.toLowerCase());

    const result = await request.query(`
      SELECT Role FROM dbo.users WHERE LOWER(AzureID) = @userId
    `);

    if (!result.recordset || result.recordset.length === 0) {
      console.warn(`[requireRole] AzureID not found: ${userInfo.userId}`);
      return false;
    }

    const dbRole = (result.recordset[0].Role || '').toLowerCase();
    const isAuthorized = dbRole === requiredRole.toLowerCase();

    console.log(`[requireRole] DB Role: ${dbRole}, Expected: ${requiredRole}, Authorized: ${isAuthorized}`);
    return isAuthorized;
  } catch (err) {
    console.error('[requireRole] DB error:', err.message);
    return false;
  }
}

// Standard secure headers
function addSecureHeaders(headers = {}) {
  const nonce = crypto.randomBytes(12).toString('base64');
  return {
    ...headers,
    'Content-Type': headers['Content-Type'] || 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Cache-Control': 'no-store',
    'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}'; object-src 'none'; base-uri 'self'; form-action 'self'`,
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Permissions-Policy': 'camera=(), geolocation=(), microphone=()',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'csp-nonce': nonce
  };
}

// Enhanced input validator
function validateInput(input, options = {}) {
  if ((input === undefined || input === null || input === '') && options.required !== false) return false;
  const value = String(input);
  if (options.maxLength && value.length > options.maxLength) return false;
  if (options.minLength && value.length < options.minLength) return false;

  if (typeof validator === 'object') {
    switch (options.type) {
      case 'email': return validator.isEmail(value);
      case 'alphanumeric': return validator.isAlphanumeric(value);
      case 'numeric': return validator.isNumeric(value);
      case 'integer': return validator.isInt(value);
      case 'ip': return validator.isIP(value);
      case 'uuid': return validator.isUUID(value);
      case 'json': return validator.isJSON(value);
      case 'url': return validator.isURL(value);
      case 'base64': return validator.isBase64(value);
      case 'hex': return validator.isHexadecimal(value);
      default: return true;
    }
  }
  return true;
}

// Simple logging
function logSecurityEvent(event, props = {}) {
  const log = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    type: 'SecurityEvent',
    name: event,
    ...props
  };
  if (log.severity === 'critical') console.error(log);
  else if (log.severity === 'warning') console.warn(log);
  else console.log(log);
  return log.id;
}

// Basic memory-based rate limiting
function checkRateLimit(key, limit = 60, windowMs = 60000) {
  const now = Date.now();
  const timestamps = rateLimits.requestCounts.get(key) || [];
  const windowStart = now - windowMs;
  const recent = timestamps.filter(t => t > windowStart);
  if (recent.length >= limit) {
    return {
      limited: true,
      reset: Math.floor((Math.min(...recent) + windowMs) / 1000)
    };
  }
  recent.push(now);
  rateLimits.requestCounts.set(key, recent);
  return {
    limited: false,
    remaining: limit - recent.length,
    reset: Math.floor((now + windowMs) / 1000)
  };
}

// Shared SQL pool
let sqlPool = null;
async function getSqlPool() {
  if (!sqlPool) {
    sqlPool = await sql.connect({
      connectionString: process.env.SqlConnectionString,
      options: {
        encrypt: true,
        trustServerCertificate: false
      }
    });
    sqlPool.on('error', err => {
      console.error('[SQL Pool Error]:', err);
      sqlPool = null;
    });
  }
  return sqlPool;
}

module.exports = {
  extractUserInfo,
  requireRole,
  addSecureHeaders,
  validateInput,
  logSecurityEvent,
  checkRateLimit
};
