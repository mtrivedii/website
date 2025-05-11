// enhanced-auth-utilities.js
const crypto = require('crypto');
const validator = require('validator');

// In-memory token blacklist (replace with Redis for production)
const tokenBlacklist = new Set();

// In-memory rate limit store (replace with Redis for production)
const rateLimits = {
  requestCounts: new Map(),
  lastCleanup: Date.now()
};

/**
 * Extracts and validates user info from Azure App Service Easy Auth headers
 */
function extractUserInfo(req) {
  try {
    // Client IP & UA
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0]
                   || req.headers['x-real-ip']
                   || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    // Log suspicious headers
    const suspiciousHeaders = [
      'x-forwarded-host', 'x-host',
      'x-original-url', 'x-rewrite-url', 'x-override-url'
    ];
    for (const h of suspiciousHeaders) {
      if (req.headers[h]) {
        console.warn(`Suspicious header ${h}=${req.headers[h]}, IP: ${clientIp}`);
      }
    }

    // Easy Auth header
    const clientPrincipal = req.headers['x-ms-client-principal'];
    if (!clientPrincipal) {
      console.warn(`Auth header missing. IP: ${clientIp}`);
      return { isAuthenticated: false, error: 'Not authenticated' };
    }

    // Must be Base64
    if (!/^[A-Za-z0-9+/=]+$/.test(clientPrincipal)) {
      console.warn(`Malformed auth header. IP: ${clientIp}`);
      return { isAuthenticated: false, error: 'Invalid authentication format' };
    }

    // Decode & parse JSON
    let principal;
    try {
      const decoded = Buffer.from(clientPrincipal, 'base64').toString('utf8');
      principal = JSON.parse(decoded);
    } catch (err) {
      console.error(`Auth decode error: ${err.message}`);
      return { isAuthenticated: false, error: 'Authentication decode error' };
    }

    if (!principal?.claims || !Array.isArray(principal.claims)) {
      console.warn(`Invalid principal structure. IP: ${clientIp}`);
      return { isAuthenticated: false, error: 'Invalid authentication data' };
    }

    // Sanitize and collect claims
    const claims = principal.claims.map(c => {
      if (
        typeof c.typ !== 'string' ||
        typeof c.val !== 'string' ||
        c.typ.length > 100 ||
        c.val.length > 500
      ) {
        throw new Error('Invalid claim format');
      }
      return {
        typ: c.typ,
        val: validator.escape(c.val)
      };
    });

    // Extract roles/app-roles
    let roles = claims
      .filter(c =>
        c.typ === 'roles' ||
        c.typ === 'role' ||
        c.typ === 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
      )
      .map(c => c.val);

    // Extract groups if you're using AAD group claims
    const groups = claims
      .filter(c =>
        c.typ === 'groups' ||
        c.typ === 'http://schemas.microsoft.com/claims/groups'
      )
      .map(c => c.val);
    roles = roles.concat(groups);

    // Always mark as authenticated
    if (!roles.includes('authenticated')) roles.push('authenticated');

    // Build boolean shortcuts
    const userRoles = {
      isAdmin: roles.some(r => r.toLowerCase() === 'admin'),
      canReadScoreboard: roles.some(r =>
        r.toLowerCase() === 'scoreboard.read' ||
        r.toLowerCase() === 'admin'
      ),
      canWriteScoreboard: roles.some(r =>
        r.toLowerCase() === 'scoreboard.write' ||
        r.toLowerCase() === 'admin'
      )
    };

    // Find userId & username
    const userIdClaim = claims.find(c =>
      c.typ === 'http://schemas.microsoft.com/identity/claims/objectidentifier' ||
      c.typ === 'oid' ||
      c.typ === 'sub'
    );
    const usernameClaim = claims.find(c =>
      c.typ === 'preferred_username' ||
      c.typ === 'name' ||
      c.typ === 'upn' ||
      c.typ === 'email'
    );

    if (!userIdClaim?.val) {
      console.warn(`Missing user ID. IP: ${clientIp}`);
      return { isAuthenticated: false, error: 'Incomplete authentication data' };
    }

    return {
      isAuthenticated: true,
      userId: userIdClaim.val,
      username: usernameClaim?.val || 'User',
      roles: userRoles,
      allRoles: roles,
      identityProvider: principal.identityProvider || 'unknown',
      clientIp,
      userAgent: userAgent.substring(0, 500),
      requestNonce: crypto.randomBytes(16).toString('hex'),
      authTimestamp: Date.now()
    };
  } catch (error) {
    console.error('Critical error in auth processing:', error);
    return { isAuthenticated: false, error: 'Authentication processing error' };
  }
}

/**
 * Check if user has required role (case-insensitive)
 */
function requireRole(userInfo, role) {
  if (!userInfo?.isAuthenticated) return false;
  // Expire after 30m
  if (Date.now() - userInfo.authTimestamp > 30 * 60 * 1000) return false;

  const want = role.toLowerCase();
  switch (want) {
    case 'admin':
      return userInfo.roles.isAdmin === true;
    case 'authenticated':
      return true; // any signed-in user
    case 'scoreboard.read':
      return userInfo.roles.canReadScoreboard === true;
    case 'scoreboard.write':
      return userInfo.roles.canWriteScoreboard === true;
    default:
      return userInfo.allRoles.some(r => r.toLowerCase() === want);
  }
}

/**
 * Log security events
 */
function logSecurityEvent(eventName, properties = {}) {
  try {
    const log = {
      type: 'SecurityEvent',
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      name: eventName,
      severity: properties.severity || 'warning',
      ...properties
    };
    if (log.severity === 'critical') console.error(log);
    else if (log.severity === 'warning') console.warn(log);
    else console.log(log);
    return log.id;
  } catch (err) {
    console.error('Failed to log security event:', err);
    return null;
  }
}

/**
 * Create secure headers
 */
function addSecureHeaders(headers = {}) {
  const cspNonce = crypto.randomBytes(16).toString('base64');
  return {
    ...headers,
    'Content-Type': headers['Content-Type'] || 'application/json',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'X-XSS-Protection': '1; mode=block',
    'Cache-Control': headers['Cache-Control'] || 'no-store',
    'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${cspNonce}'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'`,
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'X-Permitted-Cross-Domain-Policies': 'none',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Resource-Policy': 'same-origin',
    'Permissions-Policy': 'camera=(), geolocation=(), microphone=()',
    'X-DNS-Prefetch-Control': 'off',
    'csp-nonce': cspNonce
  };
}

/**
 * Input validation
 */
function validateInput(input, options = {}) {
  if ((input == null || input === '') && options.required !== false) return false;
  if ((input == null || input === '') && options.required === false) return true;
  const value = String(input);
  if (options.maxLength && value.length > options.maxLength) return false;
  if (options.minLength && value.length < options.minLength) return false;

  if (validator) {
    switch (options.type) {
      case 'email':      return validator.isEmail(value);
      case 'alphanumeric': return validator.isAlphanumeric(value);
      case 'numeric':    return validator.isNumeric(value);
      case 'integer':    return validator.isInt(value);
      case 'float':      return validator.isFloat(value);
      case 'ip':         return validator.isIP(value);
      case 'uuid':       return validator.isUUID(value);
      case 'date':       return validator.isISO8601(value);
      case 'json':       return validator.isJSON(value);
      case 'url':        return validator.isURL(value, { require_tld: options.requireTLD !== false });
      case 'base64':     return validator.isBase64(value);
      case 'hex':        return validator.isHexadecimal(value);
      case 'jwt':        return validator.isJWT(value);
      case 'username':   return /^[a-zA-Z0-9_-]{3,30}$/.test(value);
      case 'password':   return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/.test(value);
      default:
        // Reject obvious XSS payloads
        return !/<script|javascript:|onerror=|onload=|eval\(/i.test(value);
    }
  }

  // Fallback basic checks
  switch (options.type) {
    case 'email': return /^[^@]+@[^@]+\.[^@]+$/.test(value);
    case 'integer': return /^-?\d+$/.test(value);
    case 'numeric': return /^-?\d+(\.\d+)?$/.test(value);
    case 'alphanumeric': return /^[a-zA-Z0-9]+$/.test(value);
    default: return true;
  }
}

/**
 * Mask email (for logs)
 */
function maskEmail(email) {
  if (typeof email !== 'string') return null;
  const escaped = validator.escape(email);
  const [name, domain] = escaped.split('@');
  if (!domain) return escaped;
  return `${name[0]}${'*'.repeat(Math.max(1, name.length - 1))}@${domain}`;
}

/**
 * Sanitize output recursively
 */
function sanitizeOutput(input) {
  if (input == null) return '';
  if (Array.isArray(input)) return input.map(sanitizeOutput);
  if (typeof input === 'object') {
    return Object.fromEntries(
      Object.entries(input).map(([k,v]) => [k, sanitizeOutput(v)])
    );
  }
  return validator.escape(String(input));
}

/**
 * Rate limiting (memory-based)
 */
function checkRateLimit(key, limit = 60, windowMs = 60000) {
  // Cleanup every 5m
  if (Date.now() - rateLimits.lastCleanup > 300000) {
    const cutoff = Date.now() - windowMs;
    for (const [k,timestamps] of rateLimits.requestCounts.entries()) {
      const recent = timestamps.filter(t => t > cutoff);
      if (recent.length) rateLimits.requestCounts.set(k, recent);
      else rateLimits.requestCounts.delete(k);
    }
    rateLimits.lastCleanup = Date.now();
  }
  const now = Date.now();
  const timestamps = rateLimits.requestCounts.get(key) || [];
  const windowStart = now - windowMs;
  const recent = timestamps.filter(t => t > windowStart);
  if (recent.length >= limit) {
    return { limited: true, remaining: 0, reset: Math.floor((Math.min(...recent) + windowMs)/1000) };
  }
  recent.push(now);
  rateLimits.requestCounts.set(key, recent);
  return { limited: false, remaining: limit - recent.length, reset: Math.floor((now + windowMs)/1000) };
}

/**
 * Blacklist a token (logout)
 */
function addToBlacklist(token, exp) {
  tokenBlacklist.add(token);
  if (exp) {
    const now = Math.floor(Date.now()/1000);
    if (exp > now) {
      setTimeout(() => tokenBlacklist.delete(token), (exp - now)*1000);
    }
  }
}

/**
 * Detect suspicious request patterns
 */
function detectSuspiciousPatterns(req) {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.headers['x-real-ip'] || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const url = req.url || '';

  let score = 0, reasons = [];

  // Bad headers
  const badH = [
    'x-original-url','x-rewrite-url','x-override-url',
    'x-forwarded-host','x-host'
  ];
  for (const h of badH) {
    if (req.headers[h]) {
      score += 2;
      reasons.push(`Suspicious header: ${h}`);
    }
  }

  // UA scanners
  const uaPatterns = [/sqlmap|nikto|nessus|acunetix|arachni|nmap/i];
  for (const p of uaPatterns) {
    if (p.test(userAgent)) {
      score += 2;
      reasons.push(`Scanner UA: ${p}`);
    }
  }

  // IP private ranges
  const ipPatterns = [/^192\.168\./, /^10\./, /^172\.(1[6-9]|2\d|3[0-1])\./];
  for (const p of ipPatterns) {
    if (p.test(clientIp)) {
      score += 1;
      reasons.push(`Private IP: ${p}`);
    }
  }

  // Suspicious URLs
  const urlPatterns = [/\.php|wp-admin|etc\/passwd/i];
  for (const p of urlPatterns) {
    if (p.test(url)) {
      score += 3;
      reasons.push(`Suspicious URL: ${p}`);
    }
  }

  return { suspiciousScore: score, reasons };
}


module.exports = {
  extractUserInfo,
  requireRole,
  logSecurityEvent,
  addSecureHeaders,
  validateInput,
  maskEmail,
  sanitizeOutput,
  checkRateLimit,
  addToBlacklist,
  detectSuspiciousPatterns
};
