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
    // Client info for logging
    const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.headers['x-real-ip'] || 'unknown';
    const userAgent = req.headers['user-agent'] || 'unknown';

    // Suspicious headers
    const suspiciousHeaders = [
      'x-forwarded-host', 'x-host', 'x-original-url', 'x-rewrite-url', 'x-override-url'
    ];
    for (const header of suspiciousHeaders) {
      if (req.headers[header]) {
        console.warn(`Suspicious header detected: ${header}=${req.headers[header]}, IP: ${clientIp}`);
      }
    }

    // Check for Easy Auth header
    const clientPrincipal = req.headers['x-ms-client-principal'];
    if (!clientPrincipal) {
      console.warn(`Auth header missing. IP: ${clientIp}, UA: ${userAgent.substring(0, 100)}`);
      return { isAuthenticated: false, error: 'Not authenticated' };
    }

    // Validate base64 format
    if (!/^[A-Za-z0-9+/=]+$/.test(clientPrincipal)) {
      console.warn(`Malformed auth header detected. IP: ${clientIp}`);
      return { isAuthenticated: false, error: 'Invalid authentication format' };
    }

    // Decode and parse
    let decodedPrincipal, principal;
    try {
      decodedPrincipal = Buffer.from(clientPrincipal, 'base64').toString('utf8');
      principal = JSON.parse(decodedPrincipal);
    } catch (error) {
      console.error(`Auth header decode error: ${error.message}, IP: ${clientIp}`);
      return { isAuthenticated: false, error: 'Authentication decode error' };
    }

    // Validate principal structure
    if (!principal || typeof principal !== 'object' || !principal.claims || !Array.isArray(principal.claims)) {
      console.warn(`Invalid principal structure. IP: ${clientIp}`);
      return { isAuthenticated: false, error: 'Invalid authentication data' };
    }

    // Extract and validate claims
    const claims = principal.claims;
    for (const claim of claims) {
      if (!claim.typ || !claim.val || typeof claim.typ !== 'string' || typeof claim.val !== 'string' ||
          claim.typ.length > 100 || claim.val.length > 500) {
        console.warn(`Suspicious claim format detected. IP: ${clientIp}`);
        return { isAuthenticated: false, error: 'Invalid claim format' };
      }
      if (typeof validator === 'object' && typeof validator.escape === 'function') {
        claim.val = validator.escape(claim.val);
      }
    }

    // Extract roles
    const roles = claims
      .filter(claim =>
        claim.typ === 'roles' ||
        claim.typ === 'role' ||
        claim.typ === 'http://schemas.microsoft.com/ws/2008/06/identity/claims/role'
      )
      .map(claim => claim.val);

    // Normalize admin role
    if (claims.some(claim =>
      (claim.typ === 'roles' && claim.val === 'admin') ||
      (claim.typ === 'role' && claim.val === 'admin')
    )) {
      if (!roles.includes('admin')) roles.push('admin');
    }

    // Map roles to permissions
    const userRoles = {
      isAdmin: roles.some(r => r.toLowerCase() === 'admin'),
      canReadScoreboard: roles.some(r =>
        r.toLowerCase() === 'scoreboard.read' || r.toLowerCase() === 'admin'
      ),
      canWriteScoreboard: roles.some(r =>
        r.toLowerCase() === 'scoreboard.write' || r.toLowerCase() === 'admin'
      )
    };

    // Get user ID and username
    const userIdClaim = claims.find(claim =>
      claim.typ === 'http://schemas.microsoft.com/identity/claims/objectidentifier' ||
      claim.typ === 'oid' ||
      claim.typ === 'sub'
    );
    const usernameClaim = claims.find(claim =>
      claim.typ === 'preferred_username' ||
      claim.typ === 'name' ||
      claim.typ === 'upn' ||
      claim.typ === 'email'
    );

    if (!userIdClaim || !userIdClaim.val) {
      console.warn(`Missing user ID claim. IP: ${clientIp}`);
      return { isAuthenticated: false, error: 'Incomplete authentication data' };
    }

    // Generate a request nonce for CSRF protection
    const requestNonce = crypto.randomBytes(16).toString('hex');

    return {
      isAuthenticated: true,
      userId: userIdClaim.val,
      username: usernameClaim ? usernameClaim.val : 'User',
      roles: userRoles,
      allRoles: roles,
      identityProvider: principal.identityProvider || 'unknown',
      clientIp: clientIp,
      userAgent: userAgent.substring(0, 500),
      requestNonce: requestNonce,
      authTimestamp: Date.now()
    };
  } catch (error) {
    console.error('Critical error in auth processing:', error);
    return { isAuthenticated: false, error: 'Authentication processing error' };
  }
}

/**
 * Check if user has required role with case-insensitive comparison
 */
function requireRole(userInfo, role) {
  if (!userInfo || typeof userInfo !== 'object') return false;
  if (!userInfo.isAuthenticated || !userInfo.userId) return false;
  const maxAuthAge = 30 * 60 * 1000; // 30 min
  if (userInfo.authTimestamp && (Date.now() - userInfo.authTimestamp) > maxAuthAge) return false;
  const requestedRole = role.toLowerCase();
  switch (requestedRole) {
    case 'admin':
      return userInfo.roles && userInfo.roles.isAdmin === true;
    case 'scoreboard.read':
      return userInfo.roles && userInfo.roles.canReadScoreboard === true;
    case 'scoreboard.write':
      return userInfo.roles && userInfo.roles.canWriteScoreboard === true;
    default:
      return userInfo.allRoles &&
             Array.isArray(userInfo.allRoles) &&
             userInfo.allRoles.some(r => r.toLowerCase() === requestedRole);
  }
}

/**
 * Log security events with enhanced detail for incident response
 */
function logSecurityEvent(eventName, properties = {}) {
  try {
    const securityLog = {
      type: 'SecurityEvent',
      id: crypto.randomUUID(),
      timestamp: new Date().toISOString(),
      name: eventName,
      severity: properties.severity || 'warning',
      ...properties
    };
    if (securityLog.severity === 'critical') {
      console.error(securityLog);
    } else if (securityLog.severity === 'warning') {
      console.warn(securityLog);
    } else {
      console.log(securityLog);
    }
    return securityLog.id;
  } catch (error) {
    console.error('Failed to log security event:', error);
    return null;
  }
}

/**
 * Create secure headers with enhanced protections
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
 * Robust input validation for various input types
 */
function validateInput(input, options = {}) {
  if ((input === undefined || input === null || input === '') && options.required !== false) {
    return false;
  }
  if ((input === undefined || input === null || input === '') && options.required === false) {
    return true;
  }
  const value = String(input);
  if (options.maxLength && value.length > options.maxLength) return false;
  if (options.minLength && value.length < options.minLength) return false;
  if (typeof validator === 'object') {
    switch (options.type) {
      case 'email': return validator.isEmail(value);
      case 'alphanumeric': return validator.isAlphanumeric(value);
      case 'numeric': return validator.isNumeric(value);
      case 'integer': return validator.isInt(value);
      case 'float': return validator.isFloat(value);
      case 'ip': return validator.isIP(value);
      case 'uuid': return validator.isUUID(value);
      case 'date': return validator.isISO8601(value);
      case 'json': return validator.isJSON(value);
      case 'url': return validator.isURL(value, { require_tld: options.requireTLD !== false });
      case 'base64': return validator.isBase64(value);
      case 'hex': return validator.isHexadecimal(value);
      case 'jwt': return validator.isJWT(value);
      case 'username': return /^[a-zA-Z0-9_-]{3,30}$/.test(value);
      case 'password': return /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/.test(value);
      default: return !/<script|javascript:|data:|vbscript:|file:|alert\(|confirm\(|prompt\(|onerror=|onload=|onclick=|eval\(|document\.cookie/i.test(value);
    }
  } else {
    switch (options.type) {
      case 'email': return /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(value);
      case 'integer': return /^-?\d+$/.test(value);
      case 'numeric': return /^-?\d+(\.\d+)?$/.test(value);
      case 'alphanumeric': return /^[a-zA-Z0-9]+$/.test(value);
      default: return !/<script|javascript:|data:|vbscript:|file:|alert\(|confirm\(|prompt\(|onerror=|onload=|onclick=|eval\(|document\.cookie/i.test(value);
    }
  }
}

/**
 * Helper function to mask sensitive data for privacy with enhanced security
 */
function maskEmail(email) {
  if (!email) return null;
  if (typeof email !== 'string') return null;
  let sanitizedEmail = email;
  if (typeof validator === 'object' && typeof validator.escape === 'function') {
    sanitizedEmail = validator.escape(email);
  }
  const [name, domain] = sanitizedEmail.split('@');
  if (!domain) return sanitizedEmail;
  return `${name.charAt(0)}${'*'.repeat(Math.max(1, name.length - 1))}@${domain}`;
}

/**
 * Sanitize output to prevent XSS
 */
function sanitizeOutput(input) {
  if (input === null || input === undefined) return '';
  if (typeof input === 'object') {
    if (Array.isArray(input)) {
      return input.map(item => sanitizeOutput(item));
    }
    const sanitized = {};
    for (const key in input) {
      if (Object.prototype.hasOwnProperty.call(input, key)) {
        sanitized[key] = sanitizeOutput(input[key]);
      }
    }
    return sanitized;
  }
  const str = String(input);
  if (typeof validator === 'object' && typeof validator.escape === 'function') {
    return validator.escape(str);
  }
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

/**
 * Rate limiting implementation (memory-based, use Redis in production)
 */
function checkRateLimit(key, limit = 60, windowMs = 60000) {
  // Clean up old entries every 5 minutes
  if (Date.now() - rateLimits.lastCleanup > 300000) {
    const cutoff = Date.now() - windowMs;
    for (const [entryKey, timestamps] of rateLimits.requestCounts.entries()) {
      const validTimestamps = timestamps.filter(time => time > cutoff);
      if (validTimestamps.length === 0) {
        rateLimits.requestCounts.delete(entryKey);
      } else {
        rateLimits.requestCounts.set(entryKey, validTimestamps);
      }
    }
    rateLimits.lastCleanup = Date.now();
  }
  const now = Date.now();
  const timestamps = rateLimits.requestCounts.get(key) || [];
  const windowStart = now - windowMs;
  const recentTimestamps = timestamps.filter(time => time > windowStart);
  if (recentTimestamps.length >= limit) {
    return {
      limited: true,
      remaining: 0,
      reset: Math.floor((Math.min(...recentTimestamps) + windowMs) / 1000)
    };
  }
  recentTimestamps.push(now);
  rateLimits.requestCounts.set(key, recentTimestamps);
  return {
    limited: false,
    remaining: limit - recentTimestamps.length,
    reset: Math.floor((now + windowMs) / 1000)
  };
}

/**
 * Add token to blacklist for secure logout
 */
function addToBlacklist(token, exp) {
  tokenBlacklist.add(token);
  const now = Math.floor(Date.now() / 1000);
  if (exp && exp > now) {
    setTimeout(() => {
      tokenBlacklist.delete(token);
    }, (exp - now) * 1000);
  }
}

/**
 * Detect suspicious patterns for honeypot functionality
 */
function detectSuspiciousPatterns(req) {
  const clientIp = req.headers['x-forwarded-for']?.split(',')[0] || req.headers['x-real-ip'] || 'unknown';
  const userAgent = req.headers['user-agent'] || 'unknown';
  const referer = req.headers['referer'] || 'unknown';
  const host = req.headers['host'] || 'unknown';

  let suspiciousScore = 0;
  let reasons = [];

  // Check request headers for suspicious patterns
  const suspiciousHeaders = [
    'x-original-url', 'x-rewrite-url', 'x-override-url',
    'x-forwarded-host', 'x-host',
    'x-up-calling-line-id', 'charge-to', 'user-charge-to',
    'x-http-backdoor', 'x-http-method-override'
  ];
  for (const header of suspiciousHeaders) {
    if (req.headers[header]) {
      suspiciousScore += 2;
      reasons.push(`Suspicious header detected: ${header}`);
    }
  }

  // Suspicious user agent patterns
  const suspiciousUserAgentPatterns = [
    /sqlmap|nikto|nessus|acunetix|arachni|metasploit|nmap/i,
    /ZmEu|python-requests|wget|curl|go http|netsparker|dirbuster/i,
    /HeadlessChrome|PhantomJS/,
    /\\x[0-9a-f]{2}/i,
  ];
  for (const pattern of suspiciousUserAgentPatterns) {
    if (pattern.test(userAgent)) {
      suspiciousScore += 2;
      reasons.push(`Suspicious user agent pattern detected: ${pattern}`);
    }
  }

  // Suspicious IP patterns
  const suspiciousIpPatterns = [
    /^192\.168\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^127\./
  ];
  for (const pattern of suspiciousIpPatterns) {
    if (pattern.test(clientIp)) {
      suspiciousScore += 1;
      reasons.push(`Suspicious IP pattern detected: ${pattern}`);
    }
  }

  // Suspicious URL patterns
  const url = req.url || '';
  const suspiciousUrlPatterns = [
    /\.(php|asp|aspx|jsp|cgi|bak|old|backup|zip|tar|gz)$/i,
    /\/(admin|phpMyAdmin|phpmyadmin|admin\.php|wp-admin|wp-login)/i,
    /\/(etc\/passwd|boot\.ini|win\.ini|system32)/,
    /[;'"<>]|\.\.|\/\/|%00|%27|%3C|%3E|%22/i,
    /SELECT|UNION|INSERT|UPDATE|DELETE|DROP|ALTER|EXEC|CONCAT/i
  ];
  for (const pattern of suspiciousUrlPatterns) {
    if (pattern.test(url)) {
      suspiciousScore += 3;
      reasons.push(`Suspicious URL pattern detected: ${pattern}`);
    }
  }

  return {
    isSuspicious: suspiciousScore >= 3,
    score: suspiciousScore,
    reasons
  };
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
