// functions/auth-utilities.js
import { jwtVerify } from 'jose';

const tokenBlacklist = new Set();

export async function extractUserInfo(request, env) {
  // 1) Easy Auth header (if using CF Access with JWT)
  const auth = request.headers.get('Authorization')?.split(' ')[1];
  if (!auth) return { isAuthenticated: false };

  // 2) Verify JWT against your AAD keys (set in wrangler.toml as env vars)
  let payload;
  try {
    const { payload: pl } = await jwtVerify(
      auth,
      async header => {
        const res = await fetch(env.JWKS_URI);
        const { keys } = await res.json();
        const key = keys.find(k => k.kid === header.kid);
        return await crypto.subtle.importKey(
          'jwk', key, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
          false, ['verify']
        );
      },
      {
        issuer:   env.AAD_ISSUER,
        audience: env.AAD_CLIENT_ID
      }
    );
    payload = pl;
  } catch {
    return { isAuthenticated: false };
  }

  // 3) Extract user info & roles
  const roles = Array.isArray(payload.roles) ? payload.roles : [];
  return {
    isAuthenticated: true,
    userId:          payload.oid || payload.sub,
    roles,
    allRoles:       roles
  };
}

const RATE_LIMITS = new Map();
export function checkRateLimit(key, limit = 60, windowMs = 60_000) {
  const now = Date.now();
  const entry = RATE_LIMITS.get(key) || [];
  const recent = entry.filter(ts => ts > now - windowMs);
  if (recent.length >= limit) {
    return { limited: true, reset: Math.ceil((Math.min(...recent) + windowMs) / 1000) };
  }
  recent.push(now);
  RATE_LIMITS.set(key, recent);
  return { limited: false, remaining: limit - recent.length };
}

export function detectSuspiciousPatterns(request) {
  // very basic – expand as needed
  const url = request.url;
  return /(<script|union\s+select)/i.test(url);
}

export function logSecurityEvent(name, props = {}) {
  // You can push to a Service like Logflare or to App Insights via its REST API
  console.warn(`[SECURITY] ${name}`, props);
}
