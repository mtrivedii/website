// functions/checkAdmin.js
import {
  extractUserInfo, checkRateLimit,
  detectSuspiciousPatterns, logSecurityEvent
} from './auth-utilities.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  const requestId = crypto.randomUUID();

  // 1. Authenticate
  const userInfo = await extractUserInfo(request, env);
  if (!userInfo.isAuthenticated) {
    return new Response(JSON.stringify({ error: 'Unauthorized', requestId }), { status: 401 });
  }

  // 2. Rate-limit & detect anomalies
  const rate = checkRateLimit(userInfo.userId);
  if (rate.limited) {
    return new Response(JSON.stringify({ error: 'Too Many Requests', requestId }), {
      status: 429,
      headers: { 'Retry-After': String(rate.reset) }
    });
  }
  if (detectSuspiciousPatterns(request)) {
    logSecurityEvent('SuspiciousRequest', { userId: userInfo.userId, requestId });
  }

  // 3. Delegate admin-check to an HTTP API (you must implement)
  const resp = await fetch(
    `${env.SQL_API_URL}/checkAdmin?userId=${encodeURIComponent(userInfo.userId)}`,
    { headers: { Authorization: request.headers.get('Authorization') } }
  );
  if (!resp.ok) return new Response('Internal Error', { status: 500 });
  const { isAdmin } = await resp.json();
  logSecurityEvent('CheckAdmin', { userId: userInfo.userId, isAdmin, requestId });

  // 4. Return
  if (!isAdmin) {
    return new Response(JSON.stringify({ error: 'Forbidden', requestId }), { status: 403 });
  }
  return new Response(JSON.stringify({ message: 'Admin granted', requestId }), { status: 200 });
}
