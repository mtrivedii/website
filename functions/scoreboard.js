// functions/scoreboard.js
import {
  extractUserInfo, requireRole, // you can inline a simple role‐check
  checkRateLimit, logSecurityEvent
} from './auth-utilities.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  const requestId = crypto.randomUUID();

  // Auth + role
  const userInfo = await extractUserInfo(request, env);
  if (!userInfo.isAuthenticated) {
    return new Response('Unauthorized', { status: 401 });
  }
  if (!userInfo.allRoles.includes('Scoreboard.Read') && !userInfo.allRoles.includes('admin')) {
    return new Response('Forbidden', { status: 403 });
  }

  // Rate limit
  const rate = checkRateLimit(userInfo.userId);
  if (rate.limited) {
    return new Response('Too Many Requests', {
      status: 429,
      headers: { 'Retry-After': String(rate.reset) }
    });
  }

  // Fetch scoreboard via HTTP API
  const resp = await fetch(env.SQL_API_URL + '/scoreboard');
  if (!resp.ok) return new Response('Internal Error', { status: 500 });
  const data = await resp.json();

  logSecurityEvent('ScoreboardAccess', { userId: userInfo.userId, requestId });
  return new Response(JSON.stringify(data), { status: 200, headers: { 'Content-Type': 'application/json' } });
}
