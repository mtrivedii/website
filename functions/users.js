// functions/users.js
import {
  extractUserInfo, checkRateLimit,
  logSecurityEvent
} from './auth-utilities.js';

export async function onRequestGet(context) {
  const { request, env } = context;
  const requestId = crypto.randomUUID();

  // Require admin
  const userInfo = await extractUserInfo(request, env);
  if (!userInfo.isAuthenticated || !userInfo.allRoles.includes('admin')) {
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

  // Forward to your HTTP API
  const url = new URL(env.SQL_API_URL + '/users');
  if (request.url.includes('?id=')) url.search = request.url.split('?')[1];
  const resp = await fetch(url.toString());
  if (!resp.ok) return new Response('Internal Error', { status: 500 });
  const users = await resp.json();

  logSecurityEvent('UsersFetched', { userId: userInfo.userId, count: users.length, requestId });
  return new Response(JSON.stringify(users), { status: 200, headers: { 'Content-Type': 'application/json' } });
}
