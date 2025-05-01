import { decodeJwt } from 'jose';

export async function onRequestGet(context) {
  const { request, env } = context;
  const requestId = crypto.randomUUID();

  // 1. Authenticate using Cloudflare Access
  const jwt = request.headers.get("CF-Access-Jwt-Assertion");
  if (!jwt) {
    return new Response('Unauthorized', { status: 401 });
  }

  // 2. Extract roles from the JWT
  let userInfo;
  try {
    userInfo = decodeJwt(jwt);
  } catch {
    return new Response('Invalid Token', { status: 401 });
  }

  // 3. Role check (inline)
  const roles = Array.isArray(userInfo.roles)
    ? userInfo.roles
    : userInfo.roles ? [userInfo.roles] : [];
  if (!roles.includes('Scoreboard.Read') && !roles.includes('admin')) {
    return new Response('Forbidden', { status: 403 });
  }

  // 4. (Optional) Rate limiting can be handled by Cloudflare dashboard rules
  // If you want in-code rate limiting, you can implement it here (not recommended for edge functions)

  // 5. Fetch scoreboard via HTTP API
  const resp = await fetch(env.SQL_API_URL + '/scoreboard');
  if (!resp.ok) return new Response('Internal Error', { status: 500 });
  const data = await resp.json();

  // 6. (Optional) Log security event (use console.warn for basic logging)
  console.warn('ScoreboardAccess', { userId: userInfo.sub, requestId });

  return new Response(JSON.stringify(data), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
}
