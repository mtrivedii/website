import { decodeJwt } from 'jose';

export async function onRequestGet(context) {
  const { request, env } = context;
  const requestId = crypto.randomUUID();

  // 1. Authenticate using Cloudflare Access
  const jwt = request.headers.get("CF-Access-Jwt-Assertion");
  if (!jwt) {
    return new Response('Forbidden', { status: 403 });
  }
  let userInfo;
  try {
    userInfo = decodeJwt(jwt);
  } catch {
    return new Response('Invalid Token', { status: 401 });
  }

  // 2. Require admin role
  const roles = Array.isArray(userInfo.roles)
    ? userInfo.roles
    : userInfo.roles ? [userInfo.roles] : [];
  if (!roles.includes('admin')) {
    return new Response('Forbidden', { status: 403 });
  }

  // 3. (Recommended) Use Cloudflare dashboard for rate limiting
  // If you want in-code rate limiting, you can implement it here (not recommended for edge).

  // 4. Forward to your HTTP API
  const url = new URL(env.SQL_API_URL + '/users');
  if (request.url.includes('?id=')) url.search = request.url.split('?')[1];
  const resp = await fetch(url.toString());
  if (!resp.ok) return new Response('Internal Error', { status: 500 });
  const users = await resp.json();

  // 5. Logging (optional)
  console.warn('UsersFetched', { userId: userInfo.sub, count: users.length, requestId });

  return new Response(JSON.stringify(users), {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
}
