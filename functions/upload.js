import { decodeJwt } from 'jose';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = crypto.randomUUID();

  // 1. Authenticate using Cloudflare Access
  const jwt = request.headers.get("CF-Access-Jwt-Assertion");
  if (!jwt) {
    return new Response('Unauthorized', { status: 401 });
  }
  let userInfo;
  try {
    userInfo = decodeJwt(jwt);
  } catch {
    return new Response('Invalid Token', { status: 401 });
  }

  // 2. (Recommended) Rate limit uploads using Cloudflare dashboard rules
  // If you want in-code rate limiting (not recommended for edge), you could implement it here.
  // But Cloudflare's built-in rate limiting is more robust and scalable.
  // Remove in-code rate limiting for production.

  // 3. Parse and validate JSON body
  let body;
  try {
    body = await request.json();
    if (JSON.stringify(body).length > 10_000) throw new Error('Payload too large');
  } catch (e) {
    return new Response(e.message, { status: 400 });
  }

  const { filename, ipAddress } = body;
  if (!filename || filename.length > 255) {
    return new Response('Invalid filename', { status: 400 });
  }

  // 4. Log upload via HTTP API
  await fetch(env.SQL_API_URL + '/upload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filename, ipAddress, requestId, user: userInfo.email || userInfo.sub })
  });

  // 5. (Optional) Log suspicious uploads (use WAF for production)
  // For basic logging:
  // console.warn('SuspiciousUpload', { ip: request.headers.get('cf-connecting-ip'), filename, requestId });

  return new Response(JSON.stringify({ message: 'OK', requestId }), { status: 200 });
}
