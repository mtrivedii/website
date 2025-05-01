// functions/upload.js
import {
  extractUserInfo, checkRateLimit,
  detectSuspiciousPatterns, logSecurityEvent
} from './auth-utilities.js';

export async function onRequestPost(context) {
  const { request, env } = context;
  const requestId = crypto.randomUUID();

  // Auth (any authenticated user)
  const userInfo = await extractUserInfo(request, env);
  if (!userInfo.isAuthenticated) {
    return new Response('Unauthorized', { status: 401 });
  }

  // Rate limit by IP
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  const rate = checkRateLimit(`upload:${ip}`, 5, 60_000);
  if (rate.limited) {
    logSecurityEvent('UploadRateLimitExceeded', { ip, requestId });
    return new Response('Too Many Requests', { status: 429 });
  }

  // JSON parse + size check
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

  // Log via HTTP API
  await fetch(env.SQL_API_URL + '/upload', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ filename, ipAddress, requestId })
  });

  if (detectSuspiciousPatterns(request)) {
    logSecurityEvent('SuspiciousUpload', { ip, filename, requestId });
  }

  return new Response(JSON.stringify({ message: 'OK', requestId }), { status: 200 });
}
