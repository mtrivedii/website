export async function onRequestGet(context) {
  const { request, env } = context;
  const requestId = crypto.randomUUID();

  // 1. Authenticate using Cloudflare Access
  const jwt = request.headers.get("CF-Access-Jwt-Assertion");
  if (!jwt) {
    return new Response(JSON.stringify({ error: 'Unauthorized', requestId }), { status: 401 });
  }

  const resp = await fetch(
    `${env.SQL_API_URL}/checkAdmin`, {
      method: "GET",
      headers: { "CF-Access-Jwt-Assertion": jwt }
    }
  );
  if (!resp.ok) return new Response('Internal Error', { status: 500 });
  const { isAdmin } = await resp.json();

  // 4. Return
  if (!isAdmin) {
    return new Response(JSON.stringify({ error: 'Forbidden', requestId }), { status: 403 });
  }
  return new Response(JSON.stringify({ message: 'Admin granted', requestId }), { status: 200 });
}
