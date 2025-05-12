// mocks/mock-checkAdmin.js
const mockSql = require('./mock-db');
const { extractUserInfo } = require('../auth-utilities');
const jwt = require('jsonwebtoken');

async function handler(req, res) {
  console.log('[MOCK API] /api/checkAdmin invoked');
  console.log('Request headers:', JSON.stringify(req.headers));
  
  // Check for JWT token in cookies
  const authToken = req.cookies?.auth_token;
  if (authToken) {
    try {
      console.log('[MOCK API] Found JWT token, verifying...');
      const decoded = jwt.verify(authToken, 'dev-secret-key');
      
      console.log(`[MOCK API] JWT verified for user: ${decoded.email} (${decoded.userId})`);
      
      // Check if user has admin role
      if (decoded.role && decoded.role.toLowerCase() === 'admin') {
        console.log(`[MOCK API] Admin access granted via JWT for ${decoded.email}`);
        return res.status(200).json({ message: 'Admin access granted' });
      } else {
        console.log(`[MOCK API] User ${decoded.email} is not an admin (role: ${decoded.role})`);
        return res.status(403).json({ error: 'Forbidden', details: 'User is not an admin' });
      }
    } catch (err) {
      console.error('[MOCK API] JWT verification error:', err);
      // Continue to Azure AD auth if JWT is invalid
    }
  }
  
  // Fallback to Azure AD authentication
  const userInfo = extractUserInfo(req);
  console.log(`Admin check for user ID: ${userInfo.userId || 'missing'}`);

  if (
    !userInfo.isAuthenticated ||
    !userInfo.userId ||
    typeof userInfo.userId !== 'string' ||
    userInfo.userId.length < 5
  ) {
    console.warn('[MOCK API] Unauthorized: Missing or invalid user ID');
    return res
      .status(401)
      .json({ error: 'Unauthorized', details: 'Not authenticated or missing client principal' });
  }

  try {
    const pool = await mockSql.connect();
    const request = pool.request();
    request.input('userId', mockSql.NVarChar, userInfo.userId);

    const query = 'SELECT Role FROM Users WHERE AzureID = @userId';
    console.log(`[MOCK API] Executing query: ${query} with userId = ${userInfo.userId}`);

    const result = await request.query(query);
    console.log('[MOCK API] Query result:', JSON.stringify(result.recordset));

    const userRole = result.recordset[0]?.Role;
    if (!userRole) {
      console.warn(`[MOCK API] Forbidden: User ${userInfo.userId} not found in database`);
      return res
        .status(403)
        .json({ error: 'Forbidden', details: 'User not found in database' });
    }

    console.log(`[MOCK API] User role found: ${userRole}`);
    if (userRole.trim().toLowerCase() === 'admin') {
      console.log(`[MOCK API] Admin access granted for user ${userInfo.userId}`);
      return res.status(200).json({ message: 'Admin access granted' });
    }

    console.warn(`[MOCK API] Forbidden: User ${userInfo.userId} is not an admin (role: ${userRole})`);
    return res
      .status(403)
      .json({ error: 'Forbidden', details: 'User is not an admin' });

  } catch (err) {
    console.error('[MOCK API] Database error:', err);
    return res
      .status(500)
      .json({ error: 'Database error', details: err.message });
  }
}

module.exports = { handler };