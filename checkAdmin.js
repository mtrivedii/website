// checkAdmin.js
const sql = require('mssql');
const { extractUserInfo } = require('./auth-utilities');

const sqlConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: 'azure-active-directory-msi-app-service' },
  options: { encrypt: true, trustServerCertificate: false }
};

let poolPromise = null;
function getSqlPool() {
  if (!poolPromise) {
    poolPromise = sql.connect(sqlConfig);
    poolPromise.catch(() => { poolPromise = null; }); // Reset on failure
  }
  return poolPromise;
}

async function handler(req, res) {
  console.log('Request headers:', JSON.stringify(req.headers));
  const userInfo = extractUserInfo(req);
  console.log(`adminCheck invoked. User ID: ${userInfo.userId || 'missing'}`);

  if (
    !userInfo.isAuthenticated ||
    !userInfo.userId ||
    typeof userInfo.userId !== 'string' ||
    userInfo.userId.length < 5
  ) {
    console.warn('Unauthorized: Missing or invalid user ID');
    return res
      .status(401)
      .json({ error: 'Unauthorized', details: 'Not authenticated or missing client principal' });
  }

  try {
    const pool = await getSqlPool();
    const request = pool.request();
    request.input('userId', sql.NVarChar, userInfo.userId);

    const query = 'SELECT Role FROM Users WHERE AzureID = @userId';
    console.log(`Executing query: ${query} with userId = ${userInfo.userId}`);

    const result = await request.query(query);
    console.log('Query result:', JSON.stringify(result.recordset));

    const userRole = result.recordset[0]?.Role;
    if (!userRole) {
      console.warn(`Forbidden: User ${userInfo.userId} not found in database`);
      return res
        .status(403)
        .json({ error: 'Forbidden', details: 'User not found in database' });
    }

    console.log(`User role found: ${userRole}`);
    if (userRole.trim().toLowerCase() === 'admin') {
      console.log(`Admin access granted for user ${userInfo.userId}`);
      return res.status(200).json({ message: 'Admin access granted' });
    }

    console.warn(`Forbidden: User ${userInfo.userId} is not an admin (role: ${userRole})`);
    return res
      .status(403)
      .json({ error: 'Forbidden', details: 'User is not an admin' });

  } catch (err) {
    console.error('Database error:', err);
    return res
      .status(500)
      .json({ error: 'Database error', details: err.message });
  }
}

module.exports = { handler };
