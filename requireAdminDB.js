// requireAdminDb.js
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
    poolPromise.catch(() => { poolPromise = null; });
  }
  return poolPromise;
}

async function requireAdminDb(req, res, next) {
  const userInfo = extractUserInfo(req);

  if (
    !userInfo.isAuthenticated ||
    !userInfo.userId ||
    typeof userInfo.userId !== 'string' ||
    userInfo.userId.length < 5
  ) {
    return res.status(401).sendFile(require('path').join(__dirname, 'public', '401.html'));
  }

  try {
    const pool = await getSqlPool();
    const request = pool.request();
    request.input('userId', sql.NVarChar, userInfo.userId);

    const result = await request.query('SELECT Role FROM Users WHERE AzureID = @userId');
    const userRole = result.recordset[0]?.Role;

    if (!userRole || userRole.trim().toLowerCase() !== 'admin') {
      return res.status(401).sendFile(require('path').join(__dirname, 'public', '401.html'));
    }

    req.userRole = userRole;
    next();
  } catch (err) {
    console.error('Database error in requireAdminDb:', err);
    return res.status(500).send('Internal Server Error');
  }
}

module.exports = requireAdminDb;
