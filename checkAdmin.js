const sql = require('mssql');
const { extractUserInfo } = require('./auth-utilities');

async function handler(req, res) {
  console.log('Request headers:', JSON.stringify(req.headers));
  const userInfo = extractUserInfo(req);
  console.log(`adminCheck invoked. User ID: ${userInfo.userId || 'missing'}`);

  if (!userInfo.isAuthenticated || !userInfo.userId || typeof userInfo.userId !== 'string' || userInfo.userId.length < 5) {
    console.warn('Unauthorized: Missing or invalid user ID');
    return res.status(401).json({ error: 'Unauthorized', details: 'Not authenticated or missing client principal' });
  }

  try {
    // Configuration for Azure SQL with Entra ID authentication
    const sqlConfig = {
      server: process.env.DB_SERVER || 'yourserver.database.windows.net', // Replace with your server
      database: process.env.DB_NAME || 'yourdatabase', // Replace with your database
      authentication: {
        type: 'azure-active-directory-msi-app-service',
      },
      options: {
        encrypt: true,
        trustServerCertificate: false
      }
    };

    console.log('Connecting to SQL Server with Entra ID (MSI) authentication');

    // Connect to database
    await sql.connect(sqlConfig);

    const request = new sql.Request();
    request.input('userId', sql.NVarChar, userInfo.userId);

    const query = 'SELECT Role FROM Users WHERE AzureID = @userId';
    console.log(`Executing query: ${query} with userId = ${userInfo.userId}`);

    const result = await request.query(query);
    console.log('Query result:', JSON.stringify(result.recordset));

    const userRole = result.recordset[0]?.Role;

    if (!userRole) {
      console.warn(`Forbidden: User ${userInfo.userId} not found in database`);
      return res.status(403).json({ error: 'Forbidden', details: 'User not found in database' });
    }

    console.log(`User role found: ${userRole}`);

    // Direct admin check from DB
    if (userRole && userRole.trim().toLowerCase() === 'admin') {
      console.log(`Admin access granted for user ${userInfo.userId}`);
      return res.status(200).json({ message: 'Admin access granted' });
    }

    console.warn(`Forbidden: User ${userInfo.userId} is not an admin (role: ${userRole})`);
    return res.status(403).json({ error: 'Forbidden', details: 'User is not an admin' });

  } catch (err) {
    console.error('Database error:', err);
    return res.status(500).json({ error: 'Database error', details: err.message });
  } finally {
    try {
      await sql.close();
    } catch (closeErr) {
      console.error('Error closing SQL connection:', closeErr);
    }
  }
}

module.exports = { handler };
