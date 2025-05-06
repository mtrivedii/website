const sql = require('mssql');
const { extractUserInfo, requireRole } = require('./auth-utilities');

async function handler(req, res) {
  console.log('Request headers:', JSON.stringify(req.headers));
  const userInfo = extractUserInfo(req);
  console.log(`adminCheck invoked. User ID: ${userInfo.userId || 'missing'}`);

  if (!userInfo.isAuthenticated || !userInfo.userId || typeof userInfo.userId !== 'string' || userInfo.userId.length < 5) {
    console.warn('Unauthorized: Missing or invalid user ID');
    return res.status(401).json({ error: 'Unauthorized', details: 'Not authenticated or missing client principal' });
  }

  try {
    // Parse connection string or use explicit config
    const connectionString = process.env.SqlConnectionString;
    
    if (!connectionString) {
      console.error('SqlConnectionString environment variable is not defined');
      return res.status(500).json({ 
        error: 'Database configuration error', 
        details: 'Database connection string is not configured' 
      });
    }

    console.log('Attempting to connect to database with connection string');
    
    // Create SQL config with explicit credentials
    const config = {
      connectionString: connectionString,
      options: {
        enableArithAbort: true,
        encrypt: true,
        trustServerCertificate: false,
        connectTimeout: 30000
      }
    };

    // For debugging, log the config (without sensitive parts)
    console.log('SQL Config:', JSON.stringify({
      options: config.options,
      // Log if key parts exist or not
      connectionStringExists: !!config.connectionString,
    }));

    // Connect to database
    const pool = await sql.connect(config);
    
    const request = new sql.Request(pool);
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

    if (requireRole({ ...userInfo, allRoles: [userRole] }, 'admin')) {
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