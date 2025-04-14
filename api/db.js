const sql = require('mssql');
const { DefaultAzureCredential } = require('@azure/identity');

// Secure DB config using environment variables
const dbConfig = {
  server: process.env.DB_SERVER,       // e.g. maanitsql.database.windows.net
  database: process.env.DB_NAME,       // e.g. maanit-sqldb
  options: {
    encrypt: true,
    enableArithAbort: true,
    trustServerCertificate: false
  },
  authentication: {
    type: 'azure-active-directory-access-token'
  }
};

async function getConnection() {
  try {
    const credential = new DefaultAzureCredential();
    const accessToken = await credential.getToken("https://database.windows.net/");

    // ✅ Use correct token key for mssql: accessToken
    dbConfig.authentication.options = {
      token: accessToken.token
    };

    const pool = await sql.connect(dbConfig);
    return pool;
  } catch (err) {
    console.error('❌ Failed to connect to database:', err.message);
    throw err;
  }
}

module.exports = { getConnection };
