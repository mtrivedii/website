const sql = require('mssql');

const config = {
  server: 'maanit-server.database.windows.net',
  database: 'maanit-db',
  port: 1433,
  authentication: {
    type: 'azure-active-directory-default' // for Entra ID-based login
  },
  options: {
    encrypt: true,
    trustServerCertificate: false
  }
};

let pool;

async function getConnection() {
  try {
    if (!pool) {
      pool = await sql.connect(config);
      console.log(`✅ Connected to DB: ${config.database}`);
    }
    return pool;
  } catch (err) {
    console.error('❌ Failed to connect to DB:', err);
    throw err;
  }
}

module.exports = { getConnection };
