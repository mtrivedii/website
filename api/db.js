// test-db.js
const sql = require('mssql');

// Uses the same logic as your getConnection() function
const config = {
  server: process.env.DB_SERVER, // e.g. 'maanit-server.database.windows.net'
  database: process.env.DB_NAME, // e.g. 'maanit-sql-db'
  options: {
    encrypt: true,
    trustServerCertificate: false,
  },
  authentication: {
    type: 'azure-active-directory-default'
  }
};

async function testConnection() {
  try {
    console.log("🔄 Connecting to SQL Server...");
    const pool = await sql.connect(config);
    const result = await pool.request().query('SELECT GETDATE() AS now');
    console.log("✅ Connected. Current time:", result.recordset[0].now);
    await sql.close();
  } catch (err) {
    console.error("❌ Connection failed:", err.message);
  }
}

testConnection();
