// db.js
const sql = require('mssql');

const config = {
  server: process.env.DB_SERVER,       // e.g. maanit-server.database.windows.net
  database: process.env.DB_NAME,       // e.g. maanit-sql-db
  authentication: {
    type: 'azure-active-directory-default' // Uses Managed Identity
  },
  options: {
    encrypt: true,
    trustServerCertificate: false
  }
};

let pool;

async function getConnection() {
  if (!pool) {
    pool = await sql.connect(config);
  }
  return pool;
}

module.exports = { getConnection };
