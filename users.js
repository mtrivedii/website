// users.js - Express Router for /api/users with Azure SQL Managed Identity

const express = require('express');
const sql = require('mssql');

const router = express.Router();

// Azure SQL Managed Identity configuration
const config = {
  server: process.env.DB_SERVER,      // e.g. 'maanit-server.database.windows.net'
  port: 1433,
  database: process.env.DB_DATABASE,  // e.g. 'maanit-db'
  authentication: {
    type: 'azure-active-directory-msi-app-service'
  },
  options: {
    encrypt: true
  }
};

// Singleton SQL connection pool
let sqlPool = null;
async function getSqlPool() {
  if (!sqlPool) {
    try {
      sqlPool = await sql.connect(config);
      sqlPool.on('error', err => {
        console.error('SQL connection pool error:', err);
        sqlPool = null;
      });
    } catch (err) {
      sqlPool = null;
      throw err;
    }
  }
  return sqlPool;
}

// GET /api/users - returns all users
router.get('/users', async (req, res) => {
  try {
    const pool = await getSqlPool();
    const result = await pool.request().query('SELECT * FROM dbo.users');
    res.json(result.recordset);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Database error', details: err.message });
  }
});

module.exports = router;
