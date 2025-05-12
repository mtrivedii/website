// users.js - Express Router for /api/users with Azure SQL Managed Identity

const express = require('express');
const sql = require('mssql');
const router = express.Router();

// Singleton SQL connection pool
let sqlPool = null;
async function getSqlPool() {
  if (!sqlPool) {
    try {
      console.log('Creating new SQL connection pool using Managed Identity authentication');
      
      // Use the existing connection string (which already has AAD Default authentication)
      const connectionString = process.env.SqlConnectionString;
      
      if (!connectionString) {
        throw new Error('SqlConnectionString environment variable is not defined');
      }
      
      sqlPool = await sql.connect(connectionString);
      
      console.log('SQL connection pool created successfully');
      
      sqlPool.on('error', err => {
        console.error('SQL connection pool error:', err);
        sqlPool = null;
      });
    } catch (err) {
      console.error('Error creating SQL connection pool:', err);
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
    
    // Start with a simplified query matching your schema
    const query = `
      SELECT 
        id, 
        email, 
        AzureID, 
        Role
      FROM dbo.users
    `;
    
    console.log('Executing users query:', query);
    const result = await pool.request().query(query);
    
    console.log('Query successful, returned', result.recordset.length, 'rows');
    
    // Map results to expected format
    const sanitizedUsers = result.recordset.map(user => ({
      id: user.id,
      email: user.email,
      AzureID: user.AzureID,
      role: user.Role
    }));
    
    res.status(200).json(sanitizedUsers);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ 
      error: 'Database error', 
      details: err.message,
      stack: process.env.NODE_ENV === 'development' ? err.stack : undefined
    });
  }
});

module.exports = router;