// mocks/mock-users.js
const express = require('express');
const mockSql = require('./mock-db');
const router = express.Router();

// GET /api/users - returns all users
router.get('/users', async (req, res) => {
  try {
    console.log('[MOCK API] /api/users GET route called');
    
    const pool = await mockSql.connect();
    
    // Simplified query for mock data
    const query = `
      SELECT 
        id, 
        email, 
        AzureID, 
        Role,
        status,
        twoFactorEnabled,
        lastLogin,
        passwordLastChanged
      FROM dbo.users
    `;
    
    console.log('[MOCK API] Executing users query');
    const result = await pool.request().query(query);
    
    console.log('[MOCK API] Returned', result.recordset.length, 'users');
    
    // Map results to expected format
    const sanitizedUsers = result.recordset.map(user => ({
      id: user.id,
      email: user.email,
      AzureID: user.AzureID,
      role: user.Role,
      status: user.status || 'Unknown',
      twoFactorEnabled: user.twoFactorEnabled || false,
      lastLogin: user.lastLogin || null,
      passwordLastChanged: user.passwordLastChanged || null
    }));
    
    res.status(200).json(sanitizedUsers);
  } catch (err) {
    console.error('[MOCK API] Error fetching users:', err);
    res.status(500).json({ 
      error: 'Database error', 
      details: err.message,
      stack: err.stack
    });
  }
});

module.exports = router;
