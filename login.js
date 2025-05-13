// login.js - API endpoint for user login
const express = require('express');
const router = express.Router();
const sql = require('mssql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { DefaultAzureCredential } = require('@azure/identity');

// Singleton SQL connection pool using Managed Identity
let sqlPool = null;
async function getSqlPool() {
  if (sqlPool) return sqlPool;

  // Acquire an access token for Azure SQL
  const credential = new DefaultAzureCredential();
  const tokenResponse = await credential.getToken('https://database.windows.net/.default');

  // Build the config object for mssql
  const config = {
    server: 'maanit-server.database.windows.net', // Your server name
    database: 'maanit-db',                        // Your DB name
    options: {
      encrypt: true,
      trustServerCertificate: false
    },
    authentication: {
      type: 'azure-active-directory-access-token',
      options: {
        token: tokenResponse.token
      }
    }
  };

  sqlPool = await sql.connect(config);
  return sqlPool;
}

// Modified rate limiting middleware with better logging
const loginAttempts = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  console.log(`[RATE LIMIT] Checking IP: ${ip}`);
  
  // Get existing attempts for this IP
  const attempts = loginAttempts.get(ip) || [];
  
  // Filter out attempts older than 15 minutes
  const recentAttempts = attempts.filter(time => now - time < 900000);
  
  console.log(`[RATE LIMIT] Recent attempts: ${recentAttempts.length}`);
  
  // Check if too many attempts - temporarily increase limit for testing
  if (recentAttempts.length >= 10) { // Increased from 5 to 10 for testing
    console.log(`[RATE LIMIT] Limit exceeded for IP: ${ip}`);
    return res.status(429).json({ 
      error: 'Too many login attempts. Please try again later.' 
    });
  }
  
  // Add this attempt
  recentAttempts.push(now);
  loginAttempts.set(ip, recentAttempts);
  
  next();
}

// Login endpoint - improved logging
router.post('/login', rateLimit, async (req, res) => {
  console.log('[LOGIN] Received login attempt for:', req.body.email);
  
  const { email, password } = req.body;
  
  // Basic validation
  if (!email || !password) {
    console.log('[LOGIN] Missing email or password');
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  try {
    // Get database connection
    const pool = await getSqlPool();
    
    // Look up user by email - Fixed column names
    const query = `
      SELECT id, email, password, Role, status, twoFactorEnabled
      FROM dbo.users 
      WHERE email = @email
    `;
    
    const result = await pool.request()
      .input('email', sql.NVarChar, email)
      .query(query);
    
    // User not found
    if (result.recordset.length === 0) {
      // Log failed login attempt (for security audit)
      console.log(`[LOGIN] Failed: User not found - ${email}`);
      
      // Use a consistent response time to prevent timing attacks
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const user = result.recordset[0];
    console.log(`[LOGIN] User found: ${user.email}, role: ${user.Role}, status: ${user.status}`);
    
    // Check if account is active
    if (user.status !== 'Active') {
      console.log(`[LOGIN] Login attempt for inactive account: ${email}`);
      return res.status(401).json({ error: 'Account is inactive' });
    }
    
    // Compare password with hash - Fixed column name
    const passwordMatch = await bcrypt.compare(password, user.password);
    
    if (!passwordMatch) {
      // Log failed login attempt (for security audit)
      console.log(`[LOGIN] Failed: Invalid password - ${email}`);
      
      // Update login attempts tracking
      const userAttempts = trackUserLoginAttempts(email);
      
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Check if 2FA is required
    if (user.twoFactorEnabled) {
      console.log(`[LOGIN] 2FA required for user: ${email}`);
      return res.status(200).json({
        requireTwoFactor: true,
        userId: user.id,
        email: user.email,
        redirectTo: '/2fa-verify.html'
      });
    }
    
    // Generate session token
    const token = jwt.sign(
      { 
        userId: user.id,
        email: user.email,
        role: user.Role
      },
      process.env.JWT_SECRET || 'dev-secret-key',
      { expiresIn: '1h' }
    );
    
    // Log successful login (for security audit)
    console.log(`[LOGIN] User successfully logged in: ${email} (${user.id})`);
    console.log(`[LOGIN] Setting auth cookie with role: ${user.Role}`);

    // Debug cookie headers before setting
    console.log(`[COOKIE DEBUG] Request protocol: ${req.protocol}`);
    console.log(`[COOKIE DEBUG] X-Forwarded-Proto: ${req.headers['x-forwarded-proto']}`);
    console.log(`[COOKIE DEBUG] Request secure: ${req.secure}`);
    console.log(`[COOKIE DEBUG] Host: ${req.headers.host}`);

    // Set secure HTTP-only cookie with the token - modified for debugging
    res.cookie('auth_token', token, {
      httpOnly: false,      // SET TO FALSE FOR DEBUGGING
      secure: false,        // SET TO FALSE FOR DEBUGGING
      maxAge: 3600000,      // 1 hour
      sameSite: 'lax',      // Changed from 'strict' to 'lax'
      path: '/'             // Explicitly set the path
    });

    // Add a debugging cookie that will be visible in JavaScript
    res.cookie('auth_debug', Date.now(), {
      httpOnly: false,
      secure: false,
      maxAge: 3600000,
      path: '/'
    });

    console.log(`[COOKIE DEBUG] Cookies set`);
    
    // Update last login timestamp in database - Fixed column name
    try {
      await pool.request()
        .input('userId', sql.Int, user.id)  // Make sure this matches the expected type
        .query(`
          UPDATE dbo.users 
          SET last_login = GETDATE() 
          WHERE id = @userId
        `);
      console.log(`[LOGIN] Last login timestamp updated for user ${user.id}`);
    } catch (updateError) {
      console.error(`[LOGIN] Error updating last login timestamp: ${updateError.message}`);
      // Continue anyway, this is not critical
    }
    
    // Return success with user information (excluding sensitive data)
    return res.status(200).json({
      message: 'Login successful',
      token: token,  // Include the token in the response
      user: {
        id: user.id,
        email: user.email,
        role: user.Role
      }
    });
    
  } catch (error) {
    console.error('[LOGIN] Error:', error);
    return res.status(500).json({ error: 'An error occurred during login' });
  }
});

// Helper to track login attempts by user
const userLoginAttempts = new Map();
function trackUserLoginAttempts(email) {
  const now = Date.now();
  const attempts = userLoginAttempts.get(email) || [];
  
  // Keep only attempts from the last 24 hours
  const recentAttempts = attempts.filter(time => now - time < 86400000);
  recentAttempts.push(now);
  
  userLoginAttempts.set(email, recentAttempts);
  
  // If too many failed attempts, could implement account locking here
  if (recentAttempts.length >= 10) {
    console.log(`[SECURITY ALERT] Account ${email} has had 10+ failed login attempts in 24 hours`);
    // In a real implementation, you might set account status to 'Locked'
  }
  
  return recentAttempts.length;
}

module.exports = router;