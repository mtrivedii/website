// login.js - API endpoint for user login
const express = require('express');
const router = express.Router();
const sql = require('mssql');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Rate limiting middleware (simple implementation)
const loginAttempts = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  // Get existing attempts for this IP
  const attempts = loginAttempts.get(ip) || [];
  
  // Filter out attempts older than 15 minutes
  const recentAttempts = attempts.filter(time => now - time < 900000);
  
  // Check if too many attempts
  if (recentAttempts.length >= 5) {
    return res.status(429).json({ 
      error: 'Too many login attempts. Please try again later.' 
    });
  }
  
  // Add this attempt
  recentAttempts.push(now);
  loginAttempts.set(ip, recentAttempts);
  
  next();
}

// Login endpoint
router.post('/login', rateLimit, async (req, res) => {
  const { email, password } = req.body;
  
  // Basic validation
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  try {
    // Get database connection
    const pool = await sql.connect(process.env.SqlConnectionString);
    
    // Look up user by email
    const query = `
      SELECT id, email, password_hash, Role, status
      FROM dbo.users 
      WHERE email = @email
    `;
    
    const result = await pool.request()
      .input('email', sql.NVarChar, email)
      .query(query);
    
    // User not found
    if (result.recordset.length === 0) {
      // Log failed login attempt (for security audit)
      console.log(`Login failed: User not found - ${email}`);
      
      // Use a consistent response time to prevent timing attacks
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    const user = result.recordset[0];
    
    // Check if account is active
    if (user.status !== 'Active') {
      console.log(`Login attempt for inactive account: ${email}`);
      return res.status(401).json({ error: 'Account is inactive' });
    }
    
    // Compare password with hash
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    
    if (!passwordMatch) {
      // Log failed login attempt (for security audit)
      console.log(`Login failed: Invalid password - ${email}`);
      
      // Update login attempts tracking
      const userAttempts = trackUserLoginAttempts(email);
      
      return res.status(401).json({ error: 'Invalid email or password' });
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
    
    // Update last login timestamp in database
    await pool.request()
      .input('userId', sql.NVarChar, user.id)
      .query(`
        UPDATE dbo.users 
        SET lastLogin = GETDATE() 
        WHERE id = @userId
      `);
    
    // Log successful login (for security audit)
    console.log(`User logged in: ${email} (${user.id})`);
    
    // Set secure HTTP-only cookie with the token
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production', // Only HTTPS in production
      maxAge: 3600000, // 1 hour
      sameSite: 'strict'
    });
    
    // Return success with user information (excluding sensitive data)
    return res.status(200).json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        role: user.Role
      }
    });
    
  } catch (error) {
    console.error('Login error:', error);
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
    console.log(`SECURITY ALERT: Account ${email} has had 10+ failed login attempts in 24 hours`);
    // In a real implementation, you might set account status to 'Locked'
  }
  
  return recentAttempts.length;
}

module.exports = router;
