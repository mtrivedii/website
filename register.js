// register.js - API endpoint for user registration
const express = require('express');
const router = express.Router();
const sql = require('mssql');
const bcrypt = require('bcrypt');
const validator = require('validator');
const { v4: uuidv4 } = require('uuid');

// Validation middleware
function validateRegistration(req, res, next) {
  const { email, password } = req.body;
  
  // Check if email and password are provided
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  // Validate email format
  if (!validator.isEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  
  // Validate password strength
  if (password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }
  
  if (!/[A-Z]/.test(password)) {
    return res.status(400).json({ error: 'Password must contain at least one uppercase letter' });
  }
  
  if (!/[a-z]/.test(password)) {
    return res.status(400).json({ error: 'Password must contain at least one lowercase letter' });
  }
  
  if (!/[0-9]/.test(password)) {
    return res.status(400).json({ error: 'Password must contain at least one number' });
  }
  
  if (!/[^A-Za-z0-9]/.test(password)) {
    return res.status(400).json({ error: 'Password must contain at least one special character' });
  }
  
  next();
}

// Rate limiting middleware (simple implementation)
const registrationAttempts = new Map();
function rateLimit(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  const now = Date.now();
  
  // Get existing attempts for this IP
  const attempts = registrationAttempts.get(ip) || [];
  
  // Filter out attempts older than 1 hour
  const recentAttempts = attempts.filter(time => now - time < 3600000);
  
  // Check if too many attempts
  if (recentAttempts.length >= 5) {
    return res.status(429).json({ 
      error: 'Too many registration attempts. Please try again later.' 
    });
  }
  
  // Add this attempt
  recentAttempts.push(now);
  registrationAttempts.set(ip, recentAttempts);
  
  next();
}

// Registration endpoint
router.post('/', rateLimit, validateRegistration, async (req, res) => {
  const { email, password } = req.body;
  const saltRounds = 10;
  
  try {
    // Get database connection
    const pool = await sql.connect(process.env.SqlConnectionString);
    
    // Check if email already exists
    const checkQuery = `SELECT 1 FROM dbo.users WHERE email = @email`;
    const checkResult = await pool.request()
      .input('email', sql.NVarChar, email)
      .query(checkQuery);
    
    if (checkResult.recordset.length > 0) {
      return res.status(409).json({ error: 'Email already registered' });
    }
    
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    
    // Generate a unique ID for the user
    const userId = uuidv4();
    
    // Insert user into database
  const insertQuery = `
  INSERT INTO dbo.users (
    id, 
    email, 
    password, 
    Role, 
    status, 
    registration_complete
  )
  VALUES (
    @id, 
    @email, 
    @passwordHash, 
    'user', 
    'Active', 
    1
  )
`;

await pool.request()
  .input('id', sql.NVarChar, userId)
  .input('email', sql.NVarChar, email)
  .input('passwordHash', sql.NVarChar, hashedPassword)
  .query(insertQuery);
    // Log successful registration (for security audit)
    console.log(`User registered: ${email} (${userId})`);
    
    // Return success
    return res.status(201).json({ 
      message: 'Registration successful',
      email: email
    });
    
  } catch (error) {
    console.error('Registration error:', error);
    return res.status(500).json({ 
      error: 'An error occurred during registration' 
    });
  }
});

module.exports = router;
