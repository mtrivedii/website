// Updated mocks/mock-register.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const validator = require('validator');
const { v4: uuidv4 } = require('uuid');

// Initialize global array if needed
console.log('[MOCK API] Initializing registration system');
global.mockRegisteredUsers = global.mockRegisteredUsers || [];
console.log('[MOCK API] Current registered users:', global.mockRegisteredUsers.length);

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

// Registration endpoint
router.post('/register', validateRegistration, async (req, res) => {
  const { email, password } = req.body;
  const saltRounds = 10;
  
  try {
    console.log('[MOCK API] Registration attempt for:', email);
    
    // Check existing hardcoded users from mock-login
    const existingUserEmails = ['admin@example.com', 'user@example.com'];
    
    // Check if email already exists in the global registered users
    const existingUser = global.mockRegisteredUsers.find(
      user => user.email.toLowerCase() === email.toLowerCase()
    );
    
    const emailExists = existingUserEmails.includes(email.toLowerCase()) || existingUser;
    
    if (emailExists) {
      console.log('[MOCK API] Email already registered:', email);
      return res.status(409).json({ error: 'Email already registered' });
    }
    
    // Hash the password
    console.log('[MOCK API] Hashing password...');
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    console.log('[MOCK API] Password hashed successfully');
    
    // Generate a unique ID for the user
    const userId = uuidv4();
    
    // Create user object
    const newUser = {
      id: userId,
      email: email,
      password_hash: hashedPassword,
      Role: 'user',
      status: 'Pending2FA', // Mark as pending until 2FA setup is complete
      created_at: new Date().toISOString(),
      lastLogin: null,
      twoFactorEnabled: false,
      registrationComplete: false
    };
    
    // Add to registered users
    console.log('[MOCK API] Adding user to global array:', newUser.email);
    global.mockRegisteredUsers.push(newUser);
    
    console.log('[MOCK API] User registered successfully:', email);
    console.log('[MOCK API] Total registered users:', global.mockRegisteredUsers.length);
    console.log('[MOCK API] Global array contains:', global.mockRegisteredUsers.map(u => u.email).join(', '));
    
    // Return with 2FA setup required
    return res.status(201).json({ 
      message: 'Account created, 2FA setup required',
      userId: userId,
      email: email,
      redirectTo: `/2fa.html?userId=${userId}&email=${encodeURIComponent(email)}&setup=required`
    });
    
  } catch (error) {
    console.error('[MOCK API] Registration error:', error);
    return res.status(500).json({ 
      error: 'An error occurred during registration' 
    });
  }
});

module.exports = router;
