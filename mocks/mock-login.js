// Updated mocks/mock-login.js
const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Debug user array
console.log('[MOCK LOGIN] Initializing mock users');

// In-memory user store that works with mock-register.js
let users = [
  {
    id: 'admin-user-id',
    email: 'admin@example.com',
    // Hash for "Password123!"
    password_hash: '$2b$10$XFE.yNnZhNu7XIeEPioTR.QaT1uqGiM2QQRWaeBvU3QjPGRVkxGsy',
    Role: 'admin',
    status: 'Active',
    twoFactorEnabled: true,
    twoFactorSecret: 'JBSWY3DPEHPK3PXP', // Example secret
    registrationComplete: true,
    lastLogin: new Date().toISOString()
  },
  {
    id: 'test-user-id',
    email: 'user@example.com',
    // Hash for "Password123!"
    password_hash: '$2b$10$XFE.yNnZhNu7XIeEPioTR.QaT1uqGiM2QQRWaeBvU3QjPGRVkxGsy',
    Role: 'user',
    status: 'Active',
    twoFactorEnabled: false,
    registrationComplete: true,
    lastLogin: null
  }
];

// Login endpoint
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  console.log('[MOCK API] Login attempt for:', email);
  console.log('[MOCK API] Current users:', users.map(u => u.email).join(', '));
  
  // Check global registered users first
  if (global.mockRegisteredUsers && global.mockRegisteredUsers.length > 0) {
    console.log('[MOCK API] Found registered users:', global.mockRegisteredUsers.length);
    users = [...users, ...global.mockRegisteredUsers];
    global.mockRegisteredUsers = [];
  }
  
  // Basic validation
  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }
  
  try {
    // Find user by email
    const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
    
    // User not found
    if (!user) {
      console.log('[MOCK API] Login failed: User not found -', email);
      
      // Simulate consistent response time to prevent timing attacks
      await new Promise(resolve => setTimeout(resolve, 500));
      
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Check if account registration is complete
    if (user.status === 'Pending2FA' || user.registrationComplete === false) {
      console.log('[MOCK API] Login attempt for incomplete registration:', email);
      return res.status(403).json({ 
        error: 'Account setup incomplete',
        message: 'You must complete 2FA setup to activate your account',
        userId: user.id,
        email: user.email,
        redirectTo: `/2fa.html?userId=${user.id}&email=${encodeURIComponent(user.email)}&setup=required`
      });
    }
    
    // Check if account is active
    if (user.status !== 'Active') {
      console.log('[MOCK API] Login attempt for inactive account:', email);
      return res.status(401).json({ error: 'Account is inactive' });
    }
    
    // Compare password with hash
    console.log('[MOCK API] Verifying password for:', email);
    
    // TEMPORARY: For testing, allow any password for admin@example.com
    let passwordMatch = false;
    if (email.toLowerCase() === 'admin@example.com') {
      console.log('[MOCK API] Admin user - skipping password check for testing');
      passwordMatch = true;
    } else {
      try {
        passwordMatch = await bcrypt.compare(password, user.password_hash);
        console.log('[MOCK API] Password match result:', passwordMatch);
      } catch (bcryptError) {
        console.error('[MOCK API] Bcrypt error:', bcryptError);
        // Fallback to simple equality check for testing
        passwordMatch = (password === 'Password123!');
      }
    }
    
    if (!passwordMatch) {
      console.log('[MOCK API] Login failed: Invalid password -', email);
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    
    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      console.log('[MOCK API] 2FA required for user:', email);
      
      // Return response requiring 2FA
      return res.status(200).json({
        message: '2FA verification required',
        requireTwoFactor: true,
        userId: user.id,
        email: user.email,
        redirectTo: `/2fa-verify.html?userId=${user.id}&email=${encodeURIComponent(user.email)}`
      });
    }
    
    // If 2FA not enabled, proceed with login
    // Generate JWT token
    const token = jwt.sign(
      { 
        userId: user.id,
        email: user.email,
        role: user.Role
      },
      'dev-secret-key',
      { expiresIn: '1h' }
    );
    
    // Update last login time
    user.lastLogin = new Date().toISOString();
    
    console.log('[MOCK API] User logged in successfully:', email);
    
    // Set cookie with the token
    res.cookie('auth_token', token, {
      httpOnly: true,
      secure: false, // For local development
      maxAge: 3600000, // 1 hour
      sameSite: 'lax'
    });
    
    // Return success with user information
    return res.status(200).json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        role: user.Role
      },
      token: token // Normally wouldn't send this in response, but helpful for development
    });
    
  } catch (error) {
    console.error('[MOCK API] Login error:', error);
    return res.status(500).json({ error: 'An error occurred during login' });
  }
});

module.exports = router;
