// Updated mocks/mock-2fa.js
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const QRCode = require('qrcode');
const speakeasy = require('speakeasy');

// Store user 2FA secrets (in a real app, this would be in the database)
const userSecrets = new Map();

// Setup 2FA - Step 1: Generate secret and QR code
router.post('/2fa/setup', async (req, res) => {
  try {
    const { userId, email } = req.body;
    
    if (!userId || !email) {
      return res.status(400).json({ error: 'User ID and email are required' });
    }
    
    console.log('[MOCK 2FA] Setting up 2FA for user:', email);
    
    // Generate a new secret
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `SecureApp:${email}`
    });
    
    // Store the secret temporarily
    userSecrets.set(userId, {
      temp_secret: secret.base32,
      email: email,
      verified: false
    });
    
    // Generate QR code
    const otpauth_url = secret.otpauth_url;
    const qrCodeImage = await QRCode.toDataURL(otpauth_url);
    
    console.log('[MOCK 2FA] Secret generated for user:', userId);
    
    // Return the secret and QR code
    return res.status(200).json({
      secret: secret.base32,
      qrCodeUrl: qrCodeImage,
      message: 'Scan this QR code with your authenticator app'
    });
    
  } catch (error) {
    console.error('[MOCK 2FA] Setup error:', error);
    return res.status(500).json({ error: 'Failed to set up 2FA' });
  }
});

// Setup 2FA - Step 2: Verify and activate
router.post('/2fa/verify', (req, res) => {
  try {
    const { userId, token } = req.body;
    
    if (!userId || !token) {
      return res.status(400).json({ error: 'User ID and token are required' });
    }
    
    // Get the user's secret
    const userData = userSecrets.get(userId);
    if (!userData || !userData.temp_secret) {
      return res.status(404).json({ error: 'No 2FA setup found for this user' });
    }
    
    console.log('[MOCK 2FA] Verifying token for user:', userData.email);
    
    // Verify the token
    const verified = speakeasy.totp.verify({
      secret: userData.temp_secret,
      encoding: 'base32',
      token: token,
      window: 2 // Allow a small time window for verification
    });
    
    if (!verified) {
      console.log('[MOCK 2FA] Token verification failed');
      return res.status(401).json({ error: 'Invalid verification code' });
    }
    
    // Activate 2FA
    userSecrets.set(userId, {
      ...userData,
      secret: userData.temp_secret,
      temp_secret: null,
      verified: true
    });
    
    console.log('[MOCK 2FA] 2FA activated for user:', userData.email);
    
    // Update user in registered users
    if (global.mockRegisteredUsers) {
      const userIndex = global.mockRegisteredUsers.findIndex(u => u.id === userId);
      if (userIndex !== -1) {
        global.mockRegisteredUsers[userIndex].twoFactorEnabled = true;
        global.mockRegisteredUsers[userIndex].twoFactorSecret = userData.temp_secret;
        global.mockRegisteredUsers[userIndex].status = 'Active';
        global.mockRegisteredUsers[userIndex].registrationComplete = true;
        
        console.log('[MOCK 2FA] Updated user registration status to complete');
      }
    }
    
    // Generate recovery codes
    const recoveryCodes = Array(3).fill(0).map(() => {
      const code = crypto.randomBytes(12).toString('hex');
      // Format as XXXX-XXXX-XXXX
      return `${code.slice(0,4)}-${code.slice(4,8)}-${code.slice(8,12)}`.toUpperCase();
    });
    
    return res.status(200).json({
      message: '2FA successfully activated',
      twoFactorEnabled: true,
      registrationComplete: true,
      recoveryCodes: recoveryCodes
    });
    
  } catch (error) {
    console.error('[MOCK 2FA] Verification error:', error);
    return res.status(500).json({ error: 'Failed to verify 2FA token' });
  }
});

// Login with 2FA
router.post('/2fa/validate', (req, res) => {
  try {
    const { userId, token } = req.body;
    
    if (!userId || !token) {
      return res.status(400).json({ error: 'User ID and token are required' });
    }
    
    // Get the user's secret
    const userData = userSecrets.get(userId);
    if (!userData || !userData.secret || !userData.verified) {
      return res.status(404).json({ error: 'No active 2FA setup found for this user' });
    }
    
    console.log('[MOCK 2FA] Validating login token for user:', userData.email);
    
    // Verify the token
    const verified = speakeasy.totp.verify({
      secret: userData.secret,
      encoding: 'base32',
      token: token,
      window: 2 // Allow a small time drift
    });
    
    if (!verified) {
      console.log('[MOCK 2FA] Login token validation failed');
      return res.status(401).json({ error: 'Invalid verification code' });
    }
    
    console.log('[MOCK 2FA] Login token validated for user:', userData.email);
    
    return res.status(200).json({
      message: '2FA authentication successful',
      userId: userId,
      email: userData.email
    });
    
  } catch (error) {
    console.error('[MOCK 2FA] Validation error:', error);
    return res.status(500).json({ error: 'Failed to validate 2FA token' });
  }
});

module.exports = router;