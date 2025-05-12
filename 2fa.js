// 2fa.js - API endpoint for two-factor authentication
const express = require('express');
const router = express.Router();
const sql = require('mssql');
const crypto = require('crypto');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Singleton SQL connection pool
let sqlPool = null;
async function getSqlPool() {
  if (!sqlPool) {
    sqlPool = await sql.connect(process.env.SQLAZURECONNSTR_SqlConnectionString);
  }
  return sqlPool;
}

// Setup 2FA - Step 1: Generate secret and QR code
router.post('/setup', async (req, res) => {
  const { userId, email } = req.body;
  
  if (!userId || !email) {
    return res.status(400).json({ error: 'User ID and email are required' });
  }
  
  try {
    // Get database connection
    const pool = await getSqlPool();
    
    // Check if user exists
    const userResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query('SELECT id, email, twoFactorEnabled FROM dbo.users WHERE id = @userId');
    
    if (userResult.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    const user = userResult.recordset[0];
    
    // Check if 2FA is already enabled
    if (user.twoFactorEnabled) {
      return res.status(400).json({ error: '2FA is already enabled for this user' });
    }
    
    // Generate a new secret
    const secret = speakeasy.generateSecret({
      length: 20,
      name: `SecureApp:${email}`
    });
    
    // Store the temporary secret in the database
    await pool.request()
      .input('userId', sql.Int, userId)
      .input('secret', sql.NVarChar, secret.base32)
      .query(`
        UPDATE dbo.users
        SET twoFactorTempSecret = @secret
        WHERE id = @userId
      `);
    
    // Generate QR code
    const otpauth_url = secret.otpauth_url;
    const qrCodeImage = await QRCode.toDataURL(otpauth_url);
    
    // Log this action (for security audit)
    console.log(`2FA setup initiated for user: ${email} (${userId})`);
    
    // Return the secret and QR code
    return res.status(200).json({
      secret: secret.base32,
      qrCodeUrl: qrCodeImage,
      message: 'Scan this QR code with your authenticator app'
    });
    
  } catch (error) {
    console.error('2FA setup error:', error);
    return res.status(500).json({ error: 'Failed to set up 2FA' });
  }
});

// Setup 2FA - Step 2: Verify and activate
router.post('/verify', async (req, res) => {
  const { userId, token } = req.body;
  
  if (!userId || !token) {
    return res.status(400).json({ error: 'User ID and token are required' });
  }
  
  try {
    // Get database connection
    const pool = await getSqlPool();
    
    // Get user's temporary secret
    const secretResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, email, twoFactorTempSecret 
        FROM dbo.users 
        WHERE id = @userId
      `);
    
    if (secretResult.recordset.length === 0 || !secretResult.recordset[0].twoFactorTempSecret) {
      return res.status(404).json({ error: 'No 2FA setup found for this user' });
    }
    
    const user = secretResult.recordset[0];
    
    // Verify the token
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorTempSecret,
      encoding: 'base32',
      token: token,
      window: 1 // Allow a small time drift
    });
    
    if (!verified) {
      return res.status(401).json({ error: 'Invalid verification code' });
    }
    
    // Generate recovery codes
    const recoveryCodes = Array(3).fill(0).map(() => {
      const code = crypto.randomBytes(12).toString('hex');
      // Format as XXXX-XXXX-XXXX
      return `${code.slice(0,4)}-${code.slice(4,8)}-${code.slice(8,12)}`.toUpperCase();
    });
    
    // Hash the recovery codes
    const hashedCodes = recoveryCodes.map(code => 
      crypto.createHash('sha256').update(code).digest('hex')
    );
    
    // Update user record to enable 2FA
    await pool.request()
      .input('userId', sql.Int, userId)
      .input('secret', sql.NVarChar, user.twoFactorTempSecret)
      .input('recoveryCodes', sql.NVarChar, JSON.stringify(hashedCodes))
      .query(`
        UPDATE dbo.users
        SET 
          twoFactorEnabled = 1,
          twoFactorSecret = @secret,
          twoFactorTempSecret = NULL,
          twoFactorRecoveryCodes = @recoveryCodes
        WHERE id = @userId
      `);
    
    // Log successful activation (for security audit)
    console.log(`2FA activated for user: ${user.email} (${userId})`);
    
    // Return the recovery codes to the user (only time they'll see them unencrypted)
    return res.status(200).json({
      message: '2FA successfully activated',
      twoFactorEnabled: true,
      recoveryCodes: recoveryCodes
    });
    
  } catch (error) {
    console.error('2FA verification error:', error);
    return res.status(500).json({ error: 'Failed to verify 2FA token' });
  }
});

// Login with 2FA
router.post('/validate', async (req, res) => {
  const { userId, token } = req.body;
  
  if (!userId || !token) {
    return res.status(400).json({ error: 'User ID and token are required' });
  }
  
  try {
    // Get database connection
    const pool = await getSqlPool();
    
    // Get user's 2FA secret
    const secretResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, email, twoFactorSecret, twoFactorRecoveryCodes
        FROM dbo.users 
        WHERE id = @userId AND twoFactorEnabled = 1
      `);
    
    if (secretResult.recordset.length === 0 || !secretResult.recordset[0].twoFactorSecret) {
      return res.status(404).json({ error: 'No active 2FA found for this user' });
    }
    
    const user = secretResult.recordset[0];
    
    // First check if the token is a recovery code
    let isRecoveryCode = false;
    let recoveryCodeIndex = -1;
    
    try {
      const recoveryCodes = JSON.parse(user.twoFactorRecoveryCodes || '[]');
      const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
      
      recoveryCodeIndex = recoveryCodes.indexOf(hashedToken);
      if (recoveryCodeIndex !== -1) {
        isRecoveryCode = true;
      }
    } catch (e) {
      console.error('Error parsing recovery codes:', e);
    }
    
    let validated = false;
    
    if (isRecoveryCode) {
      // Use and invalidate recovery code
      const recoveryCodes = JSON.parse(user.twoFactorRecoveryCodes);
      recoveryCodes.splice(recoveryCodeIndex, 1);
      
      await pool.request()
        .input('userId', sql.Int, userId)
        .input('recoveryCodes', sql.NVarChar, JSON.stringify(recoveryCodes))
        .query(`
          UPDATE dbo.users
          SET twoFactorRecoveryCodes = @recoveryCodes
          WHERE id = @userId
        `);
      
      validated = true;
      console.log(`2FA recovery code used for user: ${user.email} (${userId})`);
    } else {
      // Verify the TOTP token
      validated = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token,
        window: 1 // Allow a small time drift
      });
    }
    
    if (!validated) {
      return res.status(401).json({ error: 'Invalid verification code' });
    }
    
    // Log successful 2FA validation (for security audit)
    console.log(`2FA validation successful for user: ${user.email} (${userId})`);
    
    return res.status(200).json({
      message: '2FA authentication successful',
      userId: userId,
      email: user.email
    });
    
  } catch (error) {
    console.error('2FA validation error:', error);
    return res.status(500).json({ error: 'Failed to validate 2FA token' });
  }
});

// Disable 2FA
router.post('/disable', async (req, res) => {
  const { userId, token } = req.body;
  
  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }
  
  try {
    // Get database connection
    const pool = await getSqlPool();
    
    // Get user's 2FA secret
    const secretResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, email, twoFactorSecret
        FROM dbo.users 
        WHERE id = @userId AND twoFactorEnabled = 1
      `);
    
    if (secretResult.recordset.length === 0) {
      return res.status(404).json({ error: 'No active 2FA found for this user' });
    }
    
    const user = secretResult.recordset[0];
    
    // If token is provided, verify it
    if (token) {
      const verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret,
        encoding: 'base32',
        token: token,
        window: 1
      });
      
      if (!verified) {
        return res.status(401).json({ error: 'Invalid verification code' });
      }
    }
    
    // Disable 2FA
    await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        UPDATE dbo.users
        SET 
          twoFactorEnabled = 0,
          twoFactorSecret = NULL,
          twoFactorTempSecret = NULL,
          twoFactorRecoveryCodes = NULL
        WHERE id = @userId
      `);
    
    // Log this action (for security audit)
    console.log(`2FA disabled for user: ${user.email} (${userId})`);
    
    return res.status(200).json({
      message: '2FA successfully disabled',
      twoFactorEnabled: false
    });
    
  } catch (error) {
    console.error('2FA disable error:', error);
    return res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

// Check 2FA status
router.get('/status/:userId', async (req, res) => {
  const userId = req.params.userId;
  
  if (!userId) {
    return res.status(400).json({ error: 'User ID is required' });
  }
  
  try {
    // Get database connection
    const pool = await getSqlPool();
    
    // Check if 2FA is enabled
    const result = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT twoFactorEnabled
        FROM dbo.users 
        WHERE id = @userId
      `);
    
    if (result.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }
    
    return res.status(200).json({
      twoFactorEnabled: !!result.recordset[0].twoFactorEnabled
    });
    
  } catch (error) {
    console.error('2FA status check error:', error);
    return res.status(500).json({ error: 'Failed to check 2FA status' });
  }
});

module.exports = router;