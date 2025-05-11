// index.js - Main Express application with fixed MFA redirection
const express = require('express');
const path = require('path');

// Import handlers
const checkAdminHandler = require('./checkAdmin');
const getSasTokenHandler = require('./getSasToken');
const usersRouter = require('./users'); // Express router
const mfaRouter = require('./mfa'); // MFA router
const { isMfaEnabled } = require('./mfaUtils'); // MFA utility functions

const app = express();

// Disable X-Powered-By header
app.disable('x-powered-by');

// Parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS middleware to fix issues in development
app.use((req, res, next) => {
  // Allow requests from any origin during development
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  
  // Handle preflight requests
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  next();
});

// Security headers middleware
app.use((req, res, next) => {
  // Set security headers
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://api.qrserver.com; connect-src 'self' https://*.microsoftonline.com https://login.microsoft.com https://maanit-func.azurewebsites.net");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  next();
});

// Debugging middleware - log all requests
app.use((req, res, next) => {
  console.log(`[DEBUG] ${req.method} ${req.url} from ${req.ip}`);
  console.log('[DEBUG] Headers:', req.headers);
  next();
});

// Middleware to require authentication using Easy Auth headers
function requireAuth(req, res, next) {
  const principal = req.headers['x-ms-client-principal'];
  if (!principal) {
    return res.redirect('/.auth/login/aad?post_login_redirect_uri=' + encodeURIComponent(req.originalUrl));
  }
  next();
}

// Register API routes with authentication
app.get('/api/checkAdmin', requireAuth, checkAdminHandler.handler);
app.post('/api/checkAdmin', requireAuth, checkAdminHandler.handler);

app.get('/api/getSasToken', requireAuth, getSasTokenHandler.handler);
app.options('/api/getSasToken', requireAuth, getSasTokenHandler.handler);

// Mount the MFA router for MFA-related routes
app.use('/api/mfa', mfaRouter);

// Mount the users router - TEMPORARILY REMOVED requireAuth for testing
app.use('/api', usersRouter);

// Serve static files from 'public' directory
app.use(express.static(path.join(__dirname, 'public'), {
  // Set headers for static files
  setHeaders: (res, path) => {
    // Don't apply CSP to CSS and JS files to avoid breaking functionality
    if (!path.endsWith('.css') && !path.endsWith('.js')) {
      res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https://api.qrserver.com; connect-src 'self' https://*.microsoftonline.com https://login.microsoft.com https://maanit-func.azurewebsites.net");
    }
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
  }
}));

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).send('Internal Server Error');
});

// Optional: SPA fallback to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Initialize app locals for temporary MFA data
app.locals.tempSecrets = {};

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});