// index.js

const express = require('express');
const path = require('path');

// Import handlers & routers
const checkAdminHandler = require('./checkAdmin');
const getSasTokenHandler = require('./getSasToken');
const usersRouter = require('./users');
const mfaRouter = require('./mfa');
const { isMfaEnabled } = require('./mfaUtils');
const requireAdminDb = require('./requireAdminDb'); // <-- DB-backed admin middleware

const app = express();

// Disable the X-Powered-By header
app.disable('x-powered-by');

// Body parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS (development)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.setHeader(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization'
  );
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

// Security headers
app.use((req, res, next) => {
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; " +
      "script-src 'self' 'unsafe-inline'; " +
      "style-src 'self' 'unsafe-inline'; " +
      "img-src 'self' data: https://api.qrserver.com; " +
      "connect-src 'self' https://*.blob.core.windows.net " +
      "https://*.microsoftonline.com https://login.microsoft.com " +
      "https://maanit-func.azurewebsites.net"
  );
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  next();
});

// Debug logger
app.use((req, res, next) => {
  console.log(`[DEBUG] ${req.method} ${req.url} — IP: ${req.ip}`);
  console.log('[DEBUG] Headers:', req.headers);
  next();
});

// Easy Auth guard
function requireAuth(req, res, next) {
  const principal = req.headers['x-ms-client-principal'];
  if (!principal) {
    // Redirect to AAD login and come back
    return res.redirect(
      '/.auth/login/aad?post_login_redirect_uri=' +
        encodeURIComponent(req.originalUrl)
    );
  }
  next();
}

// === API Routes ===
app.get('/api/checkAdmin', requireAuth, checkAdminHandler.handler);
app.post('/api/checkAdmin', requireAuth, checkAdminHandler.handler);

app.get('/api/getSasToken', getSasTokenHandler.handler);
app.options('/api/getSasToken', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
  res.status(200).end();
});

app.use('/api/mfa', mfaRouter);
app.use('/api', usersRouter);

// === Protected Admin Pages ===
app.get('/admin.html', requireAdminDb, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
app.get('/users.html', requireAdminDb, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'users.html'));
});

// === Static File Serving ===
app.use((req, res, next) => {
  // Let requireAdminDb handle these
  if (
    (req.path === '/admin.html' || req.path === '/users.html') &&
    req.method === 'GET'
  ) {
    return next();
  }
  express.static(path.join(__dirname, 'public'), {
    setHeaders: (res, filePath) => {
      // Apply CSP to non-static assets
      if (!filePath.match(/\.(css|js)$/)) {
        res.setHeader(
          'Content-Security-Policy',
          "default-src 'self'; " +
            "script-src 'self' 'unsafe-inline'; " +
            "style-src 'self' 'unsafe-inline'; " +
            "img-src 'self' data: https://api.qrserver.com; " +
            "connect-src 'self' https://*.blob.core.windows.net " +
            "https://*.microsoftonline.com https://login.microsoft.com " +
            "https://maanit-func.azurewebsites.net"
        );
      }
      res.setHeader('X-Frame-Options', 'DENY');
      res.setHeader('X-Content-Type-Options', 'nosniff');
      res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
      res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    }
  })(req, res, next);
});

// 401 page
app.get('/401.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', '401.html'));
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).send('Internal Server Error');
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
