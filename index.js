const express = require('express');
const path = require('path');

// Import handlers
const checkAdminHandler = require('./checkAdmin');
const getSasTokenHandler = require('./getSasToken');
const usersRouter = require('./users'); // Express router

const app = express();

// Disable X-Powered-By header
app.disable('x-powered-by');

// Security headers middleware - add this before any routes
app.use((req, res, next) => {
  // Set security headers with updated CSP to allow backend connections
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; connect-src 'self' https://*.microsoftonline.com https://login.microsoft.com https://maanit-func.azurewebsites.net");
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
  
  // Already set by Azure but including for completeness
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  
  next();
});

// Middleware to require authentication using Easy Auth headers
function requireAuth(req, res, next) {
  const principal = req.headers['x-ms-client-principal'];
  if (!principal) {
    return res.status(401).send('Unauthorized');
  }
  next();
}

// Register API routes with authentication
app.get('/api/checkAdmin', requireAuth, checkAdminHandler.handler);
app.post('/api/checkAdmin', requireAuth, checkAdminHandler.handler);

app.get('/api/getSasToken', requireAuth, getSasTokenHandler.handler);
app.options('/api/getSasToken', requireAuth, getSasTokenHandler.handler);

// Mount the users router (users.js handles /api/users)
app.use('/api', requireAuth, usersRouter);

// Serve static files from 'public' directory (your frontend)
app.use(express.static(path.join(__dirname, 'public'), {
  // Set headers for static files
  setHeaders: (res, path) => {
    // Don't apply CSP to CSS and JS files to avoid breaking functionality
    if (!path.endsWith('.css') && !path.endsWith('.js')) {
      res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; connect-src 'self' https://*.microsoftonline.com https://login.microsoft.com https://maanit-func.azurewebsites.net");
    }
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), geolocation=(), microphone=()');
  }
}));

// Optional: SPA fallback to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});