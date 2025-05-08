const express = require('express');
const path = require('path');
const helmet = require('helmet');

// Import handlers
const checkAdminHandler = require('./checkAdmin');
const getSasTokenHandler = require('./getSasToken');
const usersRouter = require('./users'); // Express router

const app = express();

// Apply Helmet with customized CSP
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts if needed for your app
        styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles if needed for your app
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
        frameAncestors: ["'none'"],
        connectSrc: ["'self'", "https://*.microsoftonline.com", "https://login.microsoft.com"]
      }
    },
    // Other Helmet options can be customized here
    xFrameOptions: { action: 'deny' },
    // Force Strict-Transport-Security even if Azure already sets it
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true
    }
  })
);

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

// Serve static files from 'public' directory
app.use(express.static(path.join(__dirname, 'public')));

// Optional: SPA fallback to index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start the server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});