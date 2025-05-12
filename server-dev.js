// server-dev.js - Development server with authentication
const express = require('express');
const path = require('path');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const app = express();

// Import mock handlers
const mockCheckAdmin = require('./mocks/mock-checkAdmin');
const mockGetSasToken = require('./mocks/mock-getSasToken');
const mockUsersRouter = require('./mocks/mock-users');
const mockRegisterRouter = require('./mocks/mock-register');
const mockLoginRouter = require('./mocks/mock-login');
const mock2FARouter = require('./mocks/mock-2fa');

// Initialize global array for registered users
global.mockRegisteredUsers = global.mockRegisteredUsers || [];

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Logging middleware
app.use((req, res, next) => {
  console.log(`[DEV SERVER] ${req.method} ${req.url}`);
  next();
});

// Mock authentication middleware - only apply to certain routes
app.use((req, res, next) => {
  // Skip for authentication, registration, and static assets
  if (req.url.match(/\.(js|css|png|jpg|jpeg|gif|ico)$/) || 
      req.url === '/api/register' || 
      req.url === '/register.html' ||
      req.url === '/api/login' ||
      req.url === '/login.html' ||
      req.url.startsWith('/api/2fa/') ||
      req.url === '/2fa.html') {
    return next();
  }
  
  // Check for auth token cookie first
  const authToken = req.cookies.auth_token;
  if (authToken) {
    // In a real app, we would verify the token here
    console.log('[DEV SERVER] Using JWT authentication');
    // Add user info to request for downstream handlers
    req.user = { 
      id: 'user-jwt-id', 
      email: 'jwt-user@example.com',
      role: 'user'
    };
    return next();
  }
  
  // Fallback to Easy Auth for routes that require authentication
  const mockUserPrincipal = {
    identityProvider: 'aad',
    userId: 'test-admin-user',
    userDetails: 'admin@example.com',
    claims: [
      { typ: 'http://schemas.microsoft.com/identity/claims/objectidentifier', val: 'test-admin-user' },
      { typ: 'name', val: 'Test Admin' },
      { typ: 'preferred_username', val: 'admin@example.com' },
      { typ: 'roles', val: 'admin' }
    ]
  };
  
  // Base64 encode the mock user principal
  const encodedPrincipal = Buffer.from(JSON.stringify(mockUserPrincipal)).toString('base64');
  req.headers['x-ms-client-principal'] = encodedPrincipal;
  next();
});

// CORS for local development
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  next();
});

// Mock API routes
app.get('/api/checkAdmin', mockCheckAdmin.handler);
app.post('/api/checkAdmin', mockCheckAdmin.handler);
app.get('/api/getSasToken', mockGetSasToken.handler);
app.use('/api', mockUsersRouter);
app.use('/api', mockRegisterRouter);
app.use('/api', mockLoginRouter);
app.use('/api', mock2FARouter);

// Mock auth endpoints
app.get('/.auth/me', (req, res) => {
  // Check for JWT auth first
  const authToken = req.cookies.auth_token;
  if (authToken) {
    // In a real app, we would decode and verify the token
    res.json({
      clientPrincipal: {
        identityProvider: 'local',
        userId: 'user-jwt-id',
        userDetails: 'jwt-user@example.com',
        userRoles: ['authenticated', 'user']
      }
    });
    return;
  }
  
  // Fallback to AAD
  res.json({
    clientPrincipal: {
      identityProvider: 'aad',
      userId: 'test-admin-user',
      userDetails: 'admin@example.com',
      userRoles: ['authenticated', 'admin']
    }
  });
});

// Mock login/logout redirects
app.get('/.auth/login/aad', (req, res) => {
  const redirectUri = req.query.post_login_redirect_uri || '/';
  res.redirect(redirectUri);
});

app.get('/.auth/logout', (req, res) => {
  // Clear auth cookie
  res.clearCookie('auth_token');
  res.redirect('/');
});

// Create and serve local uploads directory
const uploadsDir = path.join(__dirname, 'local-uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}
app.use('/local-uploads', express.static(uploadsDir));

// Serve static files
app.use(express.static('public'));

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start server
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Local development server running at http://localhost:${port}`);
  console.log('Registration page available at http://localhost:3000/register.html');
  console.log('Login page available at http://localhost:3000/login.html');
  console.log('2FA setup page available at http://localhost:3000/2fa.html');
});
