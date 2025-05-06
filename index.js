const express = require('express');
const path = require('path');

// Import handlers
const checkAdminHandler = require('./checkAdmin');
const getSasTokenHandler = require('./getSasToken');
const usersRouter = require('./users'); // Express router

const app = express();

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
