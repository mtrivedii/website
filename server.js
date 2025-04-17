const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');

// ✅ Load API logic with correct paths from /api
const loginHandler = require('./api/login/index.js');
const registerHandler = require('./register/index.js');

const app = express();
const port = process.env.PORT || 8080;

// ✅ Add CORS headers before routes
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); // Replace * with frontend URL if needed
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Static HTML pages
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));

// API endpoints
app.post('/api/login', loginHandler);
app.post('/register', registerHandler);

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
