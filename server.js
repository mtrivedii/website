const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');

// Load API logic
const loginHandler = require('./api/login/index');
const registerHandler = require('./api/register/index');

const app = express();
const port = process.env.PORT || 8080;

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname)));

// Routes for static HTML
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'register.html')));

// Routes for API
app.post('/api/login', loginHandler);
app.post('/api/register', registerHandler);

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
