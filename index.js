// app.js or index.js
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const path = require('path');
const getSasTokenHandler = require('./getSasToken');

const app = express();
const port = process.env.PORT || 3000;

// Security headers with appropriate CSP for blob uploads
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"], // Allow inline scripts
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles
      connectSrc: [
        "'self'", 
        "https://*.blob.core.windows.net", 
        "https://*.microsoftonline.com", 
        "https://login.microsoft.com", 
        "https://maanit-func.azurewebsites.net"
      ],
      imgSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  // Other security settings
  strictTransportSecurity: {
    maxAge: 31536000,
    includeSubDomains: true
  }
}));

// CORS middleware
app.use(cors({
  origin: true, // Reflects the request origin
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-ms-client-principal']
}));

// Parse JSON and URL-encoded bodies
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Static files
app.use(express.static(path.join(__dirname, 'public')));

// API route for SAS token generation
app.get('/api/getSasToken', getSasTokenHandler.handler);

// Add other routes here

// Handle 404s
app.use((req, res, next) => {
  res.status(404).sendFile(path.join(__dirname, 'public', '404.html'));
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).sendFile(path.join(__dirname, 'public', '500.html'));
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

module.exports = app;