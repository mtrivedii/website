// requireAdmin.js
const path = require('path');

function requireAdmin(req, res, next) {
  let principal = null;
  if (req.headers['x-ms-client-principal']) {
    const encoded = req.headers['x-ms-client-principal'];
    principal = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
  }
  const roles = principal?.userRoles || [];

  if (!roles.includes('admin')) {
    // Serve the 401 page from the /public directory
    return res.status(401).sendFile(path.join(__dirname, 'public', '401.html'));
  }
  req.principal = principal;
  next();
}

module.exports = requireAdmin;
