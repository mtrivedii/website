const sql = require('mssql');
const Joi = require('joi');

// Schema for creating a user
const userSchema = Joi.object({
  displayName: Joi.string().max(100).required()
});

const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: 'azure-active-directory-msi' },
  options: { encrypt: true }
};

module.exports = async function (context, req) {
  // Decode the SWA principal header:
  const hdr = req.headers['x-ms-client-principal'];
  if (!hdr) return context.res = { status: 401, body: 'Not authenticated' };

  const decoded   = Buffer.from(hdr, 'base64').toString('ascii');
  const principal = JSON.parse(decoded);
  const azureId   = principal.userId;                   // the object ID
  const email     = principal.userDetails.split('|').pop(); // email portion
  const roles     = principal.userRoles || [];  

  try {
    await sql.connect(dbConfig);

    if (req.method === 'GET') {
      // Return all users
      const result = await sql.query`SELECT id, email, displayName, AzureID, Role FROM Users`;
      return context.res = { status: 200, body: result.recordset };
    }

    if (req.method === 'POST') {
      // Validate incoming displayName
      const { error, value } = userSchema.validate(req.body);
      if (error) {
        return context.res = { status: 400, body: { message: error.details[0].message } };
      }

      // Upsert: ensure we have a record for this AzureID
      const role = roles.includes('admin') ? 'admin' : 'user';
      await sql.query`
        MERGE INTO Users WITH (HOLDLOCK) AS target
        USING (VALUES (${azureId}, ${email}, ${value.displayName}, ${role})) AS src (AzureID, email, displayName, Role)
          ON target.AzureID = src.AzureID
        WHEN MATCHED THEN
          UPDATE SET email = src.email, displayName = src.displayName, Role = src.Role
        WHEN NOT MATCHED THEN
          INSERT (AzureID, email, displayName, Role)
          VALUES (src.AzureID, src.email, src.displayName, src.Role);
      `;

      return context.res = { status: 200, body: { message: 'User upserted' } };
    }

    // Method not allowed
    context.res = { status: 405, body: 'Method not allowed' };
  } catch (err) {
    context.log.error('users function error', err);
    context.res = { status: 500, body: { message: 'Internal server error' } };
  }
};
