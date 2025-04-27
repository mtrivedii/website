const sql  = require('mssql');
const Joi  = require('joi');

// Joi schema for POSTing a new score
const scoreSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  score:    Joi.number().integer().min(0).required()
});

// DB config via Managed Identity (App Service MSI)
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: 'azure-active-directory-msi-app-service' },
  options: {
    encrypt: true,
    // allow the MSI flow to trust the platform cert
    trustServerCertificate: true
  }
};

module.exports = async function (context, req) {
  context.log('[scoreboard] invocation started');

  try {
    // establish the connection
    await sql.connect(dbConfig);
    context.log('[scoreboard] connected to DB');

    if (req.method === 'GET') {
      const result = await sql.query`
        SELECT TOP (10) username, score
        FROM Scoreboard
        ORDER BY score DESC
      `;
      context.res = {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
        body: result.recordset
      };
      return;
    }

    if (req.method === 'POST') {
      const { error, value } = scoreSchema.validate(req.body);
      if (error) {
        context.log.warn('[scoreboard] validation failed:', error.details[0].message);
        context.res = { status: 400, body: { message: error.details[0].message } };
        return;
      }
      await sql.query`
        INSERT INTO Scoreboard (username, score)
        VALUES (${value.username}, ${value.score})
      `;
      context.res = { status: 201, body: { message: 'Score added' } };
      return;
    }

    // unsupported HTTP method
    context.res = { status: 405, body: 'Method Not Allowed' };
  }
  catch (err) {
    context.log.error('[scoreboard] ERROR:', err);
    // For production, return a generic message. You can re-enable debug output if you need further insight.
    context.res = {
      status: 500,
      body: { message: 'Internal server error' }
    };
  }
};
