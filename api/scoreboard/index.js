const sql  = require('mssql');
const Joi  = require('joi');

const scoreSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  score:    Joi.number().integer().min(0).required()
});

const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: 'azure-active-directory-msi-app-service' },
  options: { encrypt: true }
};

module.exports = async function (context, req) {
  context.log('[scoreboard] invocation started');

  try {
    await sql.connect(dbConfig);
    context.log('[scoreboard] connected to DB');

    if (req.method === 'GET') {
      const result = await sql.query`
        SELECT TOP (10) username, score FROM Scoreboard ORDER BY score DESC
      `;
      return context.res = { status: 200, body: result.recordset };
    }

    if (req.method === 'POST') {
      const { error, value } = scoreSchema.validate(req.body);
      if (error) {
        return context.res = { status: 400, body: { message: error.details[0].message } };
      }
      await sql.query`
        INSERT INTO Scoreboard (username, score)
        VALUES (${value.username}, ${value.score})
      `;
      return context.res = { status: 201, body: { message: 'Score added' } };
    }

    context.res = { status: 405, body: 'Method Not Allowed' };
  }
  catch (err) {
    context.log.error('[scoreboard] ERROR:', err);
    // DEBUG: return error details
    context.res = {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
      body: {
        error: err.message,
        stack: err.stack
      }
    };
  }
};
