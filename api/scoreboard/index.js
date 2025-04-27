const sql  = require('mssql');
const Joi  = require('joi');

// ----------------------------------------------------------------------------
// Input validation
const scoreSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  score:    Joi.number().integer().min(0).required()
}).options({ abortEarly: false });

// ----------------------------------------------------------------------------
// Read + validate our SP credentials from env
const CLIENT_ID     = process.env.AAD_CLIENT_ID;
const CLIENT_SECRET = process.env.AAD_CLIENT_SECRET;
const TENANT_ID     = process.env.AAD_TENANT_ID;

if (!CLIENT_ID || !CLIENT_SECRET || !TENANT_ID) {
  throw new Error(
    'Missing one of AAD_CLIENT_ID, AAD_CLIENT_SECRET or AAD_TENANT_ID in environment'
  );
}

// ----------------------------------------------------------------------------
// DB config using service principal
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: {
    type: 'azure-active-directory-service-principal-secret',
    options: {
      clientId:     String(CLIENT_ID),
      clientSecret: String(CLIENT_SECRET),
      tenantId:     String(TENANT_ID)
    }
  },
  options: {
    encrypt: true,
    trustServerCertificate: true
  }
};

// ----------------------------------------------------------------------------
// Global pool for perf
let poolPromise = sql.connect(dbConfig)
  .then(pool => {
    console.log('[scoreboard] Pool created');
    pool.on('error', e => console.error('[scoreboard] Pool error', e));
    return pool;
  })
  .catch(e => {
    console.error('[scoreboard] Pool creation failed', e);
    throw e;
  });

// ----------------------------------------------------------------------------
// Azure Function
module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log.info(`[${id}] Start`);

  try {
    const pool = await poolPromise;
    context.log.info(`[${id}] DB connected`);

    if (req.method === 'GET') {
      context.log.info(`[${id}] GET`);
      const { recordset } = await pool
        .request()
        .query('SELECT TOP (10) username, score FROM Scoreboard ORDER BY score DESC');
      return context.res = { status: 200, body: recordset };
    }

    if (req.method === 'POST') {
      context.log.info(`[${id}] POST`);
      const { error, value } = scoreSchema.validate(req.body);
      if (error) {
        const msg = error.details.map(d => d.message).join('; ');
        context.log.warn(`[${id}] Validation failed: ${msg}`);
        return context.res = { status: 400, body: { message: msg } };
      }
      await pool
        .request()
        .input('username', sql.NVarChar, value.username)
        .input('score',    sql.Int,      value.score)
        .query('INSERT INTO Scoreboard (username, score) VALUES (@username, @score)');
      return context.res = { status: 201, body: { message: 'Score added' } };
    }

    context.log.warn(`[${id}] Method not allowed: ${req.method}`);
    context.res = { status: 405, body: 'Method Not Allowed' };
  }
  catch (err) {
    context.log.error(`[${id}] ERROR`, err);
    context.res = {
      status: 500,
      body: {
        message: 'Internal server error',
        detail: err.originalError?.message || err.message
      }
    };
  }
};
