const sql  = require('mssql');
const Joi  = require('joi');

// ============================================================================
//  Input Validation (OWASP Top 10 Proactive Controls)
// ============================================================================
const scoreSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  score:    Joi.number().integer().min(0).required()
}).options({ abortEarly: false });

// ============================================================================
//  Authentication + Encryption + PoLP
// ============================================================================
// Service Principal secret fallback (Static Web App)
// – Make sure AAD_CLIENT_ID, AAD_CLIENT_SECRET, AAD_TENANT_ID are in env vars
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: {
    type: 'azure-active-directory-service-principal-secret',
    options: {
      clientId:     process.env.AAD_CLIENT_ID,
      clientSecret: process.env.AAD_CLIENT_SECRET,
      tenantId:     process.env.AAD_TENANT_ID
    }
  },
  options: {
    encrypt: true,
    trustServerCertificate: true
  }
};

// ============================================================================
//  Connection Pool (reused across invocations for performance)
// ============================================================================
let poolPromise = sql.connect(dbConfig)
  .then(pool => {
    console.log('[scoreboard] Global connection pool created');
    pool.on('error', err => console.error('[scoreboard] Pool error:', err));
    return pool;
  })
  .catch(err => {
    console.error('[scoreboard] Global pool creation failed:', err);
    throw err;
  });

// ============================================================================
//  Fail-Safely + Logging & Monitoring
// ============================================================================
module.exports = async function (context, req) {
  const invocationId = context.executionContext.invocationId;
  context.log.info(`[${invocationId}] Invocation started`);

  try {
    context.log.info(`[${invocationId}] Connecting to SQL: ${process.env.DB_SERVER}/${process.env.DB_NAME}`);
    const pool = await poolPromise;
    context.log.info(`[${invocationId}] Connected to DB`);

    if (req.method === 'GET') {
      context.log.info(`[${invocationId}] Handling GET`);
      const result = await pool.request()
        .query('SELECT TOP (10) username, score FROM Scoreboard ORDER BY score DESC');

      context.res = {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
        body: result.recordset
      };
      context.log.info(`[${invocationId}] GET completed`);
      return;
    }

    if (req.method === 'POST') {
      context.log.info(`[${invocationId}] Handling POST`);
      const { error, value } = scoreSchema.validate(req.body);
      if (error) {
        const msg = error.details.map(e => e.message).join('; ');
        context.log.warn(`[${invocationId}] Validation failed: ${msg}`);
        context.res = { status: 400, body: { message: msg } };
        return;
      }

      await pool.request()
        .input('username', sql.NVarChar, value.username)
        .input('score',    sql.Int,      value.score)
        .query('INSERT INTO Scoreboard (username, score) VALUES (@username, @score)');

      context.res = { status: 201, body: { message: 'Score added successfully' } };
      context.log.info(`[${invocationId}] POST completed for ${value.username}`);
      return;
    }

    context.log.warn(`[${invocationId}] Unsupported method: ${req.method}`);
    context.res = { status: 405, body: 'Method Not Allowed' };
  }
  catch (err) {
    // ========================================================================
    // Detailed error logging
    // ========================================================================
    context.log.error(
      `[${invocationId}] FULL ERROR:`,
      JSON.stringify(err, Object.getOwnPropertyNames(err), 2)
    );
    context.log.error(`[${invocationId}] ORIGINAL error:`, err.originalError);

    // ========================================================================
    // Surface inner error message for debugging
    // ========================================================================
    context.res = {
      status: 500,
      body: {
        message: err.message,
        detail: err.originalError?.message || err.originalError || null
      }
    };
  }
};
