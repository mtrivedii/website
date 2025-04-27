const sql  = require('mssql');
const Joi  = require('joi');

// ============================================================================
//  Standards & Regulations + Threat Analysis & Secure Design + Input Validation
// ============================================================================
// Joi schema for POSTing a new score
const scoreSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  score:    Joi.number().integer().min(0).required()
}).options({ abortEarly: false });

// ============================================================================
//  Authentication + Encryption + Principle of Least Privilege
// ============================================================================
// Secure DB config via Managed Identity (App Service MSI)
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: 'azure-active-directory-msi-app-service' },
  options: {
    encrypt: true,
    trustServerCertificate: true,
    multiSubnetFailover: true
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
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
//  Fail Safely + Logging & Monitoring
// ============================================================================
module.exports = async function (context, req) {
  const invocationId = context.executionContext.invocationId;
  context.log.info(`[${invocationId}] Invocation started`);

  try {
    context.log.info(
      `[${invocationId}] Connecting to DB: server=${process.env.DB_SERVER}, db=${process.env.DB_NAME}`
    );
    const pool = await poolPromise;
    context.log.info(`[${invocationId}] Connected to DB (reused pool)`);

    // ========================================================================
    //  Enforce least privilege based on HTTP method
    // ========================================================================
    if (req.method === 'GET') {
      context.log.info(`[${invocationId}] Handling GET`);
      const result = await pool
        .request()
        .query('SELECT TOP (10) username, score FROM Scoreboard ORDER BY score DESC');
      context.res = {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
        body: result.recordset
      };
      context.log.info(`[${invocationId}] GET completed successfully`);
      return;
    }

    if (req.method === 'POST') {
      context.log.info(`[${invocationId}] Handling POST`);
      const { error, value } = scoreSchema.validate(req.body);
      if (error) {
        const msg = error.details.map(e => e.message).join('; ');
        context.log.warn(`[${invocationId}] Validation failed: ${msg}`);
        context.res = { status: 400, body: { message: `Validation failed: ${msg}` } };
        return;
      }

      await pool
        .request()
        .input('username', sql.NVarChar, value.username)
        .input('score', sql.Int, value.score)
        .query('INSERT INTO Scoreboard (username, score) VALUES (@username, @score)');
      
      context.res = { status: 201, body: { message: 'Score added successfully' } };
      context.log.info(`[${invocationId}] POST completed for user ${value.username}`);
      return;
    }

    // ========================================================================
    //  Reject unsupported HTTP methods
    // ========================================================================
    context.log.warn(`[${invocationId}] Unsupported HTTP method: ${req.method}`);
    context.res = { status: 405, body: 'Method Not Allowed' };
  }
  catch (err) {
    context.log.error(`[${invocationId}] ERROR: ${err.message}`, err);
    context.res = {
      status: 500,
      body: { message: 'Internal server error. Contact support with invocation ID.' }
    };
  }
};
