const sql  = require('mssql');
const Joi  = require('joi');

// Input validation
const scoreSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  score:    Joi.number().integer().min(0).required()
}).options({ abortEarly: false });

// DB config via Managed Identity
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: 'azure-active-directory-msi-app-service' },
  options: {
    encrypt: true,
    trustServerCertificate: true
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

// create one global pool
const poolPromise = sql.connect(dbConfig)
  .then(pool => {
    console.log('[scoreboard] pool created');
    pool.on('error', e => console.error('[scoreboard] pool error', e));
    return pool;
  })
  .catch(e => {
    console.error('[scoreboard] pool creation failed', e);
    throw e;
  });

module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log.info(`[${id}] scoreboard start`);

  try {
    const pool = await poolPromise;
    context.log.info(`[${id}] connected to DB`);

    if (req.method === 'GET') {
      context.log.info(`[${id}] GET`);
      const result = await pool
        .request()
        .query('SELECT TOP (10) username, score FROM Scoreboard ORDER BY score DESC');
      context.res = { status: 200, body: result.recordset };
      return;
    }

    if (req.method === 'POST') {
      context.log.info(`[${id}] POST`);
      const { error, value } = scoreSchema.validate(req.body);
      if (error) {
        const msg = error.details.map(d => d.message).join('; ');
        context.log.warn(`[${id}] Validation failed: ${msg}`);
        context.res = { status: 400, body: { message: msg } };
        return;
      }
      await pool
        .request()
        .input('username', sql.NVarChar, value.username)
        .input('score',    sql.Int,      value.score)
        .query('INSERT INTO Scoreboard (username, score) VALUES (@username,@score)');
      context.res = { status: 201, body: { message: 'Score added' } };
      return;
    }

    context.log.warn(`[${id}] Method not allowed: ${req.method}`);
    context.res = { status: 405, body: 'Method Not Allowed' };
  }
  catch (err) {
    context.log.error(`[${id}] ERROR`, err);
    context.res = {
      status: 500,
      body: { message: 'Internal server error' }
    };
  }

  // Notice: we do NOT call sql.close() here,
  // so the pool remains available for the next request.
};
