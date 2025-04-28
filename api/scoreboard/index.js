const sql = require('mssql');
const Joi = require('joi');

// Database config
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: {
    type: 'azure-active-directory-msi-app-service'
  },
  options: {
    encrypt: true,
    trustServerCertificate: false
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

// Input validation schema
const scoreSchema = Joi.object({
  Username: Joi.string().min(3).max(50).required(),
  Score: Joi.number().integer().min(0).required()
}).options({ abortEarly: false });

let poolPromise = null;
async function getPool() {
  if (!poolPromise) {
    const pool = new sql.ConnectionPool(dbConfig);
    poolPromise = pool.connect().then(() => pool);
  }
  return poolPromise;
}

module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] /api/scoreboard called with method ${req.method}`);

  try {
    const pool = await getPool();

    if (req.method === "GET") {
      const result = await pool.request()
        .query("SELECT TOP (10) ScoreID, Username, Score FROM dbo.Scoreboard ORDER BY Score DESC");

      context.res = { status: 200, body: result.recordset };
      return;
    }

    if (req.method === "POST") {
      const { error, value } = scoreSchema.validate(req.body);
      if (error) {
        context.res = { status: 400, body: { message: error.details.map(d => d.message).join("; ") } };
        return;
      }

      await pool.request()
        .input('Username', sql.NVarChar, value.Username)
        .input('Score', sql.Int, value.Score)
        .query("INSERT INTO dbo.Scoreboard (Username, Score, Timestamp) VALUES (@Username, @Score, GETDATE())");

      context.res = { status: 201, body: { message: "Score added successfully" } };
      return;
    }

    context.res = { status: 405, body: { message: "Method Not Allowed" } };
  } catch (err) {
    context.log.error(`[${id}] ERROR`, err);
    context.res = { status: 500, body: { message: "Internal Server Error" } };
  }
};
