const sql = require("mssql");
const Joi = require("joi");

// ── 1) Input validation schema (module-scope)
const scoreSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  score:    Joi.number().integer().min(0).required()
}).options({ abortEarly: false });

// ── 2) DB config via MSI (module-scope)
const dbConfig = {
  server:   process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: "azure-active-directory-msi-app-service" },
  options: { encrypt: true, trustServerCertificate: true, multiSubnetFailover: true },
  pool: { max:10, min:0, idleTimeoutMillis:30000 }
};

// ── 3) Pool-factory with retry/back-off
async function createPool(context, attempt = 1) {
  try {
    const pool = await new sql.ConnectionPool(dbConfig).connect();
    context.log.info(`Pool created (attempt ${attempt})`);
    pool.on("error", err => {
      context.log.error("Pool error, will recreate on next call:", err);
      pool = null;
      poolPromise = createPool(context);
    });
    return pool;
  } catch (err) {
    context.log.error(`Pool creation failed (attempt ${attempt}):`, err);
    // exponential back-off up to ~1 minute
    const delay = Math.min(1000 * 2 ** attempt, 60000);
    await new Promise(r => setTimeout(r, delay));
    return createPool(context, attempt + 1);
  }
}

// ── 4) One shared poolPromise
let poolPromise = null;

// ── 5) Helper to get a healthy pool
async function getPool(context) {
  if (!poolPromise) {
    poolPromise = createPool(context);
  }
  return poolPromise;
}

// ── 6) Azure Function handler
module.exports = async function(context, req) {
  const id = context.executionContext.invocationId;
  context.log.info(`[${id}] scoreboard invoked: ${req.method}`);

  try {
    const pool = await getPool(context);
    const request = pool.request().verbose = true;

    if (req.method === "GET") {
      const result = await request.query(
        "SELECT TOP(10) username, score FROM Scoreboard ORDER BY score DESC"
      );
      context.res = { status: 200, body: result.recordset };
      return;
    }

    if (req.method === "POST") {
      const { error, value } = scoreSchema.validate(req.body);
      if (error) {
        context.res = { status: 400, body: { message: error.details.map(d=>d.message).join("; ") } };
        return;
      }
      await request
        .input("username", sql.NVarChar, value.username)
        .input("score",    sql.Int,      value.score)
        .query("INSERT INTO Scoreboard (username,score) VALUES (@username,@score)");
      context.res = { status: 201, body: { message: "Score added" } };
      return;
    }

    context.res = { status: 405, body: "Method Not Allowed" };
  }
  catch (err) {
    context.log.error(`[${id}] handler error:`, err);
    context.res = { status: 500, body: { message: "Internal server error" } };
  }
};
