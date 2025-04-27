const sql  = require("mssql");
const Joi  = require("joi");

// 1) Input validation schema (module-scope)
const scoreSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  score:    Joi.number().integer().min(0).required()
}).options({ abortEarly: false });

// 2) DB config via MSI (module-scope)
const dbConfig = {
  server:   process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: "azure-active-directory-msi-app-service" },
  options: {
    encrypt: true,
    trustServerCertificate: true,
    multiSubnetFailover: true,
    connectTimeout: 15000,
    requestTimeout: 300000
  },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

// 3) Global poolPromise (module-scope) — no context here!
let poolPromise = new sql.ConnectionPool(dbConfig)
  .connect()
  .then(p => {
    console.log("[scoreboard] pool created");
    p.on("error", e => {
      console.error("[scoreboard] pool error", e);
      poolPromise = null;           // so next call rebuilds
    });
    return p;
  })
  .catch(e => {
    console.error("[scoreboard] pool creation failed", e);
    poolPromise = null;
    throw e;
  });

// 4) Function handler
module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] scoreboard start (${req.method})`);

  try {
    if (!process.env.DB_SERVER || !process.env.DB_NAME) {
      throw new Error("Missing DB_SERVER/DB_NAME");
    }

    // await or recreate the pool
    if (!poolPromise) {
      poolPromise = new sql.ConnectionPool(dbConfig).connect()
        .then(p => {
          console.log("[scoreboard] pool re-created");
          p.on("error", e => {
            console.error("[scoreboard] pool error", e);
            poolPromise = null;
          });
          return p;
        });
    }
    const pool = await poolPromise;

    if (req.method === "GET") {
      const result = await pool.request()
        .query("SELECT TOP(10) username, score FROM Scoreboard ORDER BY score DESC");
      context.res = { status: 200, body: result.recordset };
      return;
    }

    if (req.method === "POST") {
      const { error, value } = scoreSchema.validate(req.body);
      if (error) {
        context.res = {
          status: 400,
          body: { message: error.details.map(d=>d.message).join("; ") }
        };
        return;
      }
      await pool.request()
        .input("username", sql.NVarChar, value.username)
        .input("score",    sql.Int,      value.score)
        .query("INSERT INTO Scoreboard (username,score) VALUES (@username,@score)");
      context.res = { status: 201, body: { message: "Score added" } };
      return;
    }

    context.res = { status: 405, body: "Method Not Allowed" };
  }
  catch (err) {
    context.log.error(`[${id}] ERROR`, err);
    context.res = { status: 500, body: { message: "Internal server error" } };
  }
};
