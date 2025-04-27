const sql  = require("mssql");
const Joi  = require("joi");

// validate POST body
const scoreSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  score:    Joi.number().integer().min(0).required()
});

// DB config via Managed Identity
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: "azure-active-directory-msi-app-service" },
  options: {
    encrypt: true,
    trustServerCertificate: true,
    connectTimeout: 15000,
    requestTimeout: 300000
  },
  pool: { max:10, min:0, idleTimeoutMillis:30000 }
};

// one global poolPromise
const poolPromise = new sql.ConnectionPool(dbConfig)
  .connect()
  .then(p => {
    p.on("error", e => {
      console.error("[scoreboard] pool error", e);
    });
    console.log("[scoreboard] pool created");
    return p;
  })
  .catch(e => {
    console.error("[scoreboard] pool creation failed", e);
    throw e;
  });

module.exports = async function(context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] scoreboard ${req.method}`);

  try {
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
        context.res = { status: 400, body: { message: error.details.map(d=>d.message).join("; ") } };
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
