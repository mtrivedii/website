const sql = require("mssql");
const Joi = require("joi");

// Input‐validation schema
const scoreSchema = Joi.object({
  username: Joi.string().alphanum().min(3).max(30).required(),
  score:    Joi.number().integer().min(0).required()
});

// DB configuration using Managed Identity (MSI)
const dbConfig = {
  server:           process.env.DB_SERVER,
  database:         process.env.DB_NAME,
  authentication:   { type: "azure-active-directory-msi-app-service" },
  options:          { encrypt: true, trustServerCertificate: true },
  pool:             { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

// Create a single global pool once
const poolPromise = sql.connect(dbConfig)
  .then(pool => {
    console.log("[scoreboard] Connection pool created");
    pool.on("error", err => console.error("[scoreboard] Pool error", err));
    return pool;
  })
  .catch(err => {
    console.error("[scoreboard] Pool creation failed", err);
    throw err;
  });

module.exports = async function(context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] scoreboard start`);

  try {
    const pool = await poolPromise;         // reuse the same pool
    context.log(`[${id}] DB connected`);

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
        .input("u", sql.NVarChar, value.username)
        .input("s", sql.Int,       value.score)
        .query("INSERT INTO Scoreboard(username,score) VALUES(@u,@s)");
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
