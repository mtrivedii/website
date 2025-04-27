const sql = require("mssql");
const Joi = require("joi");

// Joi schema …
const scoreSchema = Joi.object({ /* … */ });

// DB config (MSI or service-principal) …
const dbConfig = { /* … */ };

// Create pool once
const poolPromise = new sql.ConnectionPool(dbConfig)
  .connect()
  .then(p => {
    console.log("Pool created");
    p.on("error", e => console.error("Pool error", e));
    return p;
  })
  .catch(e => {
    console.error("Pool creation failed", e);
    // don’t throw here – let invocations see the error
  });

module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] scoreboard start`);

  // check env inside invocation
  if (!process.env.DB_SERVER || !process.env.DB_NAME) {
    context.log.error("Missing DB_SERVER or DB_NAME");
    context.res = { status: 500, body: { message: "Configuration error" } };
    return;
  }

  try {
    const pool = await poolPromise;
    if (!pool) throw new Error("No connection pool");

    if (req.method === "GET") {
      const rs = await pool.request().query(
        "SELECT TOP (10) username, score FROM Scoreboard ORDER BY score DESC"
      );
      context.res = { status: 200, body: rs.recordset };
      return;
    }

    if (req.method === "POST") {
      const { error, value } = scoreSchema.validate(req.body);
      if (error) {
        context.res = { status: 400, body: { message: error.details[0].message } };
        return;
      }
      await pool
        .request()
        .input("username", sql.NVarChar, value.username)
        .input("score", sql.Int, value.score)
        .query("INSERT INTO Scoreboard (username,score) VALUES (@username,@score)");
      context.res = { status: 201, body: { message: "Score added" } };
      return;
    }

    context.res = { status: 405, body: "Method Not Allowed" };
  } catch (e) {
    context.log.error(`[${id}] error`, e);
    context.res = { status: 500, body: { message: "Internal server error" } };
  }
};
