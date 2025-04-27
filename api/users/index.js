const sql = require("mssql");

// DB config same as scoreboard
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
    p.on("error", e => console.error("[users] pool error", e));
    console.log("[users] pool created");
    return p;
  })
  .catch(e => {
    console.error("[users] pool creation failed", e);
    throw e;
  });

module.exports = async function(context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] users ${req.method}`);

  try {
    const pool = await poolPromise;

    if (req.method === "GET") {
      const result = await pool.request()
        .query("SELECT id, email, Role FROM Users ORDER BY id");
      context.res = { status: 200, body: result.recordset };
      return;
    }

    context.res = { status: 405, body: "Method Not Allowed" };
  }
  catch (err) {
    context.log.error(`[${id}] ERROR`, err);
    context.res = { status: 500, body: { message: "Internal server error" } };
  }
};
