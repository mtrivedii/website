const sql = require("mssql");

// 1) DB config (module-scope)
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
  pool: { max:10, min:0, idleTimeoutMillis:30000 }
};

// 2) Global poolPromise (module-scope)
let poolPromise = new sql.ConnectionPool(dbConfig)
  .connect()
  .then(p => {
    console.log("[users] pool created");
    p.on("error", e => {
      console.error("[users] pool error", e);
      poolPromise = null;
    });
    return p;
  })
  .catch(e => {
    console.error("[users] pool creation failed", e);
    poolPromise = null;
    throw e;
  });

// 3) Function handler
module.exports = async function(context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] users start (${req.method})`);

  try {
    if (!process.env.DB_SERVER || !process.env.DB_NAME) {
      throw new Error("Missing DB_SERVER/DB_NAME");
    }

    // recreate pool if needed
    if (!poolPromise) {
      poolPromise = new sql.ConnectionPool(dbConfig).connect()
        .then(p => {
          console.log("[users] pool re-created");
          p.on("error", e => {
            console.error("[users] pool error", e);
            poolPromise = null;
          });
          return p;
        });
    }
    const pool = await poolPromise;

    if (req.method === "GET") {
      const result = await pool.request()
        .query("SELECT id, email, Role AS role FROM Users ORDER BY id");
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
