const sql = require("mssql");

// DB config using Managed Identity (App Service MSI)
const dbConfig = {
  server:   process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: "azure-active-directory-msi-app-service" },
  options: {
    encrypt: true,
    trustServerCertificate: true
  },
  pool: {
    max:  10,
    min:  0,
    idleTimeoutMillis: 30000
  }
};

// create one global pool
let poolPromise = sql.connect(dbConfig)
  .then(pool => {
    console.log("[users] connection pool created");
    pool.on("error", err => console.error("[users] pool error", err));
    return pool;
  })
  .catch(err => {
    console.error("[users] pool creation failed", err);
    // leave poolPromise resolved to undefined so that invocations see the failure
  });

module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] users API start`);

  // validate env
  if (!process.env.DB_SERVER || !process.env.DB_NAME) {
    context.log.error(`[${id}] Missing DB_SERVER or DB_NAME`);
    context.res = {
      status: 500,
      body: { message: "Server configuration error" }
    };
    return;
  }

  try {
    const pool = await poolPromise;
    if (!pool) throw new Error("No database connection pool");

    context.log(`[${id}] querying Users table`);
    const result = await pool.request()
      .query("SELECT id, email, Role FROM Users ORDER BY id");

    context.res = {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: result.recordset
    };
  }
  catch (err) {
    context.log.error(`[${id}] users API error`, err);
    context.res = {
      status: 500,
      body: { message: "Internal server error" }
    };
  }
};
