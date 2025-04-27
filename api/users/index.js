const sql = require("mssql");

// same Managed Identity / MSI‐App‐Service config you used in scoreboard
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: "azure-active-directory-msi-app-service" },
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

// create pool once
const poolPromise = sql.connect(dbConfig)
  .then(pool => {
    console.log("[users] pool created");
    pool.on("error", err => console.error("[users] pool error", err));
    return pool;
  })
  .catch(err => {
    console.error("[users] pool creation failed", err);
    throw err;
  });

module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log.info(`[${id}] users function start`);

  try {
    const pool = await poolPromise;
    context.log.info(`[${id}] connected to DB`);

    const result = await pool
      .request()
      .query("SELECT id, email, Role FROM Users ORDER BY id");

    context.res = {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: result.recordset
    };
  } catch (err) {
    context.log.error(`[${id}] Users API error:`, err);
    context.res = {
      status: 500,
      body: { message: "Internal server error" }
    };
  }

  // DO NOT close the pool here!
};
