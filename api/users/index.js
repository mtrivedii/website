const sql = require("mssql");

// same MSI config
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: "azure-active-directory-msi-app-service" },
  options: { encrypt: true, trustServerCertificate: true },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

// one-time pool
const poolPromise = sql.connect(dbConfig)
  .then(p => { console.log("[users] pool created"); return p; })
  .catch(e => { console.error("[users] pool failed", e); throw e; });

module.exports = async function(context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] users start`);

  try {
    const pool = await poolPromise;
    context.log(`[${id}] connected to DB`);
    const result = await pool.request().query("SELECT id,email,Role FROM Users ORDER BY id");
    context.res = { status: 200, body: result.recordset };
  }
  catch (err) {
    context.log.error(`[${id}] ERROR`, err);
    context.res = { status: 500, body: { message: "Internal server error" } };
  }
};
