const sql = require("mssql");

// same Managed Identity / MSI‐App‐Service config you used in scoreboard
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: "azure-active-directory-msi-app-service" },
  options: {
    encrypt: true,
    trustServerCertificate: true
  }
};

module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] users() start, method=${req.method}`);

  if (req.method !== 'GET') {
    context.log.warn(`[${id}] users() -> 405 Method Not Allowed`);
    context.res = { status: 405, body: 'Method Not Allowed' };
    return;
  }

  let pool;
  try {
    pool = await sql.connect(dbConfig);
    context.log(`[${id}] Connected to DB for users`);

    const result = await pool
      .request()
      .query("SELECT id, email, Role FROM Users ORDER BY id");

    context.res = {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: result.recordset
    };
    context.log(`[${id}] users() -> 200, ${result.recordset.length} rows`);
  }
  catch (err) {
    context.log.error(`[${id}] users() ERROR:`, err);
    context.res = {
      status: 500,
      body: { message: 'Internal server error' }
    };
  }
  finally {
    try {
      if (pool) await pool.close();
      context.log(`[${id}] DB pool closed for users`);
    } catch(closeErr) {
      context.log.error(`[${id}] Error closing users pool`, closeErr);
    }
  }
};
