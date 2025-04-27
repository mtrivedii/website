const sql = require("mssql");

// ============================================================
// DB config via Managed Identity (MSI App Service)
// ============================================================
const dbConfig = {
  server:   process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: "azure-active-directory-msi-app-service" },
  options: { encrypt: true, trustServerCertificate: true, multiSubnetFailover: true },
  pool: { max: 10, min: 0, idleTimeoutMillis: 30000 }
};

// ============================================================
// Pool creation with retry/back-off
// ============================================================
async function createPool(context, attempt = 1) {
  try {
    const pool = await new sql.ConnectionPool(dbConfig).connect();
    context.log.info(`Users pool created (attempt ${attempt})`);
    pool.on("error", err => {
      context.log.error("Users pool error, will recreate on next call:", err);
      pool = null;
      poolPromise = createPool(context);
    });
    return pool;
  } catch (err) {
    context.log.error(`Users pool creation failed (attempt ${attempt}):`, err);
    const delay = Math.min(1000 * 2 ** attempt, 60000);
    await new Promise(r => setTimeout(r, delay));
    return createPool(context, attempt + 1);
  }
}

// ============================================================
// Shared poolPromise
// ============================================================
let poolPromise = null;
function getPool(context) {
  if (!poolPromise) poolPromise = createPool(context);
  return poolPromise;
}

// ============================================================
// Azure Function handler
// ============================================================
module.exports = async function(context, req) {
  const id = context.executionContext.invocationId;
  context.log.info(`[${id}] users() start`);

  try {
    // ensure config present
    if (!process.env.DB_SERVER || !process.env.DB_NAME) {
      throw new Error("Missing DB_SERVER or DB_NAME");
    }

    const pool = await getPool(context);
    context.log.info(`[${id}] users() connected to DB`);

    // only support GET
    if (req.method !== "GET") {
      context.log.warn(`[${id}] users() method not allowed: ${req.method}`);
      context.res = { status: 405, body: "Method Not Allowed" };
      return;
    }

    // fetch users
    const result = await pool.request().query(`
      SELECT 
        id, 
        email, 
        COALESCE(Role,'user') AS role 
      FROM Users 
      ORDER BY id
    `);

    context.res = {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: result.recordset
    };
    context.log.info(`[${id}] users() → 200, ${result.recordset.length} rows`);
  }
  catch (err) {
    context.log.error(`[${id}] users() ERROR:`, err);
    context.res = {
      status: 500,
      body: { message: "Internal server error" }
    };
  }
};
