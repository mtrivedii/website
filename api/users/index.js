const sql = require("mssql");

// 1) DB config
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

// 2) Lazy pool creator
let poolPromise = null;
async function getPool() {
  if (poolPromise) return poolPromise;
  const p = new sql.ConnectionPool(dbConfig);
  p.on("error", e => {
    console.error("[users] pool error", e);
    poolPromise = null;
  });
  poolPromise = p.connect().then(() => {
    console.log("[users] pool connected");
    return p;
  }).catch(err => {
    console.error("[users] pool connect failed", err);
    poolPromise = null;
    throw err;
  });
  return poolPromise;
}

// 3) Azure Function
module.exports = async function(context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] users ${req.method}`);

  try {
    const pool = await getPool();
    if (req.method === "GET") {
      const result = await pool.request()
        .query("SELECT id, email, Role AS role FROM Users ORDER BY id");
      context.res = { status:200, body: result.recordset };
      return;
    }

    context.res = { status:405, body:"Method Not Allowed" };
  }
  catch (err) {
    context.log.error(`[${id}] ERROR`, err);
    context.res = { status:500, body:{ message:"Internal server error" } };
  }
};
