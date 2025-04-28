const sql = require('mssql');

const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: {
    type: 'azure-active-directory-msi-app-service'
  },
  options: {
    encrypt: true,
    trustServerCertificate: false
  },
  pool: {
    max: 10,
    min: 0,
    idleTimeoutMillis: 30000
  }
};

let poolPromise = null;
async function getPool() {
  if (!poolPromise) {
    const pool = new sql.ConnectionPool(dbConfig);
    poolPromise = pool.connect().then(() => pool);
  }
  return poolPromise;
}

module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] /api/users called with method ${req.method}`);

  try {
    const pool = await getPool();

    if (req.method === "GET") {
      const result = await pool.request()
        .query("SELECT id, email, Role FROM dbo.users ORDER BY id ASC");

      context.res = { status: 200, body: result.recordset };
      return;
    }

    context.res = { status: 405, body: { message: "Method Not Allowed" } };
  } catch (err) {
    context.log.error(`[${id}] ERROR`, err);
    context.res = { status: 500, body: { message: "Internal Server Error" } };
  }
};
