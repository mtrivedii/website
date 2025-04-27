const sql = require("mssql");

// same dbConfig & poolPromise pattern
const dbConfig = {
  server: process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: { type: "azure-active-directory-msi-app-service" },
  options: { encrypt: true, trustServerCertificate: true }
};
const poolPromise = new sql.ConnectionPool(dbConfig)
  .connect()
  .then(pool => {
    console.log("Users pool created");
    pool.on("error", e=>console.error("Users pool error",e));
    return pool;
  })
  .catch(e=>{ console.error("Users pool failed",e); throw e; });

module.exports = async function (context, req) {
  context.log("Users API start");
  try {
    const pool = await poolPromise;
    const result = await pool.request().query("SELECT id, email, Role FROM Users ORDER BY id");
    context.res = { status: 200, body: result.recordset };
  }
  catch (err) {
    context.log.error("Users API error", err);
    context.res = { status: 500, body: { message: "Internal server error" } };
  }
};
