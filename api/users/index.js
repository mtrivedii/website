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
  context.log("Users API triggered");

  try {
    const pool = await sql.connect(dbConfig);
    context.log("Connected to DB for users");

    // pull back id, email, role
    const result = await pool
      .request()
      .query("SELECT id, email, Role FROM Users ORDER BY id");

    context.res = {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: result.recordset
    };
  } catch (err) {
    context.log.error("Users API error:", err);
    context.res = {
      status: 500,
      body: { message: "Internal server error" }
    };
  } finally {
    await sql.close();
  }
};
