const sql = require("mssql");

// same service-principal configuration:
const dbConfig = {
  server:   process.env.DB_SERVER,
  database: process.env.DB_NAME,
  authentication: {
    type: "azure-active-directory-service-principal-secret",
    options: {
      clientId:     process.env.AAD_CLIENT_ID,
      clientSecret: process.env.AAD_CLIENT_SECRET,
      tenantId:     process.env.AAD_TENANT_ID
    }
  },
  options: {
    encrypt: true,
    trustServerCertificate: true
  }
};

module.exports = async function(context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] users start`);

  try {
    const pool = await sql.connect(dbConfig);
    context.log(`[${id}] DB connected`);

    const result = await pool
      .request()
      .query("SELECT id, email, Role FROM Users ORDER BY id");

    context.res = {
      status: 200,
      headers: { "Content-Type": "application/json" },
      body: result.recordset
    };
  }
  catch (err) {
    context.log.error(`[${id}] users ERROR`, err);
    context.res = { status: 500, body: { message: "Internal server error" } };
  }
};
