const { DefaultAzureCredential } = require("@azure/identity");
const { Connection, Request, TYPES } = require("tedious");

module.exports = async function (context, req) {
  const id = req.query?.id || "0";
  const ip = req.headers["x-forwarded-for"] || req.ip || "unknown";

  const suspicious = /('|--|;|\/\*|\*\/|union|select|or\s+1=1|drop\s+table)/i.test(id);
  const isNumeric = /^\d+$/.test(id);

  const logMsg = suspicious ? `SQLi Attempt from ${ip} using payload: ${id}` : `Profile lookup for ID ${id}`;
  context.log(logMsg);

  // Log to DB for correlation
  try {
    await logToDatabase({ ip, id, suspicious }, context);
  } catch (err) {
    context.log.warn("Logging failed:", err.message);
  }

  // Return fake user data regardless
  const fakeUser = {
    id,
    name: suspicious ? "admin" : `User ${id}`,
    email: suspicious ? "root@system.local" : `user${id}@example.com`,
    role: suspicious ? "Super Admin" : "User",
    status: suspicious ? "Privileged session granted" : "Active"
  };

  context.res = {
    status: 200,
    body: fakeUser
  };
};

async function logToDatabase({ ip, id, suspicious }, context) {
  const credential = new DefaultAzureCredential();
  const token = await credential.getToken("https://database.windows.net/");

  const config = {
    server: "your-server-name.database.windows.net",
    authentication: {
      type: "azure-active-directory-access-token",
      options: { token: token.token }
    },
    options: {
      database: "your-database-name",
      encrypt: true
    }
  };

  const connection = new Connection(config);
  return new Promise((resolve, reject) => {
    connection.connect(err => {
      if (err) return reject(err);

      const request = new Request(`
        INSERT INTO honeypot_logins (email, password, ip_address, endpoint)
        VALUES (@email, @password, @ip, @endpoint)
      `, (err) => {
        if (err) return reject(err);
        connection.close();
        resolve();
      });

      request.addParameter("email", TYPES.NVarChar, `payload=${id}`);
      request.addParameter("password", TYPES.NVarChar, suspicious ? "SQLi" : "lookup");
      request.addParameter("ip", TYPES.NVarChar, ip);
      request.addParameter("endpoint", TYPES.NVarChar, "user-query");

      connection.execSql(request);
    });
  });
}
