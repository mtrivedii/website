const { DefaultAzureCredential } = require("@azure/identity");
const { Connection, Request } = require("tedious");

module.exports = async function (context, req) {
  const email = req.body?.email || '';
  const password = req.body?.password || '';
  const ip = req.headers["x-forwarded-for"] || req.ip || "unknown";

  context.log(`Honeypot triggered: email=${email}, ip=${ip}`);

  const query = `
    INSERT INTO honeypot_logins (email, password, ip_address)
    VALUES (N'${email}', N'${password}', N'${ip}')
  `;

  try {
    await logToDatabase(query, context);
    context.res = {
      status: 200,
      body: {
        message: "Access granted. Welcome elite hacker. 😈",
        hint: "You almost got root access... but not really. Better luck next time!"
      }
    };
  } catch (err) {
    context.log.error("Honeypot DB error:", err.message);
    context.res = {
      status: 500,
      body: { error: "Internal server error." }
    };
  }
};

// Azure SQL DB logging
async function logToDatabase(sql, context) {
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

      const request = new Request(sql, (err) => {
        if (err) return reject(err);
        connection.close();
        resolve();
      });

      connection.execSql(request);
    });
  });
}
