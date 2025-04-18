const { DefaultAzureCredential } = require("@azure/identity");
const { Connection, Request, TYPES } = require("tedious");

module.exports = async function (context, req) {
  const email = req.body?.email || '';
  const password = req.body?.password || '';
  const ip = req.headers["x-forwarded-for"] || req.ip || "unknown";

  context.log(`HONEYPOT_CAPTURE: email=${email}, ip=${ip}`);

  const score = (email.length * 42 + ip.length * 7) % 1000;

  try {
    await logToDatabase({ email, password, ip }, context);
    context.res = {
      status: 200,
      body: {
        message: "Access granted. Welcome elite hacker. 😈",
        hint: "You almost got root access... but not really.",
        score: score
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

async function logToDatabase({ email, password, ip }, context) {
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

      const query = `
        INSERT INTO honeypot_logins (email, password, ip_address)
        VALUES (@email, @password, @ip)
      `;

      const request = new Request(query, (err) => {
        if (err) return reject(err);
        connection.close();
        resolve();
      });

      request.addParameter("email", TYPES.NVarChar, email);
      request.addParameter("password", TYPES.NVarChar, password);
      request.addParameter("ip", TYPES.NVarChar, ip);

      connection.execSql(request);
    });
  });
}
