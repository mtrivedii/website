const { DefaultAzureCredential } = require("@azure/identity");
const { Connection, Request, TYPES } = require("tedious");
const multiparty = require("multiparty");

module.exports = async function (context, req) {
  const ip = req.headers["x-forwarded-for"] || req.ip || "unknown";

  const form = new multiparty.Form();
  form.parse(req, async (err, fields, files) => {
    if (err) {
      context.res = { status: 500, body: { message: "Upload failed." } };
      return;
    }

    const file = files.file?.[0];
    const filename = file?.originalFilename || "unknown";
    const contentType = file?.headers?.["content-type"] || "unknown";

    // Log to DB
    try {
      await logToDatabase({ ip, filename, contentType }, context);
      context.res = {
        status: 200,
        body: { message: `File uploaded to /secure/tmp/${Math.floor(Math.random() * 10000)}.dat` }
      };
    } catch (err) {
      context.log.error("Upload log error:", err);
      context.res = { status: 500, body: { message: "Internal error." } };
    }
  });
};

async function logToDatabase({ ip, filename, contentType }, context) {
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
        INSERT INTO honeypot_logins (email, password, ip_address, endpoint)
        VALUES (@email, @password, @ip, @endpoint)
      `;
      const request = new Request(query, (err) => {
        if (err) return reject(err);
        connection.close();
        resolve();
      });

      request.addParameter("email", TYPES.NVarChar, `file=${filename}`);
      request.addParameter("password", TYPES.NVarChar, contentType);
      request.addParameter("ip", TYPES.NVarChar, ip);
      request.addParameter("endpoint", TYPES.NVarChar, "upload");

      connection.execSql(request);
    });
  });
}
