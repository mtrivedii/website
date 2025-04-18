const { DefaultAzureCredential } = require("@azure/identity");
const { Connection, Request } = require("tedious");

module.exports = async function (context, req) {
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
  const results = [];

  return new Promise((resolve, reject) => {
    connection.connect(err => {
      if (err) return reject(err);

      const query = `
        SELECT TOP 10 ip_address, COUNT(*) AS hits, MAX(timestamp) AS last_seen
        FROM honeypot_logins
        GROUP BY ip_address
        ORDER BY hits DESC
      `;
      const request = new Request(query, (err) => {
        if (err) return reject(err);
        connection.close();
        context.res = { status: 200, body: results };
        resolve();
      });

      request.on("row", columns => {
        const entry = {};
        columns.forEach(col => (entry[col.metadata.colName] = col.value));
        results.push(entry);
      });

      connection.execSql(request);
    });
  });
};
