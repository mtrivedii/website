 const sql = require('mssql');
const { DefaultAzureCredential } = require('@azure/identity');

const credential = new DefaultAzureCredential();

async function getAccessToken() {
  const tokenResponse = await credential.getToken('https://database.windows.net/');
  return tokenResponse.token;
}

async function getConnection() {
  const accessToken = await getAccessToken();

  const config = {
    server: process.env.DB_SERVER,       // e.g. maanit-server.database.windows.net
    database: process.env.DB_NAME,       // e.g. maanit-sql-db
    options: {
      encrypt: true
    },
    authentication: {
      type: 'azure-active-directory-access-token'
    },
    token: accessToken
  };

  return sql.connect(config);
}

module.exports = { getConnection };
