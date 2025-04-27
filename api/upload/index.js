const { DefaultAzureCredential } = require("@azure/identity");
const { Connection, Request } = require("tedious");

module.exports = async function (context, req) {
    context.log('Upload honeypot triggered');

    const { filename, ipAddress } = req.body || {};
    if (!filename || !ipAddress) {
        context.res = { status: 400, body: "Invalid request" };
        return;
    }

    const config = await getDbConfig();
    const connection = new Connection(config);

    connection.on('connect', err => {
        if (err) {
            context.res = { status: 500, body: "Database connection error" };
            return;
        }

        const sqlQuery = "INSERT INTO UploadLogs (Filename, IPAddress, Timestamp) VALUES (@Filename, @IPAddress, GETUTCDATE())";

        const request = new Request(sqlQuery, (err) => {
            if (err) {
                context.res = { status: 500, body: "Query error" };
            } else {
                context.res = { status: 200, body: "Upload logged" };
            }
            connection.close();
        });

        request.addParameter('Filename', TYPES.NVarChar, filename);
        request.addParameter('IPAddress', TYPES.NVarChar, ipAddress);

        connection.execSql(request);
    });
};

async function getDbConfig() {
    const credential = new DefaultAzureCredential();
    const accessToken = await credential.getToken("https://database.windows.net/");
    return {
        server: process.env.DB_SERVER,
        authentication: {
            type: "azure-active-directory-access-token",
            options: { token: accessToken.token }
        },
        options: {
            database: process.env.DB_NAME,
            encrypt: true
        }
    };
}

const { TYPES } = require("tedious");
