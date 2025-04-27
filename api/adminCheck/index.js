const { DefaultAzureCredential } = require("@azure/identity");
const { Connection, Request } = require("tedious");

module.exports = async function (context, req) {
    context.log('AdminCheck triggered');

    const userId = req.headers['x-ms-client-principal-id'];
    if (!userId) {
        context.res = { status: 401, body: "Unauthorized" };
        return;
    }

    const sqlQuery = `SELECT Role FROM Users WHERE AzureID = @UserId`;
    
    const config = await getDbConfig();
    const connection = new Connection(config);

    connection.on('connect', err => {
        if (err) {
            context.res = { status: 500, body: "Database connection error" };
            return;
        }

        const request = new Request(sqlQuery, (err, rowCount, rows) => {
            if (err) {
                context.res = { status: 500, body: "Query error" };
            } else if (rowCount === 0) {
                context.res = { status: 403, body: "Forbidden" };
            } else {
                const role = rows[0][0].value;
                if (role === 'admin') {
                    context.res = { status: 200, body: "Admin access granted" };
                } else {
                    context.res = { status: 403, body: "Forbidden" };
                }
            }
            connection.close();
        });

        request.addParameter('UserId', TYPES.NVarChar, userId);
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
