const { DefaultAzureCredential } = require("@azure/identity");
const { Connection, Request } = require("tedious");

module.exports = async function (context, req) {
    context.log('Scoreboard API triggered');

    const config = await getDbConfig();
    const connection = new Connection(config);

    connection.on('connect', err => {
        if (err) {
            context.res = { status: 500, body: "Database connection error" };
            return;
        }

        const sqlQuery = "SELECT Username, Score FROM Scoreboard ORDER BY Score DESC";

        const request = new Request(sqlQuery, (err, rowCount, rows) => {
            if (err) {
                context.res = { status: 500, body: "Query error" };
            } else {
                const result = rows.map(columns => {
                    return {
                        username: columns[0].value,
                        score: columns[1].value
                    };
                });
                context.res = { status: 200, body: result };
            }
            connection.close();
        });

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
