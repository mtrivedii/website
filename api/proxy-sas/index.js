const fetch = require('node-fetch');

module.exports = async function (context, req) {
    const blobName = req.query.blobName;
    
    if (!blobName) {
        context.res = {
            status: 400,
            headers: {
                "Content-Type": "application/json"
            },
            body: { error: "Missing blobName parameter" }
        };
        return;
    }
    
    try {
        // Forward the request to your Azure Function
        const response = await fetch(
            `https://maanit-func.azurewebsites.net/api/getSasToken?blobName=${encodeURIComponent(blobName)}`,
            {
                method: 'GET',
                headers: {
                    // Forward authorization header if present
                    ...(req.headers.authorization && { 
                        'Authorization': req.headers.authorization 
                    })
                }
            }
        );
        
        if (!response.ok) {
            throw new Error(`Function returned ${response.status}: ${response.statusText}`);
        }
        
        const data = await response.json();
        
        context.res = {
            status: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache, no-store, must-revalidate"
            },
            body: data
        };
    } catch (error) {
        context.log.error("Proxy error:", error.message);
        context.res = {
            status: 500,
            headers: {
                "Content-Type": "application/json"
            },
            body: { error: "Failed to get SAS token: " + error.message }
        };
    }
};