// api/proxy-sas/index.js
const fetch = require('node-fetch');

module.exports = async function (context, req) {
    const blobName = req.query.blobName;
    
    if (!blobName) {
        return {
            status: 400,
            headers: { "Content-Type": "application/json" },
            body: { error: "Missing blobName parameter" }
        };
    }
    
    try {
        // Forward the request to Azure Function
        const response = await fetch(
            `https://maanit-func.azurewebsites.net/api/getSasToken?blobName=${encodeURIComponent(blobName)}`
        );
        
        if (!response.ok) {
            throw new Error(`Function returned ${response.status}`);
        }
        
        const data = await response.json();
        
        return {
            status: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache, no-store, must-revalidate"
            },
            body: data
        };
    } catch (error) {
        return {
            status: 500,
            headers: { "Content-Type": "application/json" },
            body: { error: "Failed to get SAS token: " + error.message }
        };
    }
};