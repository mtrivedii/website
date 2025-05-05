module.exports = async function (context, req) {
    const blobName = req.query.blobName;
    
    if (!blobName) {
        context.res = {
            status: 400,
            body: { error: "Missing blobName parameter" }
        };
        return;
    }
    
    try {
        // Get the appropriate fetch function
        const fetch = context.require('node-fetch') || require('node-fetch');
        
        // Forward the request to your Azure Function
        const response = await fetch(
            `https://maanit-func.azurewebsites.net/api/getSasToken?blobName=${encodeURIComponent(blobName)}`,
            {
                headers: {
                    // Forward authentication headers if present
                    "Authorization": req.headers.authorization || ""
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
            headers: { "Content-Type": "application/json" },
            body: { error: "Failed to get SAS token: " + error.message }
        };
    }
};