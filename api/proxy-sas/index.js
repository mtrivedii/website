const fetch = require('node-fetch');

// Helper function to log API calls for monitoring
function logApiCall(context, req, status, error = null) {
  const logEntry = {
    timestamp: new Date().toISOString(),
    operation: 'getSasToken',
    clientIP: req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || 'unknown',
    userAgent: req.headers['user-agent'] || 'unknown',
    status: status,
    blobName: req.query.blobName || 'none',
    error: error ? error.message : null
  };
  
  console.log('API Call:', JSON.stringify(logEntry));
}

module.exports = async function (context, req) {
    const blobName = req.query.blobName;
    
    // Basic parameter validation
    if (!blobName) {
        logApiCall(context, req, 400, new Error("Missing blobName parameter"));
        return {
            status: 400,
            headers: {
                "Content-Type": "application/json"
            },
            body: { error: "Missing blobName parameter" }
        };
    }
    
    // Security: File name length validation
    const MAX_BLOB_NAME_LENGTH = 256;
    if (blobName.length > MAX_BLOB_NAME_LENGTH) {
        logApiCall(context, req, 400, new Error("Blob name too long"));
        return {
            status: 400,
            headers: {
                "Content-Type": "application/json"
            },
            body: { error: "Blob name too long" }
        };
    }
    
    // Security: File type validation
    const validExtensions = ['.pdf', '.doc', '.docx', '.txt', '.jpg', '.jpeg', '.png', '.gif', '.csv', '.json', '.xml'];
    const fileExtension = '.' + blobName.split('.').pop().toLowerCase();
    
    if (!validExtensions.includes(fileExtension)) {
        logApiCall(context, req, 400, new Error("File type not allowed"));
        return {
            status: 400,
            headers: {
                "Content-Type": "application/json"
            },
            body: { error: "File type not allowed" }
        };
    }
    
    try {
        // Create request headers 
        const headers = {};
        
        // Forward Azure Static Web App auth information
        if (req.headers['x-ms-client-principal']) {
            headers['x-ms-client-principal'] = req.headers['x-ms-client-principal'];
        }
        
        // Forward authorization header if present
        if (req.headers.authorization) {
            headers['authorization'] = req.headers.authorization;
        }
        
        // Use fetch with a timeout to prevent hanging
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000); // 10-second timeout
        
        // Forward the request to Azure Function
        const response = await fetch(
            `https://maanit-func.azurewebsites.net/api/getSasToken?blobName=${encodeURIComponent(blobName)}`,
            {
                method: 'GET',
                headers: headers,
                signal: controller.signal
            }
        );
        
        clearTimeout(timeoutId);
        
        // Enhanced error handling
        if (!response.ok) {
            let errorText = 'Unknown error';
            try {
                // Try to get the error message from the response
                const errorData = await response.json();
                errorText = errorData.error || errorData.message || `Function returned ${response.status}`;
            } catch {
                errorText = `Function returned ${response.status}: ${response.statusText}`;
            }
            
            throw new Error(errorText);
        }
        
        // Verify response format
        const contentType = response.headers.get('content-type') || '';
        if (!contentType.includes('application/json')) {
            throw new Error(`Unexpected response format: ${contentType}. Expected JSON.`);
        }
        
        const data = await response.json();
        
        // Validate the response structure
        if (!data || !data.sasUrl) {
            throw new Error('Invalid SAS token response: missing sasUrl');
        }
        
        // Log successful call
        logApiCall(context, req, 200);
        
        // Return successful response with enhanced security headers
        return {
            status: 200,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache, no-store, must-revalidate",
                "Pragma": "no-cache",
                "Expires": "0",
                "X-Content-Type-Options": "nosniff"
            },
            body: data
        };
    } catch (error) {
        // Log error
        logApiCall(context, req, 500, error);
        
        // Return proper error response
        return {
            status: error.name === 'AbortError' ? 504 : 500,
            headers: {
                "Content-Type": "application/json",
                "Cache-Control": "no-cache, no-store, must-revalidate"
            },
            body: { 
                error: error.name === 'AbortError' 
                    ? "Request to function timed out" 
                    : "Failed to get SAS token: " + error.message 
            }
        };
    }
};