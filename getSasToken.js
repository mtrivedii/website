const { BlobServiceClient, StorageSharedKeyCredential, generateBlobSASQueryParameters, BlobSASPermissions } = require("@azure/storage-blob");

async function handler(req, res) {
  try {
    // Extract user info from App Service Easy Auth headers
    const userInfo = extractUserInfo(req);
    if (!userInfo.isAuthenticated) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const blobName = req.query.blobName;
    if (!blobName || typeof blobName !== 'string' || blobName.length > 256) {
      return res.status(400).json({ error: "Missing or invalid blobName query parameter" });
    }

    const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME;
    const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
    const containerName = "secure-uploads";

    if (!accountName || !accountKey) {
      return res.status(500).json({ error: "Storage credentials not configured" });
    }

    const sharedKeyCredential = new StorageSharedKeyCredential(accountName, accountKey);
    const expiresOn = new Date(Date.now() + 60 * 60 * 1000);

    const sasToken = generateBlobSASQueryParameters({
      containerName,
      blobName,
      permissions: BlobSASPermissions.parse("cw"),
      expiresOn,
      protocol: "https"
    }, sharedKeyCredential).toString();

    const sasUrl = `https://${accountName}.blob.core.windows.net/${containerName}/${encodeURIComponent(blobName)}?${sasToken}`;
    return res.status(200).json({ sasUrl });

  } catch (error) {
    console.error("Error generating SAS token:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}

// Parse Easy Auth headers
function extractUserInfo(req) {
  const clientPrincipal = req.headers['x-ms-client-principal'];
  if (!clientPrincipal) {
    return { isAuthenticated: false };
  }
  
  try {
    // Parse the client principal header
    const principal = JSON.parse(Buffer.from(clientPrincipal, 'base64').toString('utf8'));
    
    // Extract user ID
    const userIdClaim = principal.claims.find(claim => 
      claim.typ === 'http://schemas.microsoft.com/identity/claims/objectidentifier' ||
      claim.typ === 'oid' ||
      claim.typ === 'sub'
    );
    
    return {
      isAuthenticated: true,
      userId: userIdClaim ? userIdClaim.val : null,
      userRoles: principal.userRoles || []
    };
  } catch (error) {
    console.error('Error parsing client principal:', error);
    return { isAuthenticated: false };
  }
}

module.exports = { handler };