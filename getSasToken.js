const { BlobServiceClient, StorageSharedKeyCredential, generateBlobSASQueryParameters, BlobSASPermissions } = require("@azure/storage-blob");
const { extractUserInfo } = require('./auth-utilities');

async function handler(req, res) {
  try {
    // Add CORS headers for browser compatibility
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    // Handle OPTIONS requests
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    // Get user info from App Service Easy Auth
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

module.exports = { handler };