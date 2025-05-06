const { BlobServiceClient, StorageSharedKeyCredential, generateBlobSASQueryParameters, BlobSASPermissions } = require("@azure/storage-blob");
const { extractUserInfo } = require('./auth-utilities'); // Use your auth utility

// Express route handler
async function getSasTokenHandler(req, res) {
  try {
    // 1. Validate authentication using Easy Auth
    const userInfo = extractUserInfo(req);
    if (!userInfo.isAuthenticated) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // 2. Validate input
    const blobName = req.query.blobName;
    if (!blobName || typeof blobName !== 'string' || blobName.length > 256) {
      return res.status(400).json({ error: "Missing or invalid blobName query parameter" });
    }

    // 3. Prepare storage credentials (use environment variables, never hardcode)
    const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME;
    const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY;
    const containerName = "secure-uploads";

    if (!accountName || !accountKey) {
      return res.status(500).json({ error: "Storage credentials not configured" });
    }

    // 4. Principle of least privilege: SAS for a single blob, minimal permissions
    const sharedKeyCredential = new StorageSharedKeyCredential(accountName, accountKey);

    // 5. Short expiry (1 hour)
    const expiresOn = new Date(Date.now() + 60 * 60 * 1000);

    const sasToken = generateBlobSASQueryParameters({
      containerName,
      blobName,
      permissions: BlobSASPermissions.parse("cw"), // create + write only
      expiresOn,
      protocol: "https"
    }, sharedKeyCredential).toString();

    // 6. Construct the SAS URL
    const sasUrl = `https://${accountName}.blob.core.windows.net/${containerName}/${encodeURIComponent(blobName)}?${sasToken}`;

    // 7. Return only to authenticated users, never log the SAS token
    return res.status(200).json({ sasUrl });

  } catch (error) {
    console.error("Error generating SAS token:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}

module.exports = { getSasTokenHandler };
