// mocks/mock-getSasToken.js
const mockStorage = require('./mock-storage');
const { extractUserInfo } = require('../auth-utilities');

async function handler(req, res) {
  try {
    console.log('[MOCK API] /api/getSasToken invoked');
    
    // Add CORS headers for browser compatibility
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    
    // Handle OPTIONS requests
    if (req.method === 'OPTIONS') {
      return res.status(200).end();
    }

    // Skip authentication check in development mode
    // const userInfo = extractUserInfo(req);
    // if (!userInfo.isAuthenticated) {
    //   return res.status(401).json({ error: "Unauthorized" });
    // }

    const blobName = req.query.blobName;
    if (!blobName || typeof blobName !== 'string' || blobName.length > 256) {
      return res.status(400).json({ error: "Missing or invalid blobName query parameter" });
    }

    const accountName = process.env.AZURE_STORAGE_ACCOUNT_NAME || 'devstoreaccount1';
    const accountKey = process.env.AZURE_STORAGE_ACCOUNT_KEY || 'Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==';
    const containerName = "secure-uploads";

    const sharedKeyCredential = new mockStorage.StorageSharedKeyCredential(accountName, accountKey);
    const expiresOn = new Date(Date.now() + 60 * 60 * 1000);

    const sasToken = mockStorage.generateBlobSASQueryParameters({
      containerName,
      blobName,
      permissions: mockStorage.BlobSASPermissions.parse("cw"),
      expiresOn,
      protocol: "https"
    }, sharedKeyCredential).toString();

    // For local testing, we'll use a local URL
    const sasUrl = `http://localhost:3000/local-uploads/${encodeURIComponent(blobName)}?${sasToken}`;
    console.log('[MOCK API] Generated SAS URL:', sasUrl);
    
    return res.status(200).json({ sasUrl });
  } catch (error) {
    console.error("[MOCK API] Error generating SAS token:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
}

module.exports = { handler };
