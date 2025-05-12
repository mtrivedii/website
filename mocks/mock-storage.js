// mocks/mock-storage.js
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// Create local uploads directory
const uploadsDir = path.join(__dirname, '..', 'local-uploads');
if (!fs.existsSync(uploadsDir)) {
  fs.mkdirSync(uploadsDir, { recursive: true });
}

// Mock storage classes
const BlobSASPermissions = {
  parse: (permissions) => ({
    read: permissions.includes('r'),
    write: permissions.includes('w'),
    create: permissions.includes('c'),
    delete: permissions.includes('d'),
    toString: () => permissions
  })
};

// Generate mock SAS token
function generateBlobSASQueryParameters(options, credentials) {
  console.log('[MOCK STORAGE] Generating SAS token for blob:', options.blobName);
  
  // Create a fake SAS token
  const expiryDate = new Date();
  expiryDate.setHours(expiryDate.getHours() + 1); // 1 hour expiry
  
  return {
    toString: () => {
      return `sv=2021-06-08&ss=b&srt=sco&sp=${options.permissions.toString()}&se=${expiryDate.toISOString()}&sig=${crypto.randomBytes(16).toString('hex')}`;
    }
  };
}

// Mock StorageSharedKeyCredential
class StorageSharedKeyCredential {
  constructor(accountName, accountKey) {
    this.accountName = accountName;
    this.accountKey = accountKey;
  }
}

module.exports = {
  BlobSASPermissions,
  generateBlobSASQueryParameters,
  StorageSharedKeyCredential
};
