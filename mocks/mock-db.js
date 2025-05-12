// mocks/mock-db.js
class MockDatabase {
  constructor() {
    // Mock user data
    this.users = [
      { 
        id: 1, 
        email: "admin@example.com", 
        AzureID: "test-admin-user", 
        Role: "admin",
        status: "Active",
        twoFactorEnabled: true,
        lastLogin: new Date().toISOString(),
        passwordLastChanged: new Date(Date.now() - 30*24*60*60*1000).toISOString()
      },
      { 
        id: 2, 
        email: "user@example.com", 
        AzureID: "test-regular-user", 
        Role: "user",
        status: "Active",
        twoFactorEnabled: false,
        lastLogin: new Date(Date.now() - 2*24*60*60*1000).toISOString(),
        passwordLastChanged: new Date(Date.now() - 60*24*60*60*1000).toISOString()
      },
      { 
        id: 7, 
        email: "StudentAdmin@fictproftaak35.onmicrosoft.com", 
        status: "Active",
        AzureID: "student-admin-azureid",
        Role: "admin",
        twoFactorEnabled: true,
        lastLogin: new Date(Date.now() - 3*24*60*60*1000).toISOString(),
        passwordLastChanged: "2024-03-12T14:20:00Z"
      }
    ];
  }

  request() {
    return {
      input: (name, type, value) => {
        this.currentInput = { name, value };
        return this;
      },
      query: (query) => {
        console.log(`[MOCK DB] Executing query: ${query}`);
        
        // User Role lookup query
        if (query.includes('SELECT Role FROM Users WHERE AzureID = @userId')) {
          const userId = this.currentInput.value;
          const user = this.users.find(u => u.AzureID === userId);
          
          if (user) {
            console.log(`[MOCK DB] Found user with role: ${user.Role}`);
            return Promise.resolve({ recordset: [{ Role: user.Role }] });
          } else {
            console.log(`[MOCK DB] User not found`);
            return Promise.resolve({ recordset: [] });
          }
        }
        
        // Get all users query
        if (query.includes('SELECT') && query.includes('FROM dbo.users')) {
          console.log(`[MOCK DB] Returning all users`);
          return Promise.resolve({ recordset: this.users });
        }
        
        // Default empty response
        return Promise.resolve({ recordset: [] });
      }
    };
  }
}

// Mock SQL Server module
const sql = {
  connect: () => {
    console.log('[MOCK DB] Creating connection to mock database');
    return Promise.resolve(new MockDatabase());
  },
  NVarChar: 'nvarchar'
};

module.exports = sql;
