console.log("🟢 login function loaded");

const { getConnection } = require('../db');
const sql = require('mssql');
const bcrypt = require('bcryptjs'); // using bcryptjs for compatibility

module.exports = async function (context, req) {
  context.log("⚡ login triggered");

  const { email, password } = req.body || {};
  context.log("Received:", { email });

  if (!email || !password) {
    context.res = {
      status: 400,
      body: { error: 'Email and password required' }
    };
    return;
  }

  let pool;
  try {
    context.log("🔌 Connecting to DB");
    pool = await getConnection();
    context.log("✅ DB connected");
  } catch (dbErr) {
    context.log("❌ DB connection failed:", dbErr);
    context.res = {
      status: 500,
      body: { error: 'Database connection failed' }
    };
    return;
  }

  try {
    const result = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT * FROM users WHERE email = @email');

    const user = result.recordset[0];
    if (!user) {
      context.res = {
        status: 401,
        body: { error: 'Invalid email or password' }
      };
      return;
    }

    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      context.res = {
        status: 401,
        body: { error: 'Invalid email or password' }
      };
      return;
    }

    context.res = {
      status: 200,
      body: { message: 'Login successful' }
    };
  } catch (err) {
    context.log("🔥 Unexpected error:", err);
    context.res = {
      status: 500,
      body: { error: 'Unexpected error', detail: err.message }
    };
  }
};
