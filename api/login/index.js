console.log("🟢 login function loaded");

let getConnection;
let sql;
try {
  ({ getConnection, sql } = require('../db'));
} catch (err) {
  console.error("❌ db.js load failed:", err);
  module.exports = async (context, req) => {
    context.res = {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
      body: { error: "Failed to load DB module" }
    };
  };
  return;
}

const bcrypt = require('bcrypt');

module.exports = async function (context, req) {
  context.log("⚡ login triggered");

  const { email, password } = req.body || {};
  context.log("Received:", { email });

  if (!email || !password) {
    context.log("❌ Missing email or password");
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
    context.log("🔍 Checking user:", email);
    const result = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT * FROM users WHERE email = @email');

    const user = result.recordset[0];
    if (!user) {
      context.log("❌ User not found");
      context.res = {
        status: 401,
        body: { error: 'Invalid email or password' }
      };
      return;
    }

    context.log("🔒 Comparing passwords");
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
      context.log("❌ Password mismatch");
      context.res = {
        status: 401,
        body: { error: 'Invalid email or password' }
      };
      return;
    }

    context.log("✅ Login successful");
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
