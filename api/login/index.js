console.log("🔐 login function loaded");

let getConnection;
let sql;
try {
  ({ getConnection, sql } = require('../db'));
} catch (err) {
  console.error("❌ Failed to load db.js:", err);
  module.exports = async function (context, req) {
    context.res = {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
      body: { error: "Backend error loading database module" }
    };
  };
  return;
}

const bcrypt = require('bcrypt');

module.exports = async function (context, req) {
  context.log("🔐 login function triggered");

  const { email, password } = req.body || {};

  if (!email || !password) {
    context.res = {
      status: 400,
      headers: { 'Content-Type': 'application/json' },
      body: { error: 'Email and password required' }
    };
    return;
  }

  let pool;
  try {
    pool = await getConnection();
  } catch (dbErr) {
    console.error("❌ DB connection failed:", dbErr);
    context.res = {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
      body: { error: 'Failed to connect to the database' }
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
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Invalid email or password' }
      };
      return;
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      context.res = {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Invalid email or password' }
      };
      return;
    }

    context.res = {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
      body: { message: 'Login successful' }
    };
  } catch (err) {
    console.error("❌ Unexpected login error:", err);
    context.res = {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
      body: { error: 'Login failed due to unexpected error' }
    };
  }
};
