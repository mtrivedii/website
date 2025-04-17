console.log("register function loaded");

let getConnection;
try {
  ({ getConnection } = require('../db'));
} catch (err) {
  console.error("Failed to load db.js:", err);
  // Fails before function even runs
}

const sql = require('mssql');
const bcrypt = require('bcryptjs');

module.exports = async function (context, req) {
  context.log("register function invoked");

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
    console.error("DB connection failed:", dbErr);
    context.log.error("DB connection failed:", dbErr);
    context.res = {
      status: 500,
      body: { error: "Database connection failed" }
    };
    return;
  }

  try {
    const existing = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT id FROM users WHERE email = @email');

    if (existing.recordset.length > 0) {
      context.res = {
        status: 409,
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'User already exists' }
      };
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.request()
      .input('email', sql.VarChar, email)
      .input('password', sql.VarChar, hashedPassword)
      .query('INSERT INTO users (email, password) VALUES (@email, @password)');

    context.res = {
      status: 201,
      headers: { 'Content-Type': 'application/json' },
      body: { message: 'User registered successfully' }
    };
  } catch (err) {
    console.error("Unexpected error in registration logic:", err);
    context.log.error("Unexpected error in registration logic:", err);
    context.res = {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
      body: { error: 'Registration failed due to unexpected error' }
    };
  }
};
