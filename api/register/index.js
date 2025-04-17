const { getConnection } = require('../db');
const sql = require('mssql');
const bcrypt = require('bcryptjs');

module.exports = async function (context, req) {
  context.log("register function triggered");

  const { email, password } = req.body || {};
  if (!email || !password) {
    context.res = {
      status: 400,
      body: { error: 'Email and password required' }
    };
    return;
  }

  let pool;
  try {
    pool = await getConnection();
  } catch (err) {
    context.log("DB connection failed:", err);
    context.res = {
      status: 500,
      body: { error: 'Database connection failed' }
    };
    return;
  }

  try {
    const existingUser = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT id FROM users WHERE email = @email');

    if (existingUser.recordset.length > 0) {
      context.res = {
        status: 409,
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
      body: { message: 'User registered successfully' }
    };
  } catch (err) {
    context.log("Unexpected error:", err);
    context.res = {
      status: 500,
      body: { error: 'Registration failed due to unexpected error' }
    };
  }
};
