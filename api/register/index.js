const { getConnection } = require('../db');
const sql = require('mssql');
const bcrypt = require('bcrypt');

module.exports = async function (context, req) {
  const expectedApiKey = process.env.API_KEY;
  const providedApiKey = req.headers['x-api-key'];

  // 🔒 Validate API key
  if (!expectedApiKey || providedApiKey !== expectedApiKey) {
    context.res = {
      status: 401,
      body: { error: 'Unauthorized request' }
    };
    return;
  }

  const { email, password } = req.body || {};

  if (!email || !password) {
    context.res = {
      status: 400,
      body: { error: 'Email and password required' }
    };
    return;
  }

  try {
    const pool = await getConnection();

    // 🔎 Check if user exists
    const existing = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT id FROM users WHERE email = @email');

    if (existing.recordset.length > 0) {
      context.res = {
        status: 409,
        body: { error: 'User already exists' }
      };
      return;
    }

    // 🔐 Hash password and insert
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
    console.error('Registration error:', err);
    context.res = {
      status: 500,
      body: { error: 'Registration failed' }
    };
  }
};
