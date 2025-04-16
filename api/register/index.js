const { getConnection } = require('../db');
const sql = require('mssql');
const bcrypt = require('bcrypt');

module.exports = async function (context, req) {
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
    console.error('🔥 Registration failed:', err); // Server log
    context.log.error('Registration function error:', err); // Azure Functions log
    context.res = {
      status: 500,
      body: { error: 'Internal error: ' + err.message }
    };
  }
};
