const { getConnection } = require('../db');
const sql = require('mssql');
const bcrypt = require('bcrypt');

module.exports = async function (context, req) {
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
  } catch (err) {
    context.res = {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
      body: { error: 'Database connection failed', detail: err.message }
    };
    return;
  }

  try {
    const result = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT * FROM Users WHERE email = @email');

    if (result.recordset.length === 0) {
      context.res = {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
        body: { error: 'Invalid email or password' }
      };
      return;
    }

    const user = result.recordset[0];
    const match = await bcrypt.compare(password, user.password);

    if (!match) {
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
      body: { message: 'Login successful', user: { id: user.id, email: user.email } }
    };
  } catch (err) {
    context.log.error("Login error:", err);
    context.res = {
      status: 500,
      headers: { 'Content-Type': 'application/json' },
      body: { error: 'Internal server error', detail: err.message }
    };
  }
};
