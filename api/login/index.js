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
    const result = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT password FROM users WHERE email = @email');

    if (result.recordset.length === 0) {
      context.res = {
        status: 401,
        body: { error: 'Invalid credentials' }
      };
      return;
    }

    const match = await bcrypt.compare(password, result.recordset[0].password);

    if (!match) {
      context.res = {
        status: 401,
        body: { error: 'Invalid credentials' }
      };
    } else {
      context.res = {
        status: 200,
        body: { message: 'Login successful!' }
      };
    }
  } catch (err) {
    context.res = {
      status: 500,
      body: { error: 'Internal server error', detail: err.message }
    };
  }
};
