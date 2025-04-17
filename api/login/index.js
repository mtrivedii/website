const { getConnection } = require('../db');
const sql = require('mssql');
const bcrypt = require('bcryptjs');

module.exports = async function (context, req) {
  context.log("⚡ login triggered");

  const { email, password } = req.body || {};
  if (!email || !password) {
    context.res = {
      status: 400,
      body: { error: 'Email and password are required' }
    };
    return;
  }

  let pool;
  try {
    pool = await getConnection();
    const result = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT * FROM users WHERE email = @email');

    const user = result.recordset[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
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
    context.res = {
      status: 500,
      body: { error: 'Login failed', detail: err.message }
    };
  }
};
