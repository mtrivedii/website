const { getConnection } = require('../db');
const bcrypt = require('bcrypt');

module.exports = async function (context, req) {
  context.log('🟢 register function triggered');

  const { email, password } = req.body;

  if (!email || !password) {
    context.res = {
      status: 400,
      body: { error: 'Email and password are required' }
    };
    return;
  }

  try {
    const pool = await getConnection();
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.request()
      .input('email', email)
      .input('password', hashedPassword)
      .query('INSERT INTO users (email, password) VALUES (@email, @password)');

    context.res = {
      status: 201,
      body: { message: 'User registered successfully' }
    };
  } catch (err) {
    context.log('❌ register error:', err);
    context.res = {
      status: 500,
      body: { error: 'Registration failed' }
    };
  }
};
