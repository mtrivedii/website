const { getConnection } = require('../db');
const sql = require('mssql');
const bcrypt = require('bcrypt');

module.exports = async function (context, req) {
  const origin = 'https://maanit-website.azurewebsites.net';

  if (req.method === 'OPTIONS') {
    context.res = {
      status: 204,
      headers: {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    };
    return;
  }

  const { email, password } = req.body || {};
  console.log('Request body:', email, password);

  if (!email || !password) {
    console.log('Missing email or password');
    context.res = {
      status: 400,
      headers: {
        'Access-Control-Allow-Origin': origin,
      },
      body: { error: 'Email and password required' },
    };
    return;
  }

  try {
    const pool = await getConnection();
    console.log('Connected to DB');

    const existing = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT id FROM users WHERE email = @email');

    if (existing.recordset.length > 0) {
      console.log('User already exists');
      context.res = {
        status: 409,
        headers: { 'Access-Control-Allow-Origin': origin },
        body: { error: 'User already exists' },
      };
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log('Password hashed');

    await pool.request()
      .input('email', sql.VarChar, email)
      .input('password', sql.VarChar, hashedPassword)
      .query('INSERT INTO users (email, password) VALUES (@email, @password)');

    console.log('User inserted into DB');

    context.res = {
      status: 201,
      headers: { 'Access-Control-Allow-Origin': origin },
      body: { message: 'User registered successfully' },
    };
  } catch (err) {
    console.error('❌ Registration error:', err.message);
    context.res = {
      status: 500,
      headers: { 'Access-Control-Allow-Origin': origin },
      body: { error: 'Registration failed' },
    };
  }
};
