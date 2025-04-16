const { getConnection } = require('../db');
const sql = require('mssql');
const bcrypt = require('bcrypt');

module.exports = async function (context, req) {
  console.log("🔃 Incoming registration request");

  const expectedApiKey = process.env.API_KEY;
  const providedApiKey = req.headers['x-api-key'];

  console.log("🔐 Expected API Key:", expectedApiKey ? '[SET]' : '[NOT SET]');
  console.log("🔑 Provided API Key:", providedApiKey);

  if (!expectedApiKey || providedApiKey !== expectedApiKey) {
    console.log("❌ Unauthorized: Invalid API key");
    context.res = {
      status: 401,
      body: { error: 'Unauthorized request' }
    };
    return;
  }

  const { email, password } = req.body || {};
  console.log("📥 Payload:", { email, hasPassword: !!password });

  if (!email || !password) {
    console.log("⚠️ Missing email or password");
    context.res = {
      status: 400,
      body: { error: 'Email and password required' }
    };
    return;
  }

  try {
    const pool = await getConnection();
    console.log("✅ Database connection established");

    const existing = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT id FROM users WHERE email = @email');

    if (existing.recordset.length > 0) {
      console.log("⚠️ Email already exists:", email);
      context.res = {
        status: 409,
        body: { error: 'User already exists' }
      };
      return;
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    console.log("🔐 Password hashed");

    await pool.request()
      .input('email', sql.VarChar, email)
      .input('password', sql.VarChar, hashedPassword)
      .query('INSERT INTO users (email, password) VALUES (@email, @password)');

    console.log("✅ User registered:", email);
    context.res = {
      status: 201,
      body: { message: 'User registered successfully' }
    };
  } catch (err) {
    console.error("🔥 Registration error:", err);
    context.res = {
      status: 500,
      body: { error: 'Registration failed', details: err.message }
    };
  }
};
