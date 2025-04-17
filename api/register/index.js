const { getConnection } = require('../api/db');
const sql = require('mssql');
const bcrypt = require('bcrypt');

module.exports = async function (req, res) {
  console.log("register function invoked");

  const { email, password } = req.body || {};

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  let pool;
  try {
    pool = await getConnection();
  } catch (dbErr) {
    console.error("DB connection failed:", dbErr);
    return res.status(500).json({ error: "Database connection failed" });
  }

  try {
    const existing = await pool.request()
      .input('email', sql.VarChar, email)
      .query('SELECT id FROM users WHERE email = @email');

    if (existing.recordset.length > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.request()
      .input('email', sql.VarChar, email)
      .input('password', sql.VarChar, hashedPassword)
      .query('INSERT INTO users (email, password) VALUES (@email, @password)');

    return res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    console.error("Unexpected error in registration logic:", err);
    return res.status(500).json({ error: 'Registration failed due to unexpected error' });
  }
};
