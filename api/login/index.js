console.log("🟢 login function loaded");

const { getConnection } = require('../db');
const sql = require('mssql');
<<<<<<< HEAD
const bcrypt = require('bcryptjs');
=======
const bcrypt = require('bcryptjs'); // note: bcryptjs works cross-platform

module.exports = async (req, res) => {
  console.log("⚡ login triggered");
>>>>>>> fd2425374e380b02767c262ecff18c0ee114c720

  const { email, password } = req.body || {};
  console.log("Received:", { email });

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password required' });
  }

  let pool;
  try {
    console.log("🔌 Connecting to DB");
    pool = await getConnection();
    console.log("✅ DB connected");
  } catch (dbErr) {
    console.error("❌ DB connection failed:", dbErr);
    return res.status(500).json({ error: 'Database connection failed' });
  }

  try {
    const result = await pool.request()
      .input('email', sql.VarChar, email)
<<<<<<< HEAD
      .query('SELECT * FROM Users WHERE email = @email');

    const user = result.recordset[0];

    if (!user) {
      context.res = {
        status: 401,
        body: { error: 'Invalid email or password' }
      };
      return;
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
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
=======
      .query('SELECT * FROM users WHERE email = @email');

    const user = result.recordset[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    console.log("✅ Login successful");
    return res.status(200).json({ message: 'Login successful' });

>>>>>>> fd2425374e380b02767c262ecff18c0ee114c720
  } catch (err) {
    console.error("🔥 Unexpected error:", err);
    return res.status(500).json({ error: 'Unexpected error', detail: err.message });
  }
};
