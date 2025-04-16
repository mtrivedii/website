const { getConnection } = require('./db');

module.exports = async function (req, res) {
  try {
    const pool = await getConnection();
    const result = await pool.request().query('SELECT TOP 1 * FROM users');

    res.status(200).json({
      success: true,
      message: 'DB connection succeeded',
      sampleUser: result.recordset[0] || null
    });
  } catch (err) {
    console.error('DB test error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
};
