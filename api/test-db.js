const { getConnection, sql } = require('./db');

(async () => {
  try {
    const pool = await getConnection();
    const result = await pool.request().query('SELECT TOP 1 * FROM users');
    console.log('Connection successful. Sample result:', result.recordset);
  } catch (err) {
    console.error('Database connection failed:', err);
  }
})();
