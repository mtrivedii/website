const result = await pool.request()
  .input('email', sql.VarChar, email)
  .input('password', sql.VarChar, password)
  .query('SELECT * FROM Users WHERE email = @email AND password = @password');
