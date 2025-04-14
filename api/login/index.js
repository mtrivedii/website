const { getConnection } = require('../db');
const sql = require('mssql');

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
      .input('email', sql
