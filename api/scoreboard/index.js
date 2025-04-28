const axios = require('axios');

module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] scoreboard proxy ${req.method}`);

  try {
    if (req.method === "GET") {
      const response = await axios.get(`${process.env.DATA_API_BASE}/Scoreboard`);
      context.res = { status: 200, body: response.data.value };
      return;
    }

    if (req.method === "POST") {
      const body = req.body;
      const response = await axios.post(`${process.env.DATA_API_BASE}/Scoreboard`, body);
      context.res = { status: 201, body: response.data };
      return;
    }

    context.res = { status: 405, body: "Method Not Allowed" };
  } catch (err) {
    context.log.error(`[${id}] scoreboard proxy ERROR`, err);
    context.res = { status: 500, body: { message: "Internal server error" } };
  }
};
