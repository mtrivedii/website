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
    if (err.response) {
      // If Data API returned 400/404/etc
      context.log.error(`[${id}] scoreboard proxy ERROR`, err.response.status, err.response.data);
      context.res = { status: err.response.status, body: err.response.data };
    } else {
      // Axios error without response (network, etc)
      context.log.error(`[${id}] scoreboard proxy NETWORK ERROR`, err.message);
      context.res = { status: 500, body: { message: "Internal server error" } };
    }
  }
};
