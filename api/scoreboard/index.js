const axios = require('axios');

module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  console.log(`[${id}] scoreboard proxy ${req.method}`);
  console.log("DEBUG: DATA_API_BASE =", process.env.DATA_API_BASE);

  try {
    if (req.method === "GET") {
      const response = await axios.get(`${process.env.DATA_API_BASE}/Scoreboard`);
      console.log(`[${id}] DataAPI Response:`, response.data);

      // Return entire response.data without assuming "value"
      context.res = { status: 200, body: response.data };
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
      console.error(`[${id}] ERROR`, err.response.status, err.response.data);
      context.res = { status: err.response.status, body: err.response.data };
    } else {
      console.error(`[${id}] NETWORK ERROR`, err.message);
      context.res = { status: 500, body: { message: "Internal server error" } };
    }
  }
};
