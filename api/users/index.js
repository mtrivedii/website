const axios = require('axios');

module.exports = async function (context, req) {
  const id = context.executionContext.invocationId;
  context.log(`[${id}] users proxy ${req.method}`);

  try {
    if (req.method === "GET") {
      const response = await axios.get(`${process.env.DATA_API_BASE}/Users`);
      context.res = { status: 200, body: response.data.value };
      return;
    }

    context.res = { status: 405, body: "Method Not Allowed" };
  } catch (err) {
    context.log.error(`[${id}] users proxy ERROR`, err);
    context.res = { status: 500, body: { message: "Internal server error" } };
  }
};
