module.exports = async function (context, req) {
  const ip = req.headers["x-forwarded-for"] || req.ip || "unknown";
  const path = req.originalUrl;

  context.log(`Bot hit: ${path} from ${ip}`);

  context.res = {
    status: 302,
    headers: {
      Location: "/error.html"
    }
  };
};
