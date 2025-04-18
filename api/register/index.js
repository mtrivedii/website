module.exports = async function (context, req) {
  const { email, password } = req.body;

  if (!email || !password) {
    context.res = {
      status: 400,
      body: { message: "Email and password are required" }
    };
    return;
  }

  // Fake "register" logic (no DB yet — intentionally weak for testing)
  context.res = {
    status: 201,
    body: { message: "User registered (simulated)", email }
  };
};
