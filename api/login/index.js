module.exports = async function (context, req) {
  const { email, password } = req.body;

  // Simulate vulnerable login
  if (email === "admin@example.com" && password === "123456") {
    context.res = {
      status: 200,
      body: { message: "Login successful", token: "fake-token" }
    };
  } else {
    context.res = {
      status: 401,
      body: { message: "Invalid credentials" }
    };
  }
};
