const request  = require("supertest");
const mongoose = require("mongoose");
const app = require("../server");

describe("Password Reset", () => {
  beforeAll(async () => {
    await mongoose.connect(process.env.MONGO_URI);
  });

  afterAll(async () => {
    await mongoose.connection.close();
  });

  test("forgot-password should require an email", async () => {
    const response = await request(app)
      .post("/api/auth/forgot-password")
      .send({});

    expect(response.statusCode).toBe(400);
    expect(response.body.message).toBe("Email is required");
  });

  test("forgot-password should return 200 with a generic message for an unknown email (no account enumeration)", async () => {
    const response = await request(app)
      .post("/api/auth/forgot-password")
      .send({ email: "does-not-exist@example.com" });

    expect(response.statusCode).toBe(200);
    expect(response.body.message).toBe(
      "If that email is registered, a password reset token has been sent"
    );
  });
});