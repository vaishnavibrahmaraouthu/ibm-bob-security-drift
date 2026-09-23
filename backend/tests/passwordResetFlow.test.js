const request = require("supertest");
const mongoose = require("mongoose");
const app = require("../server");

describe("Password Reset Flow", () => {
  const testEmail = `reset-${Date.now()}@example.com`;

  beforeAll(async () => {
    await mongoose.connect(process.env.MONGO_URI);
  });

  afterAll(async () => {
    await mongoose.connection.close();
  });

  test("user can reset their password and login with the new password", async () => {
    // 1. Register user
    const registerResponse = await request(app)
      .post("/api/auth/register")
      .send({
        username: `resetuser${Date.now()}`,
        email: testEmail,
        password: "OldPassword123"
      });

    expect(registerResponse.statusCode).toBe(201);

    // 2. Request password reset
    const forgotResponse = await request(app)
      .post("/api/auth/forgot-password")
      .send({
        email: testEmail
      });

    expect(forgotResponse.statusCode).toBe(200);
    expect(forgotResponse.body.resetToken).toBeDefined();

    const resetToken = forgotResponse.body.resetToken;

    // 3. Reset password
    const resetResponse = await request(app)
      .post("/api/auth/reset-password")
      .send({
        email: testEmail,
        resetToken,
        newPassword: "NewPassword123"
      });

    expect(resetResponse.statusCode).toBe(200);
    expect(resetResponse.body.message).toBe("Password reset successful");

    // 4. Login using new password
    const loginResponse = await request(app)
      .post("/api/auth/login")
      .send({
        email: testEmail,
        password: "NewPassword123"
      });

    expect(loginResponse.statusCode).toBe(200);
    expect(loginResponse.body.token).toBeDefined();

    // 5. Old password should no longer work
    const oldLoginResponse = await request(app)
      .post("/api/auth/login")
      .send({
        email: testEmail,
        password: "OldPassword123"
      });

    expect(oldLoginResponse.statusCode).toBe(401);
  });
});