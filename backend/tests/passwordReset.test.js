const request = require("supertest");
const app = require("../server");

describe("Password Reset", () => {
  test("forgot-password should require an email", async () => {
    const response = await request(app)
      .post("/api/auth/forgot-password")
      .send({});

    expect(response.statusCode).toBe(400);
    expect(response.body.message).toBe("Email is required");
  });
});